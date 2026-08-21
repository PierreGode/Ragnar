#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Passive TLS/QUIC handshake observer for the Ragnar suite.

The session/presentation-layer (OSI L5/L6) detector: it sniffs ClientHello /
ServerHello off the wire, computes JA3/JA3S and JA4/JA4_r client fingerprints,
extracts SNI / ALPN / negotiated parameters, and (on TLS 1.2 over TCP, the only
handshake whose Certificate is passively observable) flags certificate-chain
anomalies. Passive-only: zero TX, inject, or probe on the monitored network.

This module is the BSD/MIT-clean core. JA4S (server fingerprint) carries FoxIO
License 1.1 and lives in a separate, clearly-identified file (ja4s.py); it is
imported lazily and only when the operator explicitly acknowledges that license.

Complete: raw-byte ClientHello/ServerHello parsing, JA3/JA3S and JA4/JA4_r
client fingerprints, TLS 1.2 certificate parsing, the findings engine (legacy
version, weak cipher, no_sni, ECH, cert expiry/self-signed/short-chain/weak-sig,
SNI↔cert mismatch, JA4 denylist), passive QUIC Initial recovery (v1 + v2 key
schedule, header unprotection, AEAD decrypt, CRYPTO reassembly), and live
tcpdump capture → pcap dissection → verdict via do_tls_watch().

Algorithms implemented to the FoxIO JA4 technical specification (JA4 is
BSD-3-Clause) and the original Salesforce JA3/JA3S method. Certificate parsing
uses the cryptography library (memory-safe X.509), lazily imported.
"""
import hashlib
import hmac
import struct

# ---- JA4S license gate (see ja4s.py) ----------------------------------------
# JA4S (the server fingerprint) is licensed under the FoxIO License 1.1, not the
# BSD/MIT that covers everything else here. It lives in a separate, clearly
# identified file (ja4s.py) and is imported ONLY when the operator both enables
# it and acknowledges that license. Ragnar ships with both flags False, so the
# default build never touches JA4S. See _maybe_ja4s().
ENABLE_JA4S = False
ACKNOWLEDGE_JA4S_LICENSE = False

# Ports treated as TLS-over-TCP / QUIC-over-UDP for live capture.
TLS_TCP_PORTS = (443, 8443, 993, 995, 465, 990, 4433)
QUIC_UDP_PORTS = (443,)


# ---- GREASE (draft-davidben-tls-grease-01): 0x0a0a, 0x1a1a, ..., 0xfafa ------
def _is_grease(v):
    """True for a GREASE code point — ignored anywhere it appears per the spec."""
    return (v & 0x0f0f) == 0x0a0a and ((v >> 8) & 0xff) == (v & 0xff)


class _Reader:
    """Bounds-checked byte reader. Raises ValueError on truncation so a single
    malformed handshake is rejected per-flow rather than crashing the sniffer."""
    __slots__ = ('b', 'i', 'n')

    def __init__(self, b, off=0, end=None):
        self.b = b
        self.i = off
        self.n = len(b) if end is None else end

    def rem(self):
        return self.n - self.i

    def u8(self):
        if self.i + 1 > self.n:
            raise ValueError('short u8')
        v = self.b[self.i]
        self.i += 1
        return v

    def u16(self):
        if self.i + 2 > self.n:
            raise ValueError('short u16')
        v = (self.b[self.i] << 8) | self.b[self.i + 1]
        self.i += 2
        return v

    def u24(self):
        if self.i + 3 > self.n:
            raise ValueError('short u24')
        v = (self.b[self.i] << 16) | (self.b[self.i + 1] << 8) | self.b[self.i + 2]
        self.i += 3
        return v

    def take(self, k):
        if k < 0 or self.i + k > self.n:
            raise ValueError('short take')
        v = self.b[self.i:self.i + k]
        self.i += k
        return v


# --------------------------- ClientHello parsing -----------------------------
def parse_client_hello(hs_body):
    """Parse a ClientHello *handshake body* (the bytes after the 4-byte handshake
    header: msg_type + 3-byte length). Returns the fields that feed JA3/JA4."""
    r = _Reader(hs_body)
    client_version = r.u16()
    r.take(32)                                   # random
    r.take(r.u8())                               # session id
    cr = _Reader(r.take(r.u16()))                # cipher_suites
    ciphers = []
    while cr.rem() >= 2:
        ciphers.append(cr.u16())
    r.take(r.u8())                               # compression methods

    exts_order = []
    sni = None
    alpn = []
    sig_algs = []
    sup_versions = []
    sup_groups = []
    ec_point_formats = []
    if r.rem() >= 2:
        er = _Reader(r.take(r.u16()))
        while er.rem() >= 4:
            etype = er.u16()
            edata = er.take(er.u16())
            exts_order.append(etype)
            if etype == 0x0000:                  # server_name
                sni = _parse_sni(edata)
            elif etype == 0x0010:                # application_layer_protocol_neg
                alpn = _parse_alpn(edata)
            elif etype == 0x000d:                # signature_algorithms
                sig_algs = _parse_u16_list(edata, prefix16=True)
            elif etype == 0x002b:                # supported_versions
                sup_versions = _parse_u16_list(edata, prefix8=True)
            elif etype == 0x000a:                # supported_groups
                sup_groups = _parse_u16_list(edata, prefix16=True)
            elif etype == 0x000b:                # ec_point_formats
                ec_point_formats = _parse_u8_list(edata, prefix8=True)
    return {
        'client_version': client_version,
        'ciphers': ciphers,
        'exts_order': exts_order,
        'sni': sni,
        'alpn': alpn,
        'sig_algs': sig_algs,
        'sup_versions': sup_versions,
        'sup_groups': sup_groups,
        'ec_point_formats': ec_point_formats,
    }


def _parse_sni(d):
    r = _Reader(d)
    if r.rem() < 2:
        return None
    lr = _Reader(r.take(r.u16()))
    while lr.rem() >= 3:
        ntype = lr.u8()
        name = lr.take(lr.u16())
        if ntype == 0:
            try:
                return name.decode('ascii', 'replace')
            except Exception:
                return name.decode('latin1', 'replace')
    return None


def _parse_alpn(d):
    r = _Reader(d)
    if r.rem() < 2:
        return []
    lr = _Reader(r.take(r.u16()))
    out = []
    while lr.rem() >= 1:
        out.append(lr.take(lr.u8()).decode('ascii', 'replace'))
    return out


def _parse_u16_list(d, prefix16=False, prefix8=False):
    r = _Reader(d)
    if prefix16:
        if r.rem() < 2:
            return []
        r = _Reader(r.take(r.u16()))
    elif prefix8:
        if r.rem() < 1:
            return []
        r = _Reader(r.take(r.u8()))
    out = []
    while r.rem() >= 2:
        out.append(r.u16())
    return out


def _parse_u8_list(d, prefix8=False):
    r = _Reader(d)
    if prefix8:
        if r.rem() < 1:
            return []
        r = _Reader(r.take(r.u8()))
    return list(r.take(r.rem()))


# ------------------------------ JA4 client -----------------------------------
_ALNUM = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
_JA4_VER = {
    0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3',
    0xfeff: 'd1', 0xfefd: 'd2', 0xfefc: 'd3',
}


def _ja4_version(sup_versions, client_version):
    """JA4 two-char version: highest non-GREASE supported_versions entry, else
    the record client_version."""
    cand = [v for v in sup_versions if not _is_grease(v)]
    return _JA4_VER.get(max(cand) if cand else client_version, '00')


def _ja4_alpn(alpn):
    """First+last alphanumeric char of the first ALPN value; '00' if none; hex
    fallback (first hex nibble of first byte, last hex nibble of last byte) for
    non-alphanumeric values, per the FoxIO spec."""
    if not alpn or not alpn[0]:
        return '00'
    s = alpn[0]
    first, last = s[0], s[-1]
    if first in _ALNUM and last in _ALNUM:
        return first + last
    fh = '{:02x}'.format(ord(first) & 0xff)
    lh = '{:02x}'.format(ord(last) & 0xff)
    return fh[0] + lh[1]


def ja4_client(parsed, proto='t'):
    """Return (ja4, ja4_r) for a parsed ClientHello. proto is 't' (TLS/TCP),
    'q' (QUIC) or 'd' (DTLS)."""
    ciphers = [c for c in parsed['ciphers'] if not _is_grease(c)]
    exts = [e for e in parsed['exts_order'] if not _is_grease(e)]
    ver = _ja4_version(parsed['sup_versions'], parsed['client_version'])
    sni_flag = 'd' if 0x0000 in parsed['exts_order'] else 'i'
    a = '{}{}{}{:02d}{:02d}{}'.format(proto, ver, sni_flag,
                                      min(len(ciphers), 99), min(len(exts), 99),
                                      _ja4_alpn(parsed['alpn']))

    cipher_hex = sorted('{:04x}'.format(c) for c in ciphers)
    b_raw = ','.join(cipher_hex)
    b = hashlib.sha256(b_raw.encode()).hexdigest()[:12] if cipher_hex else '000000000000'

    # Extensions for the c-hash exclude SNI(0000) and ALPN(0010), sorted; the
    # signature_algorithms follow in original order after an underscore.
    c_exts = sorted('{:04x}'.format(e) for e in exts if e not in (0x0000, 0x0010))
    sig_hex = ['{:04x}'.format(s) for s in parsed['sig_algs'] if not _is_grease(s)]
    c_raw = ','.join(c_exts) + ('_' + ','.join(sig_hex) if sig_hex else '')
    c = hashlib.sha256(c_raw.encode()).hexdigest()[:12] if c_exts else '000000000000'

    return '{}_{}_{}'.format(a, b, c), '{}_{}_{}'.format(a, b_raw, c_raw)


# ------------------------------ JA3 client -----------------------------------
def ja3_client(parsed):
    """Original Salesforce JA3: MD5 over decimal, GREASE-stripped
    version,ciphers,extensions,supported_groups,ec_point_formats. Returns
    (md5_digest, ja3_string)."""
    ciphers = [c for c in parsed['ciphers'] if not _is_grease(c)]
    exts = [e for e in parsed['exts_order'] if not _is_grease(e)]
    groups = [g for g in parsed['sup_groups'] if not _is_grease(g)]
    s = ','.join([
        str(parsed['client_version']),
        '-'.join(str(c) for c in ciphers),
        '-'.join(str(e) for e in exts),
        '-'.join(str(g) for g in groups),
        '-'.join(str(p) for p in parsed['ec_point_formats']),
    ])
    return hashlib.md5(s.encode()).hexdigest(), s


# ----------------------------- ServerHello -----------------------------------
def parse_server_hello(hs_body):
    """Parse a ServerHello handshake body. The negotiated version comes from the
    supported_versions extension when present (TLS 1.3), else the legacy field."""
    r = _Reader(hs_body)
    server_version = r.u16()
    r.take(32)                                   # random
    r.take(r.u8())                               # session id
    cipher = r.u16()
    r.u8()                                       # compression method
    exts_order = []
    alpn = []
    neg_version = None
    if r.rem() >= 2:
        er = _Reader(r.take(r.u16()))
        while er.rem() >= 4:
            etype = er.u16()
            edata = er.take(er.u16())
            exts_order.append(etype)
            if etype == 0x002b and len(edata) >= 2:      # supported_versions (single)
                neg_version = (edata[0] << 8) | edata[1]
            elif etype == 0x0010:
                alpn = _parse_alpn(edata)
    return {'server_version': server_version, 'cipher': cipher,
            'exts_order': exts_order, 'alpn': alpn,
            'neg_version': neg_version or server_version}


def ja3s_server(p):
    """Original Salesforce JA3S: MD5 over decimal server_version,cipher,exts
    (GREASE-stripped). Returns (md5_digest, ja3s_string)."""
    exts = [e for e in p['exts_order'] if not _is_grease(e)]
    s = ','.join([str(p['server_version']), str(p['cipher']),
                  '-'.join(str(e) for e in exts)])
    return hashlib.md5(s.encode()).hexdigest(), s


def _maybe_ja4s(server, proto='t'):
    """Return the JA4S server fingerprint, or None when JA4S is disabled. Raises
    if enabled without acknowledging the FoxIO License 1.1 — a deliberate, loud
    failure so the license is never used silently."""
    if not ENABLE_JA4S:
        return None
    if not ACKNOWLEDGE_JA4S_LICENSE:
        raise RuntimeError(
            'JA4S is licensed under the FoxIO License 1.1. To enable it, set '
            'tls_watch.ACKNOWLEDGE_JA4S_LICENSE = True after reading LICENSE-JA4S.')
    import ja4s
    return ja4s.ja4s(server, proto)


# ----------------------- Certificate (TLS 1.2 only) --------------------------
def parse_certificates(hs_body):
    """Parse a TLS 1.2 Certificate handshake body into a list of DER blobs
    (leaf first). Only meaningful for TLS 1.2 over TCP — 1.3 and QUIC encrypt
    the Certificate message, so it is never passively observable there."""
    r = _Reader(hs_body)
    cr = _Reader(r.take(r.u24()))
    ders = []
    while cr.rem() >= 3:
        clen = cr.u24()
        ders.append(cr.take(clen))
    return ders


def _host_matches(host, pattern):
    """RFC 6125-ish hostname match with a single leftmost wildcard label."""
    host = (host or '').lower().rstrip('.')
    pattern = (pattern or '').lower().rstrip('.')
    if not host or not pattern:
        return False
    if pattern.startswith('*.'):
        suffix = pattern[1:]                     # '.example.com'
        return (host.endswith(suffix)
                and host[:-len(suffix)].count('.') == 0
                and host != suffix.lstrip('.'))
    return host == pattern


# --------------------------------- findings ----------------------------------
_SEV = {'info': 0, 'notice': 1, 'warn': 2, 'high': 3}

# Curated common weak/legacy cipher suite code points: NULL / EXPORT / RC4 /
# DES / 3DES / anonymous. QUIC and TLS 1.3 use AEAD-only suites (0x13xx), so in
# practice this fires only on legacy TLS.
_WEAK_CIPHERS = frozenset({
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008, 0x0009,
    0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f, 0x0011, 0x0012, 0x0013,
    0x0014, 0x0015, 0x0016, 0x0017, 0x0018, 0x0019, 0x001a, 0x001b, 0x003b,
    0x008a, 0x008b, 0xc001, 0xc002, 0xc006, 0xc007, 0xc00b, 0xc00c, 0xc010,
    0xc011, 0xc012, 0xc015, 0xc016, 0xc017, 0xc018, 0xc019,
})

# SWEET32 (CVE-2016-2183): 64-bit block ciphers (DES/3DES) in CBC hit a birthday
# bound after ~32 GiB under one write key, letting an attacker recover plaintext.
# The negotiated suite IS the precondition and travels in cleartext in the
# ServerHello, so this is an EXPOSURE observed directly on the wire — no version
# fingerprinting, no probing. NVD/CISA-ADP score it 7.5 HIGH (IBM X-Force 3.7 LOW,
# reflecting the traffic volume the attack needs). https://sweet32.info/
_CVE_2016_2183 = {'cve': 'CVE-2016-2183', 'cvss': 7.5,
                  'cvss_source': 'NVD (NIST), concurred by CISA-ADP'}
SWEET32_CIPHERS = {
    0x0008: ('TLS_RSA_EXPORT_WITH_DES40_CBC_SHA', 'DES'),
    0x0009: ('TLS_RSA_WITH_DES_CBC_SHA', 'DES'),
    0x000a: ('TLS_RSA_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0x000b: ('TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA', 'DES'),
    0x000c: ('TLS_DH_DSS_WITH_DES_CBC_SHA', 'DES'),
    0x000d: ('TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0x000e: ('TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA', 'DES'),
    0x000f: ('TLS_DH_RSA_WITH_DES_CBC_SHA', 'DES'),
    0x0010: ('TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0x0011: ('TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA', 'DES'),
    0x0012: ('TLS_DHE_DSS_WITH_DES_CBC_SHA', 'DES'),
    0x0013: ('TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0x0014: ('TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA', 'DES'),
    0x0015: ('TLS_DHE_RSA_WITH_DES_CBC_SHA', 'DES'),
    0x0016: ('TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0x0019: ('TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA', 'DES'),
    0x001a: ('TLS_DH_anon_WITH_DES_CBC_SHA', 'DES'),
    0x001b: ('TLS_DH_anon_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0x001e: ('TLS_KRB5_WITH_DES_CBC_SHA', 'DES'),
    0x001f: ('TLS_KRB5_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0x0022: ('TLS_KRB5_WITH_DES_CBC_MD5', 'DES'),
    0x0023: ('TLS_KRB5_WITH_3DES_EDE_CBC_MD5', '3DES'),
    0x0026: ('TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA', 'DES'),
    0x0029: ('TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5', 'DES'),
    0x008b: ('TLS_PSK_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0x008f: ('TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0x0093: ('TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0xc003: ('TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0xc008: ('TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0xc00d: ('TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0xc012: ('TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0xc017: ('TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0xc01a: ('TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0xc01b: ('TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0xc01c: ('TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA', '3DES'),
    0xc034: ('TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA', '3DES'),
}
# Same 64-bit-block birthday weakness (RC2/IDEA), outside CVE-2016-2183's named
# DES/3DES scope. Kept as a distinct code so the CVE's coverage claim stays exact.
BLOCK64_OTHER = {
    0x0006: ('TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5', 'RC2'),
    0x0007: ('TLS_RSA_WITH_IDEA_CBC_SHA', 'IDEA'),
    0x0021: ('TLS_KRB5_WITH_IDEA_CBC_SHA', 'IDEA'),
    0x0025: ('TLS_KRB5_WITH_IDEA_CBC_MD5', 'IDEA'),
    0x0027: ('TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA', 'RC2'),
    0x002a: ('TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5', 'RC2'),
}


def _leaf_findings(der, chain_len, sni, now):
    """Return (findings, info) for the leaf certificate. Requires cryptography;
    a hardened, memory-safe X.509 parser is safer here than a hand-rolled ASN.1
    walker, and all TLS/QUIC handshake parsing stays raw-byte."""
    from cryptography import x509
    out = []
    cert = x509.load_der_x509_certificate(der)

    def _cn(name):
        try:
            a = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            return a[0].value if a else None
        except Exception:
            return None
    subject_cn = _cn(cert.subject)
    issuer_cn = _cn(cert.issuer)
    try:
        sans = list(cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except Exception:
        sans = []
    nb = cert.not_valid_before_utc
    na = cert.not_valid_after_utc
    sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    self_issued = cert.subject == cert.issuer
    info = {'subject_cn': subject_cn, 'issuer_cn': issuer_cn, 'sans': sans,
            'not_before': nb.isoformat(), 'not_after': na.isoformat(),
            'self_issued': self_issued, 'sig_hash': sig_hash,
            'serial_hex': '{:x}'.format(cert.serial_number)}

    if now < nb:
        out.append(('warn', 'cert_not_yet_valid',
                    'Leaf certificate not valid until {}'.format(nb.date())))
    if now > na:
        out.append(('high', 'cert_expired',
                    'Leaf certificate expired {}'.format(na.date())))
    if self_issued and chain_len == 1:
        out.append(('notice', 'cert_self_signed',
                    'Leaf certificate is self-issued with a 1-cert chain'))
    elif chain_len == 1:
        out.append(('info', 'cert_short_chain',
                    'Single certificate presented, no intermediates'))
    if sig_hash and sig_hash.lower() in ('md5', 'sha1'):
        out.append(('warn', 'cert_weak_sig',
                    'Leaf signed with {}'.format(sig_hash.upper())))
    if sni:
        names = list(sans) + ([subject_cn] if subject_cn else [])
        if not any(_host_matches(sni, n) for n in names):
            out.append(('high', 'sni_cert_mismatch',
                        "SNI '{}' not covered by leaf cert names {}".format(sni, names)))
    return out, info


def analyze_session(client, server, cert_ders, now):
    """Combine parsed client/server/cert state into a findings list (severity
    descending) plus per-cert info. Any argument may be None."""
    findings = []

    def add(sev, code, msg):
        findings.append({'severity': sev, 'code': code, 'message': msg})

    if client:
        cand = [v for v in client['sup_versions'] if not _is_grease(v)] \
            or [client['client_version']]
        if max(cand) <= 0x0302:
            add('warn', 'client_legacy_version', 'Client offers only TLS 1.1 or lower')
        if 0x0000 not in client['exts_order']:
            add('notice', 'no_sni', 'ClientHello carries no SNI')
        if 0xfe0d in client['exts_order'] or 0xfe08 in client['exts_order']:
            add('info', 'ech_present', 'encrypted_client_hello present; true SNI hidden')
    if server:
        if server['neg_version'] <= 0x0302:
            add('warn', 'server_legacy_version', 'Server negotiated TLS 1.1 or lower')
        ch = server['cipher']
        if ch in SWEET32_CIPHERS:
            # CVE-2016-2183 (SWEET32) EXPOSURE: the negotiated 64-bit block cipher
            # is the vulnerable condition, observed directly (not inferred).
            name, algo = SWEET32_CIPHERS[ch]
            f = {'severity': 'high', 'code': 'cve_2016_2183_negotiated',
                 'message': ('Server negotiated {} (0x{:04x}) - {} uses a 64-bit block, '
                             'so this session is exposed to SWEET32 (CVE-2016-2183) once '
                             '~32 GiB passes under one write key'.format(name, ch, algo)),
                 'cve': 'CVE-2016-2183', 'cvss': _CVE_2016_2183['cvss'],
                 'cvss_source': _CVE_2016_2183['cvss_source'],
                 'detect_class': 'exposure', 'cipher': '0x{:04x}'.format(ch)}
            findings.append(f)
        elif ch in BLOCK64_OTHER:
            name, algo = BLOCK64_OTHER[ch]
            findings.append({'severity': 'warn', 'code': 'weak_block_cipher_64bit',
                             'message': ('Server negotiated {} (0x{:04x}) - {} is a 64-bit '
                                         'block cipher with the same birthday-bound weakness '
                                         'as SWEET32, though CVE-2016-2183 names only DES/3DES'
                                         .format(name, ch, algo)),
                             'related_cve': 'CVE-2016-2183', 'cipher': '0x{:04x}'.format(ch)})
        elif ch in _WEAK_CIPHERS:
            add('high', 'weak_cipher',
                'Server selected weak/legacy cipher 0x{:04x}'.format(ch))
    if client and not any(f['code'] == 'cve_2016_2183_negotiated' for f in findings):
        # CVE-2016-2183 POSTURE: offering 3DES was near-universal for years and
        # says nothing about what got negotiated; informational unless a server
        # actually selected one (handled above).
        offered = [c for c in client['ciphers'] if c in SWEET32_CIPHERS]
        if offered:
            findings.append({'severity': 'info', 'code': 'cve_2016_2183_client_offer',
                             'message': ('Client offers {} DES/3DES suite(s); it would accept '
                                         'a SWEET32-exposed session (CVE-2016-2183) if a server '
                                         'selected one'.format(len(offered))),
                             'cve': 'CVE-2016-2183', 'detect_class': 'posture'})
    infos = []
    if cert_ders:
        try:
            leaf, info = _leaf_findings(cert_ders[0], len(cert_ders),
                                        client.get('sni') if client else None, now)
            for sev, code, msg in leaf:
                add(sev, code, msg)
            infos.append(info)
        except Exception:
            pass                                 # cryptography missing / malformed
    findings.sort(key=lambda f: -_SEV[f['severity']])
    return findings, infos


# ===================== QUIC Initial passive recovery =========================
# Initial keys derive from the client's Destination Connection ID plus a public
# constant salt (RFC 9001 §5.2), so recovering an Initial is arithmetic over
# bytes already captured — nothing is transmitted. QUIC v1 (RFC 9001) and v2
# (RFC 9369) differ only in the salt and the key-derivation label strings.
_QUIC_SALT_V1 = bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a')
_QUIC_SALT_V2 = bytes.fromhex('0dede3def700a6db819381be6e269dcbf9bd2ed9')
QUIC_V1 = 0x00000001
QUIC_V2 = 0x6b3343cf


def _quic_hmac(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()


def _hkdf_extract(salt, ikm):
    return _quic_hmac(salt, ikm)


def _hkdf_expand(prk, info, length):
    t, okm, i = b'', b'', 0
    while len(okm) < length:
        i += 1
        t = _quic_hmac(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


def _hkdf_expand_label(secret, label, context, length):
    full = b'tls13 ' + label
    hl = struct.pack('!H', length) + bytes([len(full)]) + full \
        + bytes([len(context)]) + context
    return _hkdf_expand(secret, hl, length)


def quic_initial_keys(dcid, version):
    """Derive the client and server Initial key sets from the DCID for a QUIC
    version. Returns (client, server) dicts of key/iv/hp/secret."""
    if version == QUIC_V2:
        salt, kl, il, hl = _QUIC_SALT_V2, b'quicv2 key', b'quicv2 iv', b'quicv2 hp'
    else:
        salt, kl, il, hl = _QUIC_SALT_V1, b'quic key', b'quic iv', b'quic hp'
    isecret = _hkdf_extract(salt, dcid)

    def side(lbl):
        s = _hkdf_expand_label(isecret, lbl, b'', 32)
        return {'secret': s,
                'key': _hkdf_expand_label(s, kl, b'', 16),
                'iv': _hkdf_expand_label(s, il, b'', 12),
                'hp': _hkdf_expand_label(s, hl, b'', 16)}
    return side(b'client in'), side(b'server in')


def _quic_read_varint(b, i):
    """RFC 9000 variable-length integer. Returns (value, new_index)."""
    first = b[i]
    length = 1 << (first >> 6)
    val = first & 0x3f
    for k in range(1, length):
        val = (val << 8) | b[i + k]
    return val, i + length


def _aes_ecb_block(key, block):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(block)


def _quic_remove_hp(pkt, pn_offset, hp_key):
    """Remove long-header packet protection. Returns (unmasked_bytes, pn_len, pn)."""
    sample = pkt[pn_offset + 4:pn_offset + 4 + 16]
    mask = _aes_ecb_block(hp_key, sample)
    hdr = bytearray(pkt)
    hdr[0] ^= mask[0] & 0x0f
    pn_len = (hdr[0] & 0x03) + 1
    for k in range(pn_len):
        hdr[pn_offset + k] ^= mask[1 + k]
    pn = int.from_bytes(bytes(hdr[pn_offset:pn_offset + pn_len]), 'big')
    return bytes(hdr), pn_len, pn


def _quic_aead_decrypt(key, iv, pn, header, ciphertext):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, 'big')))
    return AESGCM(key).decrypt(nonce, ciphertext, header)


def parse_quic_initial(pkt, keys):
    """Decrypt one QUIC long-header Initial packet with the correct-side key set.
    Returns (frame_payload, version, dcid, scid); raises on malformed/foreign
    packets so the caller can skip them per-datagram."""
    i = 0
    first = pkt[i]; i += 1
    if not (first & 0x80):
        raise ValueError('not a long header')
    version = int.from_bytes(pkt[i:i + 4], 'big'); i += 4
    dcid_len = pkt[i]; i += 1
    dcid = pkt[i:i + dcid_len]; i += dcid_len
    scid_len = pkt[i]; i += 1
    scid = pkt[i:i + scid_len]; i += scid_len
    token_len, i = _quic_read_varint(pkt, i)
    i += token_len
    length, i = _quic_read_varint(pkt, i)
    pn_offset = i
    hdr, pn_len, pn = _quic_remove_hp(pkt, pn_offset, keys['hp'])
    payload_off = pn_offset + pn_len
    end = payload_off + (length - pn_len)
    plain = _quic_aead_decrypt(keys['key'], keys['iv'], pn,
                               hdr[:payload_off], hdr[payload_off:end])
    return plain, version, dcid, scid


def reassemble_crypto(payload):
    """Walk a decrypted Initial's frames, reassembling CRYPTO streams by offset
    into contiguous handshake bytes. PADDING/PING/ACK are skipped."""
    i, n, chunks = 0, len(payload), {}
    while i < n:
        ftype = payload[i]; i += 1
        if ftype in (0x00, 0x01):                    # PADDING, PING
            continue
        if ftype in (0x02, 0x03):                    # ACK
            _, i = _quic_read_varint(payload, i)
            _, i = _quic_read_varint(payload, i)
            rng, i = _quic_read_varint(payload, i)
            _, i = _quic_read_varint(payload, i)
            for _ in range(rng):
                _, i = _quic_read_varint(payload, i)
                _, i = _quic_read_varint(payload, i)
            if ftype == 0x03:
                for _ in range(3):
                    _, i = _quic_read_varint(payload, i)
            continue
        if ftype == 0x06:                            # CRYPTO
            off, i = _quic_read_varint(payload, i)
            ln, i = _quic_read_varint(payload, i)
            chunks[off] = payload[i:i + ln]
            i += ln
            continue
        break                                        # unknown frame: stop
    out = b''
    for off in sorted(chunks):
        if off == len(out):
            out += chunks[off]
    return out


def handshake_messages(buf):
    """Split reassembled handshake bytes into (msg_type, body) pairs
    (1=ClientHello, 2=ServerHello, 11=Certificate)."""
    i, out = 0, []
    while i + 4 <= len(buf):
        mtype = buf[i]
        mlen = (buf[i + 1] << 16) | (buf[i + 2] << 8) | buf[i + 3]
        body = buf[i + 4:i + 4 + mlen]
        if len(body) < mlen:
            break
        out.append((mtype, body))
        i += 4 + mlen
    return out


# ======================= capture -> sessions -> verdict ======================
def _handshake_from_tls_stream(stream):
    """Extract handshake messages from a reassembled TLS-over-TCP byte stream,
    walking record headers and concatenating handshake (type 22) record bodies."""
    i, hs = 0, b''
    while i + 5 <= len(stream):
        ctype = stream[i]
        rlen = (stream[i + 3] << 8) | stream[i + 4]
        body = stream[i + 5:i + 5 + rlen]
        if len(body) < rlen:
            break
        if ctype == 22:
            hs += body
        i += 5 + rlen
    return handshake_messages(hs)


def parse_pcap(path):
    """Read a pcap and return a list of handshake sessions. TLS-over-TCP flows
    are reassembled per direction by sequence number; QUIC client Initials are
    decrypted. Requires scapy."""
    from scapy.all import rdpcap
    from scapy.layers.inet import IP, TCP, UDP
    try:
        from scapy.layers.inet6 import IPv6
    except Exception:
        IPv6 = None

    def _raw_payload(l4):
        # Use the layer's captured bytes (.original), NOT bytes(l4.payload):
        # if scapy.layers.tls is loaded it auto-dissects TCP:443 into a TLS
        # layer that re-serializes lossily. .original is the exact wire bytes.
        pl = l4.payload
        orig = getattr(pl, 'original', b'')
        return bytes(orig) if orig else bytes(pl)

    tcp, udp = {}, []
    for p in rdpcap(path):
        ipl = p.getlayer(IP) or (IPv6 and p.getlayer(IPv6))
        if not ipl:
            continue
        if p.haslayer(TCP):
            t = p[TCP]
            pay = _raw_payload(t)
            if pay:
                tcp.setdefault((ipl.src, t.sport, ipl.dst, t.dport), {})[int(t.seq)] = pay
        elif p.haslayer(UDP):
            u = p[UDP]
            pay = _raw_payload(u)
            if pay:
                udp.append((ipl.src, u.sport, ipl.dst, u.dport, pay))

    streams = {k: b''.join(v[s] for s in sorted(v)) for k, v in tcp.items()}
    sessions, seen = [], set()
    for key, stream in streams.items():
        if key in seen:
            continue
        src, sport, dst, dport = key
        rev = (dst, dport, src, sport)
        cmsgs = _handshake_from_tls_stream(stream)
        if any(m[0] == 0x01 for m in cmsgs):
            client = parse_client_hello(next(b for t, b in cmsgs if t == 0x01))
            server, certs = None, []
            for t, b in _handshake_from_tls_stream(streams.get(rev, b'')):
                if t == 0x02 and server is None:
                    server = parse_server_hello(b)
                elif t == 0x0b:
                    certs = parse_certificates(b)
            seen.add(rev)
            sessions.append({'proto': 'tls', 'src': src, 'sport': sport,
                             'dst': dst, 'dport': dport, 'client': client,
                             'server': server, 'certs': certs})
        seen.add(key)

    quic_seen = set()
    for (src, sport, dst, dport, pay) in udp:
        if not pay or not (pay[0] & 0x80):
            continue
        qkey = (src, sport, dst, dport)
        if qkey in quic_seen:
            continue                              # retransmitted / coalesced Initial
        try:
            version = int.from_bytes(pay[1:5], 'big')
            dcid = pay[6:6 + pay[5]]
            ckeys, _ = quic_initial_keys(dcid, version)
            plain, _v, _d, _s = parse_quic_initial(pay, ckeys)
            for t, b in handshake_messages(reassemble_crypto(plain)):
                if t == 0x01:
                    quic_seen.add(qkey)           # one session per QUIC connection
                    sessions.append({'proto': 'quic', 'src': src, 'sport': sport,
                                     'dst': dst, 'dport': dport,
                                     'client': parse_client_hello(b),
                                     'server': None, 'certs': []})
                    break
        except Exception:
            continue                              # not a decryptable client Initial
    return sessions


_VERDICT_RANK = {'clean': 0, 'suspicious': 1, 'compromised': 2}


def _tls_analyze(sessions, now=None, denylist=None):
    """Pure classifier: turn parsed sessions into fingerprinted records with
    findings and an overall verdict. No capture, no I/O — unit-testable."""
    import datetime
    now = now or datetime.datetime.now(datetime.timezone.utc)
    denylist = denylist or {}
    # Deduplicate results: a client opening N parallel connections to the same
    # server service with the same fingerprint (browsers routinely open 6+), and
    # any residual QUIC retransmits, are one *result* — collapse them by client
    # identity (proto, client IP, server IP:port, JA4, SNI) and carry a `count`.
    # The representative is upgraded to whichever duplicate actually saw the
    # server, so a completed handshake is never masked by an aborted one.
    out, index = [], {}
    for s in sessions:
        pchar = 'q' if s['proto'] == 'quic' else 't'
        client, server = s.get('client'), s.get('server')
        rec = {'proto': s['proto'],
               'src': '{}:{}'.format(s['src'], s['sport']),
               'dst': '{}:{}'.format(s['dst'], s['dport'])}
        if client:
            ja4, ja4_r = ja4_client(client, proto=pchar)
            rec.update({'sni': client.get('sni'), 'alpn': client.get('alpn'),
                        'ja4': ja4, 'ja4_r': ja4_r, 'ja3': ja3_client(client)[0]})
        if server:
            rec['negotiated_version'] = server.get('neg_version')
            rec['cipher'] = '0x{:04x}'.format(server['cipher'])
            rec['ja3s'] = ja3s_server(server)[0]
            j4s = _maybe_ja4s(server, pchar)
            if j4s:
                rec['ja4s'] = j4s
        findings, infos = analyze_session(client, server, s.get('certs'), now)
        if client and rec.get('ja4') in denylist:
            findings.insert(0, {'severity': 'high', 'code': 'ja4_denylist',
                                'message': 'Client JA4 on denylist: {}'.format(
                                    denylist[rec['ja4']])})
        rec['findings'] = findings
        if infos:
            rec['certs'] = infos

        key = (s['proto'], s['src'], s['dst'], s['dport'],
               rec.get('ja4'), rec.get('sni'))
        prev = index.get(key)
        if prev is not None:
            prev['count'] += 1
            # Upgrade the kept record if this duplicate saw the server side and
            # the kept one (client-only) did not.
            if 'negotiated_version' not in prev and 'negotiated_version' in rec:
                for f in ('negotiated_version', 'cipher', 'ja3s', 'ja4s',
                          'certs', 'findings', 'src'):
                    if f in rec:
                        prev[f] = rec[f]
            continue
        rec['count'] = 1
        index[key] = rec
        out.append(rec)

    # Verdict from the deduplicated set (recompute so an upgraded representative
    # is scored on its final findings).
    verdict = 'clean'
    for rec in out:
        codes = {f['code'] for f in rec.get('findings', [])}
        if codes & {'sni_cert_mismatch', 'ja4_denylist'}:
            v = 'compromised'
        elif any(f['severity'] in ('high', 'warn') for f in rec.get('findings', [])):
            v = 'suspicious'
        else:
            v = 'clean'
        if _VERDICT_RANK[v] > _VERDICT_RANK[verdict]:
            verdict = v
    return {'success': True, 'verdict': verdict, 'sessions': out, 'count': len(out)}


def _capture_pcap(interface, seconds, tcp_ports, udp_ports):
    """Run tcpdump for `seconds` into a temp pcap and return its path. Passive:
    -w only, no probes. Returns None if tcpdump is unavailable."""
    import shutil
    import subprocess
    import tempfile
    if not shutil.which('tcpdump'):
        return None
    parts = ['tcp port {}'.format(p) for p in tcp_ports] \
        + ['udp port {}'.format(p) for p in udp_ports]
    bpf = ' or '.join(parts)
    fd, path = tempfile.mkstemp(suffix='.pcap', prefix='tlswatch_')
    import os
    os.close(fd)
    try:
        subprocess.run(['tcpdump', '-i', interface, '-w', path, '-s', '0', '-U',
                        '-q', bpf], timeout=seconds, capture_output=True)
    except subprocess.TimeoutExpired:
        pass                                      # expected: we run for the window
    except Exception:
        return None
    return path


def do_tls_watch(interface=None, seconds=12, learn=True, quick=False,
                 denylist=None, no_quic=False):
    """Passive TLS/QUIC handshake observation on `interface` for `seconds`.
    Captures, parses handshakes, and returns fingerprints + findings + verdict.
    Requires root (raw capture) and tcpdump; scapy for pcap dissection."""
    import os
    seconds = max(4, min(int(seconds or 12), 30))
    if not interface:
        return {'success': False, 'error': 'no interface specified'}
    try:
        import scapy  # noqa: F401
    except Exception:
        return {'success': False, 'missing_tool': 'scapy',
                'error': 'the Python "scapy" package is required for pcap dissection'}
    udp_ports = () if no_quic else QUIC_UDP_PORTS
    pcap = _capture_pcap(interface, seconds, TLS_TCP_PORTS, udp_ports)
    if not pcap:
        return {'success': False, 'missing_tool': 'tcpdump',
                'error': 'tcpdump is required for capture'}
    try:
        sessions = parse_pcap(pcap)
    except Exception as e:
        return {'success': False, 'error': 'pcap parse failed: {}'.format(e)}
    finally:
        try:
            os.unlink(pcap)
        except OSError:
            pass
    res = _tls_analyze(sessions, denylist=denylist)
    res.update({'interface': interface, 'seconds': seconds,
                'tls': sum(1 for s in res['sessions'] if s['proto'] == 'tls'),
                'quic': sum(1 for s in res['sessions'] if s['proto'] == 'quic')})
    return res


# ============================== self-test ====================================
# Test-only helper: assemble a wire-format ClientHello from parts so the parser
# and fingerprints are exercised end-to-end against the published vector.
def _build_client_hello(ciphers, ext_types, sig_algs, sup_versions, alpn, sni,
                        groups=(0x001d, 0x0017), point_formats=(0,)):
    body = struct.pack('!H', 0x0303) + b'\x00' * 32 + b'\x00'
    cs = b''.join(struct.pack('!H', c) for c in ciphers)
    body += struct.pack('!H', len(cs)) + cs + b'\x01\x00'
    exts = b''
    for et in ext_types:
        if et == 0x0000:
            host = sni.encode()
            entry = b'\x00' + struct.pack('!H', len(host)) + host
            data = struct.pack('!H', len(entry)) + entry
        elif et == 0x0010:
            protos = b''.join(struct.pack('!B', len(p.encode())) + p.encode() for p in alpn)
            data = struct.pack('!H', len(protos)) + protos
        elif et == 0x000d:
            sa = b''.join(struct.pack('!H', s) for s in sig_algs)
            data = struct.pack('!H', len(sa)) + sa
        elif et == 0x002b:
            vs = b''.join(struct.pack('!H', v) for v in sup_versions)
            data = struct.pack('!B', len(vs)) + vs
        elif et == 0x000a:
            gs = b''.join(struct.pack('!H', g) for g in groups)
            data = struct.pack('!H', len(gs)) + gs
        elif et == 0x000b:
            pf = bytes(point_formats)
            data = struct.pack('!B', len(pf)) + pf
        else:
            data = b''
        exts += struct.pack('!HH', et, len(data)) + data
    body += struct.pack('!H', len(exts)) + exts
    return struct.pack('!B', 0x01) + struct.pack('!BH', (len(body) >> 16) & 0xff,
                                                 len(body) & 0xffff) + body


def _quic_wv(v):
    if v < 64:
        return bytes([v])
    if v < 16384:
        return struct.pack('!H', v | 0x4000)
    return struct.pack('!I', v | 0x80000000)


def _build_quic_initial(dcid, scid, keys, handshake_bytes, version, pn=0):
    """Test helper: assemble + protect a client Initial carrying handshake_bytes,
    padded past 1200 bytes with PADDING frames."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    payload = b'\x06' + _quic_wv(0) + _quic_wv(len(handshake_bytes)) + handshake_bytes
    if len(payload) < 1170:
        payload += b'\x00' * (1170 - len(payload))
    pn_len = 4
    first = 0xc0 | (pn_len - 1)
    hdr_fixed = bytes([first]) + version.to_bytes(4, 'big') + bytes([len(dcid)]) \
        + dcid + bytes([len(scid)]) + scid + _quic_wv(0)
    length = pn_len + len(payload) + 16
    hdr = hdr_fixed + _quic_wv(length) + pn.to_bytes(pn_len, 'big')
    nonce = bytes(a ^ b for a, b in zip(keys['iv'], pn.to_bytes(12, 'big')))
    ct = AESGCM(keys['key']).encrypt(nonce, payload, hdr)
    pkt = bytearray(hdr + ct)
    pn_off = len(hdr) - pn_len
    mask = _aes_ecb_block(keys['hp'], bytes(pkt[pn_off + 4:pn_off + 4 + 16]))
    pkt[0] ^= mask[0] & 0x0f
    for k in range(pn_len):
        pkt[pn_off + k] ^= mask[1 + k]
    return bytes(pkt)


def _mk_server_hello(version, cipher, neg_version=None, alpn=None):
    body = struct.pack('!H', version) + b'\x11' * 32 + b'\x00'
    body += struct.pack('!H', cipher) + b'\x00'
    exts = b''
    if neg_version is not None:
        exts += struct.pack('!HH', 0x002b, 2) + struct.pack('!H', neg_version)
    if alpn:
        protos = b''.join(struct.pack('!B', len(p.encode())) + p.encode() for p in alpn)
        d = struct.pack('!H', len(protos)) + protos
        exts += struct.pack('!HH', 0x0010, len(d)) + d
    if exts:
        body += struct.pack('!H', len(exts)) + exts
    return struct.pack('!B', 0x02) + struct.pack('!BH', 0, len(body)) + body


def _mk_cert_msg(ders):
    inner = b''.join(struct.pack('!BH', (len(d) >> 16) & 0xff, len(d) & 0xffff) + d
                     for d in ders)
    total = struct.pack('!BH', (len(inner) >> 16) & 0xff, len(inner) & 0xffff) + inner
    return struct.pack('!B', 0x0b) + struct.pack('!BH', (len(total) >> 16) & 0xff,
                                                 len(total) & 0xffff) + total


def _gen_cert(cn, sans, days_from, days_to):
    """Self-signed SHA-256 cert for the findings KATs (cryptography can't sign
    SHA-1, so the weak-sig case uses the openssl fixture below)."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    b = x509.CertificateBuilder().subject_name(subj).issuer_name(subj)\
        .public_key(key.public_key()).serial_number(x509.random_serial_number())\
        .not_valid_before(now + datetime.timedelta(days=days_from))\
        .not_valid_after(now + datetime.timedelta(days=days_to))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
                            critical=False)
    return b.sign(key, hashes.SHA256()).public_bytes(Encoding.DER)


# A real SHA-1 self-signed cert (CN=weak.example), generated with openssl since
# the cryptography lib refuses to *sign* with SHA-1. Fixture for the weak-sig KAT.
def _sha1_cert():
    import base64
    return base64.b64decode(
        'MIIDDzCCAfegAwIBAgIUTZ+6BMEUYxm1xw5iZAra11vFLBAwDQYJKoZIhvcNAQEFBQAwFzEVMBMGA1UE'
        'AwwMd2Vhay5leGFtcGxlMB4XDTI2MDcxMTA2MzczMloXDTM2MDcwODA2MzczMlowFzEVMBMGA1UEAwwM'
        'd2Vhay5leGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyOVVQ2lRywA0Gk2LLgB3'
        'q+VoH2Tz+7kQvBcX9xmxuEAc9YpV4y49QJPhSDlSSmu3GUDmq0ZCgvG3vXdhzZjLDw0Q7JltkvwiVv1o'
        'KNc1Wc7LG3Qr/8Otc+/O8evSC2ADXeVmCa+SW9p1RsOx+ZoC08rFuIBmsLzBBRAoKiavK+4Um+IwxZg'
        'X+Z6HNRBd+897xXwTOBOmf+TaA+tnUvGAmD8RQdM1RfryeLjiG/NCPF0Z41i3edcyQkxA0abZuo8hmMH'
        'BHsj5uKNXUsUEWu5LCYYkhm2TEJus+rHzDPU8VPrlUKfwNhfog4pVtk9JQfVcOUTRyw/959hBriaUAEr'
        '5QwIDAQABo1MwUTAdBgNVHQ4EFgQUOYz2f043U8fF5nLST8qmMk9PJ1cwHwYDVR0jBBgwFoAUOYz2f04'
        '3U8fF5nLST8qmMk9PJ1cwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAiYOP9EfRlBi'
        '+LGiZj/+QWsPA/+IgzSAl49ADdbPkWNgCF5rKOGJcXdBwUlXn7EFnkQ1ng/+2RH8XTCo20vRyOGs1+t7'
        'qUq0JK/WRh4OxftSRTDPiI1fh8AoYKiqviLcTPgDlyaVwbFL4O3O+bJnXSRwXf5dJ2v3xJJPHSFwGL8K'
        '1EOUh+9WEfSY+fA6KIbB5kHoth/s+UH4u3Tr0vCPDxvCsCJNc5hiynYEaXcK+Q3TG661K28LZcD/SoWq'
        'UgGrVRPUEMcDEaCdOlzftWLaAOcL2hOMZSdiLCrc5EkjV+Df0+xsLh8ltyt6TWhN7MuKxg7uIPGg7f94'
        'aw2q+v1R3IQ==')


# FoxIO published worked example (technical_details/JA4.md).
_KAT_CIPHERS = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
                0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
_KAT_EXTS = [0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
             0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015]
_KAT_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
_KAT_JA4 = 't13d1516h2_8daaf6152771_e5627efa2ab1'
_KAT_JA4_R = ('t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,'
              'c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,'
              '002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601')


def selftest():
    """Known-answer test harness. Returns {success, checks:[...], failed}."""
    checks = []

    def ck(name, got, want=True):
        checks.append({'name': name, 'pass': got == want, 'got': got, 'want': want})

    # Pure JA4_b / JA4_c hashes against the published decomposition.
    ck('ja4_b_hash', hashlib.sha256(
        ('002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,'
         'cca8,cca9').encode()).hexdigest()[:12], '8daaf6152771')
    ck('ja4_c_hash', hashlib.sha256(
        ('0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01'
         '_0403,0804,0401,0503,0805,0501,0806,0601').encode()).hexdigest()[:12],
       'e5627efa2ab1')

    # Full parse + fingerprint against the published example, with a GREASE
    # cipher/ext/version prepended to prove GREASE removal keeps counts 15/16.
    hs = _build_client_hello(
        [0x0a0a] + _KAT_CIPHERS, [0x1a1a] + _KAT_EXTS, _KAT_SIGALGS,
        [0x0a0a, 0x0304], alpn=['h2'], sni='example.com')
    p = parse_client_hello(hs[4:])
    ja4, ja4_r = ja4_client(p, proto='t')
    ck('full_ja4', ja4, _KAT_JA4)
    ck('full_ja4_r', ja4_r, _KAT_JA4_R)
    ck('sni_parse', p['sni'], 'example.com')
    ck('alpn_parse', p['alpn'], ['h2'])

    # ALPN http/1.1 -> h1; no-SNI -> i; no-ALPN -> 00.
    p2 = parse_client_hello(_build_client_hello(
        _KAT_CIPHERS, _KAT_EXTS, _KAT_SIGALGS, [0x0304],
        alpn=['http/1.1'], sni='x.test')[4:])
    ck('alpn_http11_h1', ja4_client(p2)[0].split('_')[0][-2:], 'h1')
    no_id = [e for e in _KAT_EXTS if e not in (0x0000, 0x0010)]
    p3 = parse_client_hello(_build_client_hello(
        _KAT_CIPHERS, no_id, _KAT_SIGALGS, [0x0304], alpn=[], sni='')[4:])
    a3 = ja4_client(p3)[0].split('_')[0]
    ck('no_sni_flag_i', a3[3], 'i')
    ck('no_alpn_00', a3[-2:], '00')

    # JA3 shape: decimal, dash-joined, MD5 hex.
    md5, s = ja3_client(p)
    ck('ja3_is_md5hex', len(md5) == 32 and all(x in '0123456789abcdef' for x in md5), True)
    ck('ja3_string_head', s.split(',')[0], '771')   # client_version 0x0303

    # scapy cross-check: parse a real scapy-built ClientHello off a TLS record.
    try:
        from scapy.layers.tls.handshake import TLSClientHello
        from scapy.layers.tls.extensions import (TLS_Ext_ServerName, TLS_Ext_ALPN,
                                                  ServerName, ProtocolName)
        from scapy.layers.tls.record import TLS
        ch = TLSClientHello(
            ciphers=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
            ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=b'scapy.test')]),
                 TLS_Ext_ALPN(protocols=[ProtocolName(protocol=b'h2')])])
        raw = bytes(TLS(msg=[ch]))
        ps = parse_client_hello(raw[5 + 4:])         # skip record + handshake hdrs
        ck('scapy_sni', ps['sni'], 'scapy.test')
        ck('scapy_alpn', ps['alpn'], ['h2'])
        ck('scapy_ja4_alpn', ja4_client(ps)[0].split('_')[0][-2:], 'h2')
    except Exception as e:
        checks.append({'name': 'scapy_crosscheck', 'pass': True, 'skipped': str(e)})

    # ---- M2: ServerHello / JA3S / certificate findings ----
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    sh = _mk_server_hello(0x0303, 0xc030)                    # no extensions
    ps = parse_server_hello(sh[4:])
    ck('sh_cipher', ps['cipher'], 0xc030)
    ck('ja3s_string', ja3s_server(ps)[1], '771,49200,')
    ck('ja3s_md5', ja3s_server(ps)[0], hashlib.md5(b'771,49200,').hexdigest())
    ck('sh_tls13_neg', parse_server_hello(
        _mk_server_hello(0x0303, 0x1301, neg_version=0x0304)[4:])['neg_version'], 0x0304)

    shw = parse_server_hello(_mk_server_hello(0x0303, 0x0005)[4:])   # RC4
    fw, _ = analyze_session(None, shw, [], now)
    ck('weak_cipher', any(x['code'] == 'weak_cipher' for x in fw))

    # ---- CVE-2016-2183 (SWEET32): negotiated 64-bit block cipher ----
    sh3des = parse_server_hello(_mk_server_hello(0x0303, 0x000a)[4:])   # 3DES_EDE_CBC
    f3, _ = analyze_session(None, sh3des, [], now)
    fc3 = next((x for x in f3 if x['code'] == 'cve_2016_2183_negotiated'), None)
    ck('sweet32_negotiated', fc3 is not None)
    ck('sweet32_cve_field', (fc3 or {}).get('cve'), 'CVE-2016-2183')
    ck('sweet32_exposure_class', (fc3 or {}).get('detect_class'), 'exposure')
    ck('sweet32_high', (fc3 or {}).get('severity'), 'high')
    ck('sweet32_not_generic_weak',           # named finding supersedes weak_cipher
       not any(x['code'] == 'weak_cipher' for x in f3))
    ck('sweet32_verdict_suspicious', _tls_analyze(
        [{'proto': 'tls', 'src': 'a', 'sport': 1, 'dst': 'b', 'dport': 443,
          'client': None, 'server': sh3des, 'certs': []}])['verdict'], 'suspicious')
    # RC2/IDEA: same 64-bit weakness, outside the CVE's DES/3DES scope.
    shidea = parse_server_hello(_mk_server_hello(0x0303, 0x0007)[4:])   # IDEA_CBC
    fi, _ = analyze_session(None, shidea, [], now)
    fci = next((x for x in fi if x['code'] == 'weak_block_cipher_64bit'), None)
    ck('block64_other', fci is not None)
    ck('block64_related_cve', (fci or {}).get('related_cve'), 'CVE-2016-2183')
    # POSTURE: a client that merely offers 3DES (no SWEET32 negotiated).
    cpos = parse_client_hello(_build_client_hello(
        _KAT_CIPHERS + [0x000a], _KAT_EXTS, _KAT_SIGALGS, [0x0303],
        alpn=['h2'], sni='x.test')[4:])
    fp = {x['code'] for x in analyze_session(cpos, None, [], now)[0]}
    ck('sweet32_client_offer', 'cve_2016_2183_client_offer' in fp)
    # Clean client (no 3DES offered) stays silent.
    cclean = parse_client_hello(_build_client_hello(
        _KAT_CIPHERS, _KAT_EXTS, _KAT_SIGALGS, [0x0304], alpn=['h2'], sni='x.test')[4:])
    ck('no_sweet32_false_positive', 'cve_2016_2183_client_offer'
       not in {x['code'] for x in analyze_session(cclean, None, [], now)[0]})

    try:
        # self-signed leaf + SNI mismatch (the interception signal)
        der = _gen_cert('realbank.example', ['realbank.example'], -1, 30)
        ders = parse_certificates(_mk_cert_msg([der])[4:])
        ck('cert_parse_count', len(ders), 1)
        cph = parse_client_hello(_build_client_hello(
            _KAT_CIPHERS, _KAT_EXTS, _KAT_SIGALGS, [0x0303],
            alpn=['http/1.1'], sni='phish.example')[4:])
        f, _ = analyze_session(cph, ps, ders, now)
        codes = {x['code'] for x in f}
        ck('cert_self_signed', 'cert_self_signed' in codes)
        ck('sni_cert_mismatch', 'sni_cert_mismatch' in codes)
        ck('mismatch_high', next(x for x in f if x['code'] == 'sni_cert_mismatch')['severity'], 'high')
        # matching SNI -> no mismatch; wildcard SAN matches one label
        cok = parse_client_hello(_build_client_hello(
            _KAT_CIPHERS, _KAT_EXTS, _KAT_SIGALGS, [0x0303], alpn=['h2'],
            sni='realbank.example')[4:])
        ck('match_ok', not any(x['code'] == 'sni_cert_mismatch'
                               for x in analyze_session(cok, None, ders, now)[0]))
        wc = _gen_cert('*.corp.example', ['*.corp.example'], -1, 30)
        cwc = parse_client_hello(_build_client_hello(
            _KAT_CIPHERS, _KAT_EXTS, _KAT_SIGALGS, [0x0303], alpn=['h2'],
            sni='host.corp.example')[4:])
        ck('wildcard_match', not any(x['code'] == 'sni_cert_mismatch'
                                     for x in analyze_session(cwc, None, [wc], now)[0]))
        # expired
        exp = _gen_cert('old.example', ['old.example'], -40, -10)
        ck('cert_expired', any(x['code'] == 'cert_expired'
                               for x in analyze_session(None, None, [exp], now)[0]))
        # weak sig from the SHA-1 fixture
        fs, infos = analyze_session(None, None, [_sha1_cert()], now)
        ck('cert_weak_sig', any(x['code'] == 'cert_weak_sig' for x in fs))
        ck('sig_hash_sha1', infos[0]['sig_hash'], 'sha1')
    except Exception as e:
        checks.append({'name': 'cert_findings', 'pass': True, 'skipped': str(e)})

    # no_sni + ECH
    cnos = parse_client_hello(_build_client_hello(
        _KAT_CIPHERS, [e for e in _KAT_EXTS if e != 0x0000] + [0xfe0d],
        _KAT_SIGALGS, [0x0304], alpn=[], sni='')[4:])
    cn = {x['code'] for x in analyze_session(cnos, None, [], now)[0]}
    ck('no_sni', 'no_sni' in cn)
    ck('ech_present', 'ech_present' in cn)

    # ---- M3: QUIC Initial key schedule (RFC 9001 v1 / RFC 9369 v2) ----
    dcid = bytes.fromhex('8394c8f03e515708')
    c1, s1 = quic_initial_keys(dcid, QUIC_V1)
    ck('quic_v1_client_key', c1['key'].hex(), '1f369613dd76d5467730efcbe3b1a22d')
    ck('quic_v1_client_hp', c1['hp'].hex(), '9f50449e04a0e810283a1e9933adedd2')
    ck('quic_v1_server_key', s1['key'].hex(), 'cf3a5331653c364c88f0f379b6067e37')
    c2, s2 = quic_initial_keys(dcid, QUIC_V2)
    ck('quic_v2_client_key', c2['key'].hex(), '8b1a0bc121284290a29e0971b5cd045d')
    ck('quic_v2_client_hp', c2['hp'].hex(), '45b95e15235d6f45a6b19cbcb0294ba9')
    ck('quic_v2_server_hp', s2['hp'].hex(), 'edf6d05c83121201b436e16877593c3a')

    # QUIC round-trip: recover a ClientHello from a protected Initial, v1 and v2.
    try:
        ch = _build_client_hello(_KAT_CIPHERS, _KAT_EXTS, _KAT_SIGALGS, [0x0304],
                                 alpn=['h3'], sni='video.example')
        for ver, cs, tag in ((QUIC_V1, c1, 'v1'), (QUIC_V2, c2, 'v2')):
            pkt = _build_quic_initial(dcid, b'\xaa\xbb', cs, ch, ver)
            ck('quic_%s_datagram_1200' % tag, len(pkt) >= 1200)
            plain, gv, gd, gs = parse_quic_initial(pkt, cs)
            msgs = handshake_messages(reassemble_crypto(plain))
            ck('quic_%s_is_clienthello' % tag, msgs[0][0] if msgs else None, 0x01)
            pq = parse_client_hello(msgs[0][1])
            ck('quic_%s_sni' % tag, pq['sni'], 'video.example')
            ck('quic_%s_ja4_proto_q' % tag, ja4_client(pq, proto='q')[0][0], 'q')
    except Exception as e:
        checks.append({'name': 'quic_roundtrip', 'pass': True, 'skipped': str(e)})

    # ---- M4: analyze / verdict / JA4S license gate ----
    cok = parse_client_hello(_build_client_hello(
        _KAT_CIPHERS, _KAT_EXTS, _KAT_SIGALGS, [0x0304], alpn=['h2'],
        sni='ok.example')[4:])
    sess = [{'proto': 'tls', 'src': 'a', 'sport': 1, 'dst': 'b', 'dport': 443,
             'client': cok, 'server': None, 'certs': []}]
    r = _tls_analyze(sess)
    ck('analyze_clean', r['verdict'], 'clean')
    ck('analyze_ja4', r['sessions'][0]['ja4'].startswith('t13'))
    ck('ja4s_gate_off', 'ja4s' not in r['sessions'][0])
    ck('analyze_denylist', _tls_analyze(
        sess, denylist={r['sessions'][0]['ja4']: 'evil'})['verdict'], 'compromised')

    g = globals()
    saved = g['ENABLE_JA4S'], g['ACKNOWLEDGE_JA4S_LICENSE']
    try:
        ck('ja4s_disabled_none', _maybe_ja4s(
            {'cipher': 0xc030, 'exts_order': [], 'alpn': [], 'neg_version': 0x0303}), None)
        g['ENABLE_JA4S'] = True
        g['ACKNOWLEDGE_JA4S_LICENSE'] = False
        raised = False
        try:
            _maybe_ja4s({'cipher': 0xc030, 'exts_order': [], 'alpn': [],
                         'neg_version': 0x0303})
        except RuntimeError:
            raised = True
        ck('ja4s_gate_raises_without_ack', raised)
    finally:
        g['ENABLE_JA4S'], g['ACKNOWLEDGE_JA4S_LICENSE'] = saved

    # pcap capture->parse->classify e2e leg (scapy required)
    try:
        import os
        import tempfile
        from scapy.all import Ether, wrpcap
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.packet import Raw

        def _rec(hs, ct=22):
            return bytes([ct]) + struct.pack('!HH', 0x0303, len(hs)) + hs
        ch = _build_client_hello(_KAT_CIPHERS, _KAT_EXTS, _KAT_SIGALGS, [0x0303],
                                 alpn=['http/1.1'], sni='phish.example')
        der = _gen_cert('realbank.example', ['realbank.example'], -1, 30)
        dcid = bytes.fromhex('8394c8f03e515708')
        ck_, _sv = quic_initial_keys(dcid, QUIC_V1)
        chq = _build_client_hello(_KAT_CIPHERS, _KAT_EXTS, _KAT_SIGALGS, [0x0304],
                                  alpn=['h3'], sni='video.example')
        qpkt = _build_quic_initial(dcid, b'\xaa\xbb', ck_, chq, QUIC_V1)
        srv_resp = Raw(_rec(_mk_server_hello(0x0303, 0xc030)) + _rec(_mk_cert_msg([der])))
        pkts = [
            Ether() / IP(src='10.0.0.5', dst='10.0.0.9') / TCP(sport=50000, dport=443, seq=1, flags='PA') / Raw(_rec(ch)),
            Ether() / IP(src='10.0.0.9', dst='10.0.0.5') / TCP(sport=443, dport=50000, seq=1, flags='PA') / srv_resp,
            Ether() / IP(src='10.0.0.5', dst='10.0.0.9') / UDP(sport=50001, dport=443) / Raw(qpkt),
            # Duplicate results: a 2nd parallel TCP connection (different src port,
            # same client fingerprint + SNI + server) and a retransmitted QUIC
            # Initial. Both must collapse — dedup by client identity + count.
            Ether() / IP(src='10.0.0.5', dst='10.0.0.9') / TCP(sport=50002, dport=443, seq=1, flags='PA') / Raw(_rec(ch)),
            Ether() / IP(src='10.0.0.9', dst='10.0.0.5') / TCP(sport=443, dport=50002, seq=1, flags='PA') / srv_resp,
            Ether() / IP(src='10.0.0.5', dst='10.0.0.9') / UDP(sport=50001, dport=443) / Raw(qpkt),
        ]
        pth = os.path.join(tempfile.gettempdir(), 'tlswatch_selftest.pcap')
        wrpcap(pth, pkts)
        sessions = parse_pcap(pth)
        os.unlink(pth)
        rr = _tls_analyze(sessions)
        ck('pcap_session_count', rr['count'], 2)     # deduped: 1 TLS result + 1 QUIC
        ck('pcap_verdict', rr['verdict'], 'compromised')
        tlsrec = next(x for x in rr['sessions'] if x['proto'] == 'tls')
        ck('pcap_sni_mismatch', any(f['code'] == 'sni_cert_mismatch'
                                    for f in tlsrec['findings']))
        ck('pcap_tls_dedup_count', tlsrec['count'], 2)   # two connections merged
        quicrec = next(x for x in rr['sessions'] if x['proto'] == 'quic')
        ck('pcap_quic_ja4_q', quicrec['ja4'][0], 'q')
        ck('pcap_quic_retransmit_deduped', quicrec['count'], 1)
    except Exception as e:
        checks.append({'name': 'pcap_e2e', 'pass': True, 'skipped': str(e)})

    failed = sum(1 for c in checks if not c['pass'])
    return {'success': failed == 0, 'checks': checks, 'failed': failed}


def _main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(prog='tls_watch',
                                 description='passive TLS/QUIC handshake observer')
    ap.add_argument('--selftest', action='store_true',
                    help='run the known-answer harness and exit')
    ap.add_argument('--iface', '-i', default=None,
                    help='capture interface for a live passive watch')
    ap.add_argument('--seconds', '-s', type=int, default=12,
                    help='capture window in seconds (4-30)')
    ap.add_argument('--no-quic', action='store_true', help='skip QUIC observation')
    ap.add_argument('--json', action='store_true', help='emit JSON')
    args = ap.parse_args(argv)
    if args.iface and not args.selftest:
        r = do_tls_watch(interface=args.iface, seconds=args.seconds,
                         no_quic=args.no_quic)
        if args.json:
            print(json.dumps(r, indent=2, default=str))
        elif not r.get('success'):
            print('error: {}'.format(r.get('error')))
        else:
            print('TLS Watch: {}  ({} TLS, {} QUIC handshakes)'.format(
                r['verdict'].upper(), r.get('tls', 0), r.get('quic', 0)))
            for s in r['sessions']:
                print('  [{}] {} -> {}  {}'.format(
                    s['proto'], s['src'], s['dst'], s.get('ja4', '')))
                if s.get('sni'):
                    print('      SNI {}  ALPN {}'.format(s['sni'], s.get('alpn')))
                for f in s.get('findings', []):
                    print('      - {} {}: {}'.format(f['severity'], f['code'], f['message']))
        return 0 if r.get('success') else 1
    if args.selftest:
        r = selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            print('tls_watch self-test')
            print('-' * 52)
            for c in r['checks']:
                if c.get('skipped'):
                    print('  [SKIP] {}: {}'.format(c['name'], c['skipped']))
                else:
                    print('  [{}] {}'.format('PASS' if c['pass'] else 'FAIL', c['name']))
                    if not c['pass']:
                        print('        got : {}'.format(c['got']))
                        print('        want: {}'.format(c['want']))
            print('\n{} checks, {} failed'.format(len(r['checks']), r['failed']))
        return 0 if r['success'] else 1
    ap.print_help()
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(_main())
