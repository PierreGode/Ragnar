#!/usr/bin/env python3
"""certwatch_selftest.py — offline self-test for certwatch (no wire, no iface).

Mints certificates in-memory, synthesizes TLS byte streams (reusing
tls_watch.py's builders), and drives them through certwatch's triage engine and
flow reassembler. Two checks push real scapy IPv4/IPv6 packets through the live
capture handler. Run via `python3 certwatch.py --selftest`.
"""

import os
import struct
import sys
import time
from datetime import datetime, timezone

# tls_watch is a core module in the repo root (this file is under python/).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import certwatch as cw
import tls_watch as _tw


def _gen_cert_bits(cn, sans, days_from, days_to, bits=2048):
    """Self-signed cert with a chosen RSA key size (for the WEAK_KEY KAT)."""
    import datetime as _dt
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = _dt.datetime.now(_dt.timezone.utc)
    b = x509.CertificateBuilder().subject_name(subj).issuer_name(subj)\
        .public_key(key.public_key()).serial_number(x509.random_serial_number())\
        .not_valid_before(now + _dt.timedelta(days=days_from))\
        .not_valid_after(now + _dt.timedelta(days=days_to))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
                            critical=False)
    return b.sign(key, hashes.SHA256()).public_bytes(Encoding.DER)


def _rec(payload, ctype=22, ver=0x0303):
    """Wrap bytes in one TLS record."""
    return bytes([ctype]) + struct.pack('!H', ver) + struct.pack('!H', len(payload)) + payload


def _client_stream(sni):
    ch = _tw._build_client_hello(ciphers=[0x1301], ext_types=[0x0000, 0x002b],
                                 sig_algs=[], sup_versions=[0x0304], alpn=[], sni=sni)
    return _rec(ch)


def _server_stream_12(ders):
    sh = _tw._mk_server_hello(0x0303, 0xc02f)
    cert = _tw._mk_cert_msg(ders)
    return _rec(sh) + _rec(cert)


def _server_stream_13():
    sh = _tw._mk_server_hello(0x0303, 0x1301, neg_version=0x0304)
    return _rec(sh)


class Harness:
    def __init__(self):
        self.n = 0
        self.fail = 0

    def ck(self, name, cond):
        self.n += 1
        ok = bool(cond)
        if not ok:
            self.fail += 1
        self._log('PASS' if ok else 'FAIL', name)

    def _log(self, verdict, name):
        if self.verbose:
            print('  [{}] {}'.format(verdict, name))

    verbose = True


def _codes(rec):
    return {f['code'] for f in rec.get('findings', [])}


def run(verbose=True):
    h = Harness()
    h.verbose = verbose
    now = datetime.now(timezone.utc)

    # ---- triage_cert finding KATs -----------------------------------------
    expired = _gen_cert_bits('exp.example', ['exp.example'], -100, -10)
    st, f, info = cw.triage_cert(expired, 'exp.example', now)
    h.ck('EXPIRED code', 'EXPIRED' in _codes({'findings': f}))
    h.ck('EXPIRED status CRIT', st == 'CRIT')
    h.ck('EXPIRED days_left negative', info['days_left'] < 0)

    nyv = _gen_cert_bits('nyv.example', ['nyv.example'], 10, 100)
    st, f, _ = cw.triage_cert(nyv, 'nyv.example', now)
    h.ck('NOT_YET_VALID code', 'NOT_YET_VALID' in {x['code'] for x in f})
    h.ck('NOT_YET_VALID status CRIT', st == 'CRIT')

    soon = _gen_cert_bits('soon.example', ['soon.example'], -10, 15)
    st, f, info = cw.triage_cert(soon, 'soon.example', now, warn_days=30)
    h.ck('EXPIRING_SOON code', 'EXPIRING_SOON' in {x['code'] for x in f})
    h.ck('EXPIRING_SOON not fired past window',
         'EXPIRING_SOON' not in {x['code'] for x in
                                 cw.triage_cert(soon, 'soon.example', now, warn_days=5)[1]})
    h.ck('EXPIRING_SOON days_left in window', 0 <= info['days_left'] <= 30)

    match = _gen_cert_bits('m.example', ['m.example'], -10, 200)
    st, f, _ = cw.triage_cert(match, 'm.example', now)
    h.ck('name match -> no NAME_MISMATCH', 'NAME_MISMATCH' not in {x['code'] for x in f})

    mis = _gen_cert_bits('a.example', ['a.example'], -10, 200)
    st, f, _ = cw.triage_cert(mis, 'b.example', now)
    h.ck('NAME_MISMATCH code', 'NAME_MISMATCH' in {x['code'] for x in f})
    h.ck('NAME_MISMATCH status CRIT', st == 'CRIT')
    st, f, _ = cw.triage_cert(mis, None, now)
    h.ck('no SNI -> no NAME_MISMATCH', 'NAME_MISMATCH' not in {x['code'] for x in f})

    wild = _gen_cert_bits('wild', ['*.example.com'], -10, 200)
    st, f, _ = cw.triage_cert(wild, 'host.example.com', now)
    codes = {x['code'] for x in f}
    h.ck('WILDCARD code', 'WILDCARD' in codes)
    h.ck('wildcard covers host (no mismatch)', 'NAME_MISMATCH' not in codes)

    nosan = _gen_cert_bits('cn.only.example', [], -10, 200)
    st, f, _ = cw.triage_cert(nosan, None, now)
    h.ck('MISSING_SAN code', 'MISSING_SAN' in {x['code'] for x in f})

    longv = _gen_cert_bits('long.example', ['long.example'], -10, 500)
    st, f, info = cw.triage_cert(longv, 'long.example', now)
    h.ck('LONG_VALIDITY code', 'LONG_VALIDITY' in {x['code'] for x in f})
    h.ck('validity_days > 398', info['validity_days'] > 398)

    selfsigned = _gen_cert_bits('ss.example', ['ss.example'], -10, 200)
    st, f, info = cw.triage_cert(selfsigned, 'ss.example', now)
    h.ck('SELF_SIGNED code', 'SELF_SIGNED' in {x['code'] for x in f})
    h.ck('self_signed info flag', info['self_signed'] is True)

    weakkey = _gen_cert_bits('weakkey.example', ['weakkey.example'], -10, 200, bits=1024)
    st, f, info = cw.triage_cert(weakkey, 'weakkey.example', now)
    h.ck('WEAK_KEY code', 'WEAK_KEY' in {x['code'] for x in f})
    h.ck('key_bits reported', info['key_bits'] == 1024)

    sha1 = _tw._sha1_cert()
    st, f, info = cw.triage_cert(sha1, None, now)
    codes = {x['code'] for x in f}
    h.ck('WEAK_SIG_SHA1 code', 'WEAK_SIG_SHA1' in codes)
    h.ck('WEAK_SIG_SHA1 status CRIT', st == 'CRIT')
    h.ck('CA_CERT code (CA:TRUE leaf)', 'CA_CERT' in codes)
    h.ck('sig_alg reported sha1', (info['sig_alg'] or '').lower() == 'sha1')

    # ---- flow reassembler --------------------------------------------------
    def feed(client_stream, server_stream, cip='10.0.0.9', sip='10.0.0.1',
             split_server=None, reverse=False, warn_days=30):
        t = cw.FlowTracker(warn_days=warn_days)
        base = time.time()
        t.add_segment(cip, 50000, sip, 443, 1000, client_stream, base)
        rec = None
        if split_server is None:
            rec = t.add_segment(sip, 443, cip, 50000, 2000, server_stream, base)
        else:
            a, b = server_stream[:split_server], server_stream[split_server:]
            segs = [(2000, a), (2000 + len(a), b)]
            if reverse:
                segs = list(reversed(segs))
            for seq, chunk in segs:
                r = t.add_segment(sip, 443, cip, 50000, seq, chunk, base)
                rec = r or rec
        return t, rec

    good = _gen_cert_bits('good.example', ['good.example'], -10, 200)
    _, rec = feed(_client_stream('good.example'), _server_stream_12([good]))
    h.ck('reassembly: cert record produced', rec is not None)
    h.ck('reassembly: type cert', rec and rec['type'] == 'cert')
    h.ck('reassembly: SNI extracted', rec and rec['sni'] == 'good.example')
    h.ck('reassembly: version 1.2', rec and rec['version'] == 'TLS 1.2')
    h.ck('reassembly: server_ip is server side', rec and rec['server_ip'] == '10.0.0.1')
    h.ck('reassembly: server_port 443', rec and rec['server_port'] == 443)
    h.ck('reassembly: name matches (no NAME_MISMATCH)',
         rec and 'NAME_MISMATCH' not in _codes(rec))
    # Triage must actually RUN through the flow path (not silently PARSE_ERROR
    # on the float/datetime boundary) — feed a broken cert and assert the code.
    h.ck('reassembly: triage ran (no PARSE_ERROR)', rec and 'PARSE_ERROR' not in _codes(rec))
    h.ck('reassembly: days_left present', rec and rec.get('days_left') is not None)
    expired_leaf = _gen_cert_bits('exp.example', ['exp.example'], -100, -10)
    _, erec = feed(_client_stream('exp.example'), _server_stream_12([expired_leaf]))
    h.ck('reassembly: EXPIRED fires via flow path', erec and 'EXPIRED' in _codes(erec))
    h.ck('reassembly: EXPIRED status CRIT via flow path', erec and erec['status'] == 'CRIT')

    # chained certs
    inter = _gen_cert_bits('intermediate', [], -10, 3000)
    _, rec = feed(_client_stream('good.example'), _server_stream_12([good, inter]))
    h.ck('reassembly: chain_len 2', rec and rec['chain_len'] == 2)

    # TLS 1.3 inventory
    _, rec = feed(_client_stream('h3.example'), _server_stream_13())
    h.ck('1.3: inventory record', rec and rec['type'] == 'inventory')
    h.ck('1.3: CERT_NOT_OBSERVABLE', rec and 'CERT_NOT_OBSERVABLE' in _codes(rec))
    h.ck('1.3: version 1.3', rec and rec['version'] == 'TLS 1.3')
    h.ck('1.3: SNI still extracted', rec and rec['sni'] == 'h3.example')

    # cert spanning multiple TCP segments (split mid-stream)
    ss = _server_stream_12([good])
    _, rec = feed(_client_stream('good.example'), ss, split_server=len(ss) // 2)
    h.ck('multi-segment cert reassembled', rec is not None and rec['type'] == 'cert')

    # out-of-order server segments
    _, rec = feed(_client_stream('good.example'), ss, split_server=len(ss) // 2,
                  reverse=True)
    h.ck('out-of-order segments reassembled', rec is not None and rec['type'] == 'cert')

    # handshake fragmented across two TLS records
    sh = _tw._mk_server_hello(0x0303, 0xc02f)
    cert = _tw._mk_cert_msg([good])
    hs = sh + cert
    fragmented = _rec(hs[:len(sh) + 5]) + _rec(hs[len(sh) + 5:])
    _, rec = feed(_client_stream('good.example'), fragmented)
    h.ck('handshake fragmented across records', rec is not None and rec['type'] == 'cert')

    # coalesced SH+Cert in ONE record
    coalesced = _rec(sh + cert)
    _, rec = feed(_client_stream('good.example'), coalesced)
    h.ck('coalesced SH+Cert in one record', rec is not None and rec['type'] == 'cert')

    # non-TLS garbage: no record, no crash
    t = cw.FlowTracker()
    try:
        r = t.add_segment('1.2.3.4', 5, '5.6.7.8', 443, 1, b'\x99\x99not tls\x00\x01', time.time())
        h.ck('garbage input safe', r is None)
    except Exception:
        h.ck('garbage input safe', False)

    # malformed cert-message length: no crash
    badcert = _rec(sh) + _rec(b'\x0b\x00\xff\xff\x00\x00\x10deadbeef')
    try:
        _, rec = feed(_client_stream('x'), badcert)
        h.ck('malformed cert length safe', True)
    except Exception:
        h.ck('malformed cert length safe', False)

    # per-flow byte cap
    t = cw.FlowTracker()
    big = b'\x16\x03\x03' + b'\x00' * (cw.MAX_FLOW_BYTES + 100)
    t.add_segment('9.9.9.9', 1, '8.8.8.8', 443, 1, big, time.time())
    h.ck('per-flow byte cap evicts', t.stats['evicted_cap'] >= 1)

    # MAX_FLOWS LRU eviction
    t = cw.FlowTracker()
    for i in range(cw.MAX_FLOWS + 50):
        t.add_segment('10.1.{}.{}'.format(i // 256, i % 256), 1000, '8.8.8.8', 443,
                      1, b'\x16\x03\x03\x00\x01\x00', time.time())
    h.ck('MAX_FLOWS bounded', len(t.flows) <= cw.MAX_FLOWS)
    h.ck('LRU evictions counted', t.stats['evicted_lru'] >= 50)

    # TTL sweep
    t = cw.FlowTracker()
    base = time.time()
    t.add_segment('7.7.7.7', 1, '8.8.8.8', 443, 1, b'\x16\x03\x03\x00\x01\x00', base)
    t.sweep(base + cw.FLOW_TTL + 5)
    h.ck('TTL sweep evicts idle flow', t.stats['evicted_ttl'] >= 1 and len(t.flows) == 0)

    # ---- batch helpers -----------------------------------------------------
    h.ck('rotation suffix .pcap0 is a capture', cw._is_capture('capture.pcap0'))
    h.ck('.pcapng is a capture', cw._is_capture('x.pcapng'))
    h.ck('.pcap.gz is a capture', cw._is_capture('x.pcap.gz'))
    h.ck('.txt is not a capture', not cw._is_capture('notes.txt'))
    order = sorted(['c.pcap10', 'c.pcap2', 'c.pcap1'], key=cw._natural_key)
    h.ck('natural sort pcap2 before pcap10', order == ['c.pcap1', 'c.pcap2', 'c.pcap10'])

    # ---- real scapy packets through the live handler -----------------------
    try:
        from scapy.layers.inet import IP, TCP
        recs = []
        handler = cw.make_handler(cw.FlowTracker(), cw.DEFAULT_PORTS, recs.append)
        cs = _client_stream('scapy.example')
        gcert = _gen_cert_bits('scapy.example', ['scapy.example'], -10, 200)
        srv = _server_stream_12([gcert])
        handler(IP(src='10.0.0.9', dst='10.0.0.1') / TCP(sport=50001, dport=443, seq=1) / cs)
        handler(IP(src='10.0.0.1', dst='10.0.0.9') / TCP(sport=443, dport=50001, seq=1) / srv)
        h.ck('scapy IPv4 handler produces record', len(recs) == 1 and recs[0]['type'] == 'cert')
    except Exception as e:
        h.ck('scapy IPv4 handler produces record', False)
        if verbose:
            print('    (scapy IPv4 error: {})'.format(e))

    try:
        from scapy.layers.inet import TCP
        from scapy.layers.inet6 import IPv6
        recs = []
        handler = cw.make_handler(cw.FlowTracker(), cw.DEFAULT_PORTS, recs.append)
        cs = _client_stream('v6.example')
        gcert = _gen_cert_bits('v6.example', ['v6.example'], -10, 200)
        srv = _server_stream_12([gcert])
        handler(IPv6(src='2001:db8::9', dst='2001:db8::1') / TCP(sport=50002, dport=443, seq=1) / cs)
        handler(IPv6(src='2001:db8::1', dst='2001:db8::9') / TCP(sport=443, dport=50002, seq=1) / srv)
        h.ck('scapy IPv6 handler produces record', len(recs) == 1 and recs[0]['type'] == 'cert')
    except Exception as e:
        h.ck('scapy IPv6 handler produces record', False)
        if verbose:
            print('    (scapy IPv6 error: {})'.format(e))

    total = h.n
    passed = total - h.fail
    print('certwatch self-test: {}/{} {}'.format(passed, total,
                                                 'OK' if h.fail == 0 else 'FAILED'))
    return 0 if h.fail == 0 else 1


if __name__ == '__main__':
    sys.exit(run(verbose=True))
