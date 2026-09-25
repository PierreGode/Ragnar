#!/usr/bin/env python3
"""snmpwatch_selftest.py — offline self-test for snmpwatch (no Scapy, no NIC).

Builds SNMP v1/v2c/v3 messages with a pure-Python BER encoder and drives them
through the real decoder, severity engine, OID-hint pass, and watch engine.
Run via `python3 snmpwatch.py --selftest`.
"""

import sys

import snmpwatch as sw
from snmpwatch import enc, enc_int, enc_octet, enc_oid, enc_seq

# PDU tags
GET, GETNEXT, RESPONSE, SET, TRAP, GETBULK, INFORM, V2TRAP, REPORT = (
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8)


def _pdu(tag, oids=(), maxrep=0):
    vbs = enc_seq(*[enc_seq(enc_oid(o), enc(0x05, b'')) for o in oids])
    f3 = enc_int(maxrep) if tag == GETBULK else enc_int(0)
    return enc(tag, enc_int(1) + enc_int(0) + f3 + vbs)


def v2c(community, tag, oids=(), version=1, maxrep=0):
    return enc_seq(enc_int(version), enc_octet(community), _pdu(tag, oids, maxrep))


def v1(community, tag, oids=()):
    return v2c(community, tag, oids, version=0)


def v3(auth, priv, tag=GET, oids=(), plaintext=True, ctx='ctx'):
    flags = (1 if auth else 0) | (2 if priv else 0) | 4
    gd = enc_seq(enc_int(1000), enc_int(65507), enc_octet(bytes([flags])), enc_int(3))
    sec = enc_octet(b'')
    if plaintext:
        data = enc_seq(enc_octet(b'\x80\x00\x00\x09'), enc_octet(ctx), _pdu(tag, oids))
    else:
        data = enc(0x04, b'\xde\xad\xbe\xef' * 4)      # encryptedPDU OCTET STRING
    return enc_seq(enc_int(3), gd, sec, data)


class H:
    def __init__(self, verbose):
        self.n = self.fail = 0
        self.verbose = verbose

    def ck(self, name, cond):
        self.n += 1
        if not cond:
            self.fail += 1
        if self.verbose:
            print('  [{}] {}'.format('PASS' if cond else 'FAIL', name))


def run(verbose=True):
    h = H(verbose)

    # ---- BER primitives ---------------------------------------------------
    h.ck('ber_int positive', sw.ber_int(b'\x2a') == 42)
    h.ck('ber_int multi-byte', sw.ber_int(b'\x01\x00') == 256)
    h.ck('ber_int negative', sw.ber_int(b'\xff') == -1)
    h.ck('ber_oid basic', sw.ber_oid(b'\x2b\x06\x01') == '1.3.6.1')
    h.ck('ber_oid multibyte arc', sw.ber_oid(enc_oid('1.3.6.1.4.1.9.9.96')[2:]) == '1.3.6.1.4.1.9.9.96')
    tag, val, nxt = sw.read_tlv(enc_int(5), 0)
    h.ck('read_tlv int', tag == 0x02 and sw.ber_int(val) == 5 and nxt == 3)

    # ---- decode: versions / pdus / oids -----------------------------------
    m = sw.parse_snmp(v2c('public', GET, ['1.3.6.1.2.1.1.1.0']))
    h.ck('decode v2c version', m['version'] == 'v2c')
    h.ck('decode v2c community', m['community'] == 'public')
    h.ck('decode v2c pdu GET', m['pdu'] == 'GetRequest')
    h.ck('decode v2c oid', m['oids'] == ['1.3.6.1.2.1.1.1.0'])
    h.ck('decode v1 version', sw.parse_snmp(v1('c', GET))['version'] == 'v1')
    for tag, name in [(GETNEXT, 'GetNextRequest'), (SET, 'SetRequest'),
                      (RESPONSE, 'GetResponse'), (GETBULK, 'GetBulkRequest'),
                      (INFORM, 'InformRequest'), (V2TRAP, 'V2Trap'), (REPORT, 'Report')]:
        h.ck('decode pdu ' + name, sw.parse_snmp(v2c('c', tag))['pdu'] == name)
    m = sw.parse_snmp(v2c('c', GET, ['1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.5.0']))
    h.ck('decode multi-oid', len(m['oids']) == 2)
    m = sw.parse_snmp(v2c('c', GETBULK, ['1.3.6.1'], maxrep=200))
    h.ck('decode getbulk max_repetitions', m.get('max_repetitions') == 200)

    # malformed -> BerError
    try:
        sw.parse_snmp(b'\x30\x82\xff\xff\x02')
        h.ck('decode truncated raises', False)
    except sw.BerError:
        h.ck('decode truncated raises', True)

    # ---- v3 modes ---------------------------------------------------------
    h.ck('v3 noAuthNoPriv', sw.parse_snmp(v3(False, False))['v3_mode'] == 'noAuthNoPriv')
    h.ck('v3 authNoPriv', sw.parse_snmp(v3(True, False))['v3_mode'] == 'authNoPriv')
    h.ck('v3 authPriv', sw.parse_snmp(v3(True, True, plaintext=False))['v3_mode'] == 'authPriv')
    h.ck('v3 privNoAuth', sw.parse_snmp(v3(False, True, plaintext=False))['v3_mode'] == 'privNoAuth')
    m = sw.parse_snmp(v3(False, False, GET, ['1.3.6.1.2.1.1.5.0']))
    h.ck('v3 plaintext scopedPDU decodes oids', m['oids'] == ['1.3.6.1.2.1.1.5.0'])
    h.ck('v3 plaintext context_name', m['context_name'] == 'ctx')
    h.ck('v3 plaintext context_engine_id', m['context_engine_id'] == '80000009')
    m = sw.parse_snmp(v3(True, True, GET, ['1.3.6.1'], plaintext=False))
    h.ck('v3 encrypted -> no oids', m['oids'] == [] and m['v3_plaintext'] is False)
    m = sw.parse_snmp(v3(True, True, GET, ['1.3.6.1'], plaintext=True))
    h.ck('v3 claims priv but plaintext', m['claims_priv_plaintext'] is True)
    m = sw.parse_snmp(v3(False, False, GET, ['1.3.6.1'], plaintext=True))
    h.ck('v3 no false-positive claims-priv', m['claims_priv_plaintext'] is False)

    # ---- classify matrix --------------------------------------------------
    def sev(msg_bytes):
        return sw.classify(sw.parse_snmp(msg_bytes))[0]
    h.ck('cls v2c SET -> CRITICAL', sev(v2c('private', SET, ['1.3.6.1.2.1.1.5.0'])) == 'CRITICAL')
    h.ck('cls v2c GET public -> HIGH', sev(v2c('public', GET)) == 'HIGH')
    h.ck('cls v2c GET custom -> HIGH', sev(v2c('netops', GET)) == 'HIGH')
    h.ck('cls v1 GET -> HIGH', sev(v1('public', GET)) == 'HIGH')
    h.ck('cls v3 noAuthNoPriv SET -> CRITICAL', sev(v3(False, False, SET, ['1.3.6.1'])) == 'CRITICAL')
    h.ck('cls v3 authNoPriv SET -> LOW', sev(v3(True, False, SET, ['1.3.6.1'])) == 'LOW')
    h.ck('cls v3 noAuthNoPriv GET -> MEDIUM', sev(v3(False, False, GET)) == 'MEDIUM')
    h.ck('cls v3 privNoAuth -> MEDIUM', sev(v3(False, True, plaintext=False)) == 'MEDIUM')
    h.ck('cls v3 authNoPriv GET -> LOW', sev(v3(True, False, GET)) == 'LOW')
    h.ck('cls v3 authPriv -> INFO', sev(v3(True, True, plaintext=False)) == 'INFO')
    h.ck('cls v3 claims-priv-plaintext -> HIGH', sev(v3(True, True, GET, ['1.3.6.1'], plaintext=True)) == 'HIGH')

    # ---- OID hints --------------------------------------------------------
    def hints(oid):
        return [x['mib'] for x in sw.oid_hints([oid])]
    h.ck('hint config-copy', hints('1.3.6.1.4.1.9.9.96.1.1.1.1.14.5') == ['CISCO-CONFIG-COPY-MIB'])
    h.ck('hint writeNet', hints('1.3.6.1.4.1.9.2.1.55.1') == ['OLD-CISCO writeNet'])
    h.ck('hint writeMem', hints('1.3.6.1.4.1.9.2.1.54.0') == ['OLD-CISCO writeMem'])
    h.ck('hint usmUserTable', hints('1.3.6.1.6.3.15.1.2.2.1.2') == ['usmUserTable'])
    h.ck('hint vacm', hints('1.3.6.1.6.3.16.1.2.1.3') == ['vacm MIB'])
    h.ck('hint target', hints('1.3.6.1.6.3.12.1.2') == ['target MIB'])
    h.ck('hint notification', hints('1.3.6.1.6.3.13.1.1') == ['notification MIB'])
    h.ck('hint ifAdminStatus', hints('1.3.6.1.2.1.2.2.1.7.3') == ['ifAdminStatus'])
    h.ck('hint ipForwarding', hints('1.3.6.1.2.1.4.1.0') == ['ipForwarding'])
    h.ck('hint sysName', hints('1.3.6.1.2.1.1.5.0') == ['sysName'])
    h.ck('hint sysContact', hints('1.3.6.1.2.1.1.4.0') == ['sysContact'])
    h.ck('hint sysLocation', hints('1.3.6.1.2.1.1.6.0') == ['sysLocation'])
    h.ck('hint none for non-sensitive', hints('1.3.6.1.2.1.1.3.0') == [])
    h.ck('hint longest-prefix (writeNet under cisco)',
         sw.oid_hints(['1.3.6.1.4.1.9.2.1.55.1'])[0]['mib'] == 'OLD-CISCO writeNet')
    _s, reason, _hh = sw.classify(sw.parse_snmp(v2c('private', SET, ['1.3.6.1.4.1.9.9.96.1.1.1.1.14.5'])))
    h.ck('hint spliced into write reason', 'CISCO-CONFIG-COPY-MIB' in reason)

    # ---- watch engine + report --------------------------------------------
    w = sw.SnmpWatch()
    w.observe(sw.parse_snmp(v2c('public', GET)), '10.0.0.9', 40000, '10.0.0.1', 161, now=1.0)
    w.observe(sw.parse_snmp(v2c('public', GET)), '10.0.0.9', 40001, '10.0.0.1', 161, now=2.0)
    fk = list(w.findings.values())[0]
    h.ck('engine aggregates duplicates', fk['count'] == 2)
    h.ck('engine first_seen', fk['first_seen'] == 1.0)
    h.ck('engine last_seen advances', fk['last_seen'] == 2.0)
    w = sw.SnmpWatch()
    w.observe(sw.parse_snmp(v2c('public', GET)), '10.0.0.9', 40000, '10.0.0.1', 161)
    w.observe(sw.parse_snmp(v2c('public', SET)), '10.0.0.9', 40000, '10.0.0.1', 161)
    h.ck('engine distinct pdu not masked', len(w.findings) == 2)
    # agent role resolution
    w = sw.SnmpWatch()
    w.observe(sw.parse_snmp(v2c('c', V2TRAP)), '10.0.0.1', 40000, '10.0.0.99', 162)
    h.ck('engine agent = trap source', list(w.findings.values())[0]['agent'] == '10.0.0.1')
    w = sw.SnmpWatch()
    w.observe(sw.parse_snmp(v2c('c', RESPONSE)), '10.0.0.1', 161, '10.0.0.9', 40000)
    h.ck('engine agent = response source (sport 161)', list(w.findings.values())[0]['agent'] == '10.0.0.1')

    # community reuse
    w = sw.SnmpWatch()
    w.observe(sw.parse_snmp(v2c('netops', GET)), '10.0.0.9', 40000, '10.0.0.1', 161)
    w.observe(sw.parse_snmp(v2c('netops', GET)), '10.0.0.9', 40001, '10.0.0.2', 161)
    reuse = w.community_reuse()
    h.ck('reuse across 2 agents', reuse and reuse[0]['community'] == 'netops'
         and reuse[0]['agents'] == ['10.0.0.1', '10.0.0.2'])
    h.ck('reuse severity HIGH', reuse[0]['severity'] == 'HIGH')
    w.observe(sw.parse_snmp(v2c('netops', SET)), '10.0.0.9', 40002, '10.0.0.1', 161)
    h.ck('reuse+write severity CRITICAL', w.community_reuse()[0]['severity'] == 'CRITICAL')
    w = sw.SnmpWatch()
    w.observe(sw.parse_snmp(v2c('solo', GET)), '10.0.0.9', 40000, '10.0.0.1', 161)
    h.ck('no reuse for single agent', w.community_reuse() == [])

    # report shape
    w = sw.SnmpWatch()
    w.observe(sw.parse_snmp(v2c('private', SET, ['1.3.6.1.4.1.9.9.96.1'])), '10.0.0.9', 40000, '10.0.0.1', 161)
    w.observe(sw.parse_snmp(v3(True, True, plaintext=False)), '10.0.0.9', 40001, '10.0.0.2', 161)
    rep = w.report()
    for key in ('module', 'generated', 'stats', 'severity_counts',
                'insecure_versions_present', 'community_reuse', 'findings'):
        h.ck('report has ' + key, key in rep)
    h.ck('report module', rep['module'] == 'snmpwatch')
    h.ck('report severity_counts CRITICAL', rep['severity_counts'].get('CRITICAL') == 1)
    h.ck('report finding carries oids', rep['findings'][0]['oids'] == ['1.3.6.1.4.1.9.9.96.1'])
    h.ck('report finding carries oid_hints', rep['findings'][0]['oid_hints'][0]['mib'] == 'CISCO-CONFIG-COPY-MIB')
    h.ck('report sorted severity desc', rep['findings'][0]['severity'] == 'CRITICAL')
    h.ck('insecure_versions_present (v2c)', rep['insecure_versions_present'] is True)
    w = sw.SnmpWatch()
    w.observe(sw.parse_snmp(v3(True, True, plaintext=False)), '10.0.0.9', 40000, '10.0.0.1', 161)
    h.ck('insecure False when only authPriv', w.report()['insecure_versions_present'] is False)
    w = sw.SnmpWatch()
    w.observe(sw.parse_snmp(v3(False, False, GET)), '10.0.0.9', 40000, '10.0.0.1', 161)
    h.ck('insecure True for v3 noAuthNoPriv', w.report()['insecure_versions_present'] is True)

    total = h.n
    passed = total - h.fail
    print('snmpwatch self-test: {}/{} {}'.format(
        passed, total, 'OK' if h.fail == 0 else 'FAILED'))
    return 0 if h.fail == 0 else 1


if __name__ == '__main__':
    sys.exit(run(verbose=True))
