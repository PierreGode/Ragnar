#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Self-test harness for ldap_watch.

Fabricates BER LDAP messages and runs them through THIS module's production
split_ldap_messages -> parse_ldap_message -> LdapDetector path (the same code the
live sniffer uses). No sockets, no root, no third-party deps — the BER parser and
findings engine are pure Python. Runnable under pytest OR standalone:

    python3 test_ldapwatch.py
"""
import ipaddress

import ldap_watch as L


def _detect(messages, flowkey=('10.0.0.9', 55000, '10.0.0.1', 389), cldap=None,
            local_nets=None):
    """Feed fabricated LDAP messages through the real parse + detect path."""
    det = L.LdapDetector()
    det.local_nets = local_nets
    for raw in messages:
        parsed, _ = L.split_ldap_messages(raw)
        for m in parsed:
            det.feed_message(flowkey, m)
    for c in (cldap or []):
        det.feed_cldap(*c)
    return det.result()


def _codes(res):
    return {f['code'] for f in res['findings']}


# --------------------------------------------------------------------------
# BER / ASN.1 decoder
# --------------------------------------------------------------------------
def test_ber_definite_length_roundtrip():
    raw = L._bind_req(3, 'cn=admin,dc=corp,dc=local', simple='S3cret!')
    msgs, consumed = L.split_ldap_messages(raw)
    assert consumed == len(raw)
    assert len(msgs) == 1
    m = msgs[0]
    assert m['op'] == 'bind-req'
    assert m['name'] == 'cn=admin,dc=corp,dc=local'
    assert m['version'] == 3
    assert m['password_len'] == len('S3cret!')


def test_ber_long_form_length():
    # A DN long enough to force a 2-byte long-form length still decodes.
    dn = 'cn=' + 'a' * 400 + ',dc=corp'
    msgs, _ = L.split_ldap_messages(L._bind_req(3, dn, simple='x'))
    assert msgs and msgs[0]['name'] == dn


def test_multiple_messages_in_one_stream():
    stream = L._bind_req(3, 'cn=a,dc=c', simple='') + L._ext_req(L.OID_WHOAMI)
    msgs, consumed = L.split_ldap_messages(stream)
    assert len(msgs) == 2
    assert consumed == len(stream)
    assert msgs[1]['op'] == 'ext-req' and msgs[1]['ext_name'] == 'whoami'


def test_partial_trailing_message_is_not_consumed():
    whole = L._bind_req(3, 'cn=a,dc=c', simple='pw')
    stream = whole + whole[:5]              # a complete msg + a truncated one
    msgs, consumed = L.split_ldap_messages(stream)
    assert len(msgs) == 1
    assert consumed == len(whole)           # the partial tail waits for more bytes


def test_malformed_ber_does_not_raise():
    # Bogus 4-byte long-form length claiming 4 GiB must be handled, not crash.
    msgs, consumed = L.split_ldap_messages(b'\x30\x84\xff\xff\xff\xff\x02')
    assert msgs == [] and consumed == 0


# --------------------------------------------------------------------------
# Authentication findings
# --------------------------------------------------------------------------
def test_cleartext_credentials_is_compromised():
    r = _detect([L._bind_req(3, 'cn=admin,dc=corp,dc=local', simple='S3cret!')])
    assert 'cleartext-bind-credentials' in _codes(r)
    assert r['verdict'] == 'compromised'


def test_anonymous_bind():
    r = _detect([L._bind_req(3, '', simple='')])
    assert 'anonymous-bind' in _codes(r)
    assert r['verdict'] == 'suspicious'


def test_unauthenticated_bind():
    r = _detect([L._bind_req(3, 'cn=svc,dc=corp,dc=local', simple='')])
    assert 'unauthenticated-bind' in _codes(r)


def test_sasl_plain_over_cleartext():
    r = _detect([L._bind_req(3, '', sasl_mech='PLAIN')])
    assert 'sasl-plaintext-cleartext' in _codes(r)


# --------------------------------------------------------------------------
# Search: enumeration / sensitive attrs / injection
# --------------------------------------------------------------------------
def test_directory_enumeration_whole_subtree():
    r = _detect([L._search_req('dc=corp,dc=local', 2,
                               L._f_present('objectClass'), ['cn'])])
    assert 'directory-enumeration' in _codes(r)


def test_sensitive_attribute_read():
    r = _detect([L._search_req('dc=corp,dc=local', 2,
                               L._f_equal('objectClass', 'user'),
                               ['samaccountname', 'serviceprincipalname'])])
    assert 'sensitive-attribute' in _codes(r)


def test_filter_injection():
    r = _detect([L._search_req('dc=corp,dc=local', 1,
                               L._f_equal('uid', '*)(uid=*'), ['cn'])])
    assert 'filter-injection' in _codes(r)


def test_clean_search_no_finding():
    r = _detect([L._search_req('ou=people,dc=corp,dc=local', 1,
                               L._f_equal('uid', 'alice'), ['cn', 'mail'])])
    assert r['findings'] == []
    assert r['verdict'] == 'clean'


# --------------------------------------------------------------------------
# StartTLS / brute force / CLDAP
# --------------------------------------------------------------------------
def test_starttls_stripped_on_refusal():
    r = _detect([L._ext_req(L.OID_STARTTLS), L._ext_resp(2)])   # 2 = protocolError
    assert 'starttls-stripped' in _codes(r)


def test_brute_force_bind_attempts():
    r = _detect([L._bind_req(3, 'cn=u,dc=c', simple='x')
                 for _ in range(L.BRUTE_BIND_ATTEMPTS)])
    assert 'brute-force' in _codes(r)


def test_brute_force_invalid_credentials():
    fk = ('10.0.0.1', 389, '10.0.0.9', 55000)          # server -> client direction
    det = L.LdapDetector()
    for _ in range(L.BRUTE_BIND_FAILURES):
        msgs, _ = L.split_ldap_messages(L._bind_resp(L.RC_INVALID_CREDENTIALS))
        for msg in msgs:
            det.feed_message(fk, msg)
    assert 'brute-force' in {f['code'] for f in det.result()['findings']}


def test_external_referral_ldapnightmare():
    nets = [ipaddress.ip_network('10.0.0.0/24')]
    # SearchResultReference to an external IP == LDAPNightmare steering vector.
    r = _detect([L._search_ref(['ldap://203.0.113.66:389/dc=evil,dc=com'])],
                local_nets=nets)
    assert 'external-referral' in _codes(r)
    assert r['verdict'] == 'compromised'
    # A [3] referral in a bind response is caught the same way.
    r = _detect([L._bind_resp(L.RC_SUCCESS, referrals=['ldap://198.51.100.5/'])],
                local_nets=nets)
    assert 'external-referral' in _codes(r)


def test_in_forest_referral_is_clean():
    nets = [ipaddress.ip_network('10.0.0.0/24')]
    # A referral to our own subnet (or a hostname we can't place) must NOT fire.
    r = _detect([L._search_ref(['ldap://10.0.0.7/dc=corp',
                                'ldap://dc2.corp.local/dc=corp'])], local_nets=nets)
    assert 'external-referral' not in _codes(r)


def test_cldap_reflection_off_subnet():
    nets = [ipaddress.ip_network('10.0.0.0/24')]
    cl = [('203.0.113.7', 40000, '10.0.0.1', 389,
           L._search_req('', 0, L._f_present('objectClass'), []), False, nets)]
    r = _detect([], cldap=cl)
    assert 'cldap-reflection' in _codes(r)


def test_cldap_amplification_ratio():
    det = L.LdapDetector()
    small = L._search_req('', 0, L._f_present('objectClass'), [])
    big = b'\x00' * (len(small) * 8)
    det.feed_cldap('203.0.113.7', 40000, '10.0.0.1', 389, small, False, None)
    det.feed_cldap('10.0.0.1', 389, '203.0.113.7', 40000, big, True, None)
    assert 'cldap-amplification' in {f['code'] for f in det.result()['findings']}


# --------------------------------------------------------------------------
# Passive guarantee + built-in harness
# --------------------------------------------------------------------------
def test_no_transmit_primitives_in_source():
    assert L._scan_for_transmit_primitives() == []


def test_builtin_selftest_passes():
    r = L.selftest()
    assert r['success'], [c for c in r['checks'] if not c['pass']]


if __name__ == '__main__':
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    passed = 0
    for fn in fns:
        try:
            fn()
            print('  [PASS] %s' % fn.__name__)
            passed += 1
        except Exception:
            print('  [FAIL] %s' % fn.__name__)
            traceback.print_exc()
    print('\n%d/%d tests passed' % (passed, len(fns)))
    raise SystemExit(0 if passed == len(fns) else 1)
