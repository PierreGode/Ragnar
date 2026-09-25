# SPDX-License-Identifier: LicenseRef-FoxIO-License-1.1
#
# JA4S (TLS server fingerprint) for the Ragnar suite.
# ---------------------------------------------------------------------------
# JA4S is part of the JA4+ family and is licensed by FoxIO under the FoxIO
# License 1.1 — NOT the BSD-3-Clause that covers JA4 (the client fingerprint).
# See https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4S.md for the terms.
#
# It is kept in this separate, clearly identified file so the rest of Ragnar
# (MIT) and the JA4 client fingerprint (BSD-3-Clause) stay unencumbered, exactly
# as FoxIO's FAQ permits: JA4+ code may coexist with differently licensed
# surrounding code provided the JA4+ component remains clearly identified under
# its own license.
#
# This module is imported ONLY when the operator has both enabled JA4S and
# acknowledged this license (see tls_watch.ENABLE_JA4S / ACKNOWLEDGE_JA4S_LICENSE).
# By default Ragnar ships with JA4S disabled and never imports this file.
"""JA4S server fingerprint. Format: a_b_c where
  a = [proto][2-char version][2-digit ServerHello ext count][ALPN],
  b = the chosen cipher as 4-hex (not hashed),
  c = SHA-256 (first 12 hex) of the ServerHello extension type codes in WIRE
      order (GREASE removed). In-order hashing is intentional and differs from
      JA4_c — servers do not randomize extension order, so order is signal.
"""
import hashlib

_ALNUM = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
_VER = {0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3',
        0xfeff: 'd1', 0xfefd: 'd2', 0xfefc: 'd3'}


def _is_grease(v):
    return (v & 0x0f0f) == 0x0a0a and ((v >> 8) & 0xff) == (v & 0xff)


def _alpn(alpn):
    if not alpn or not alpn[0]:
        return '00'
    s = alpn[0]
    if s[0] in _ALNUM and s[-1] in _ALNUM:
        return s[0] + s[-1]
    return '{:02x}'.format(ord(s[0]) & 0xff)[0] + '{:02x}'.format(ord(s[-1]) & 0xff)[1]


def ja4s(server, proto='t'):
    """Compute JA4S from a parsed ServerHello (tls_watch.parse_server_hello dict:
    server_version, cipher, exts_order, alpn, neg_version)."""
    exts = [e for e in server.get('exts_order', []) if not _is_grease(e)]
    ver = _VER.get(server.get('neg_version') or server.get('server_version'), '00')
    a = '{}{}{:02d}{}'.format(proto, ver, min(len(exts), 99), _alpn(server.get('alpn')))
    b = '{:04x}'.format(server['cipher'])
    ext_hex = ','.join('{:04x}'.format(e) for e in exts)          # WIRE order
    c = hashlib.sha256(ext_hex.encode()).hexdigest()[:12] if exts else '000000000000'
    return '{}_{}_{}'.format(a, b, c)


def selftest():
    """Pinned to the FoxIO published example t120000_c030_000000000000 (a TLS 1.2
    ServerHello, cipher 0xc030, no extensions, no ALPN)."""
    checks = []

    def ck(name, got, want):
        checks.append({'name': name, 'pass': got == want, 'got': got, 'want': want})

    sh_none = {'server_version': 0x0303, 'neg_version': 0x0303, 'cipher': 0xc030,
               'exts_order': [], 'alpn': []}
    ck('ja4s_no_ext', ja4s(sh_none), 't120000_c030_000000000000')

    # with extensions: a-segment count/version + cipher, and the wire-order hash
    sh_ext = {'server_version': 0x0303, 'neg_version': 0x0304, 'cipher': 0x1301,
              'exts_order': [0x002b, 0x0033], 'alpn': ['h2']}
    got = ja4s(sh_ext)
    ck('ja4s_ext_a', got.split('_')[0], 't1302h2')
    ck('ja4s_ext_b', got.split('_')[1], '1301')
    ck('ja4s_ext_c', got.split('_')[2],
       hashlib.sha256(b'002b,0033').hexdigest()[:12])

    failed = sum(1 for c in checks if not c['pass'])
    return {'success': failed == 0, 'checks': checks, 'failed': failed}


if __name__ == '__main__':
    r = selftest()
    for c in r['checks']:
        print('  [{}] {}'.format('PASS' if c['pass'] else 'FAIL', c['name']))
        if not c['pass']:
            print('        got : {}\n        want: {}'.format(c['got'], c['want']))
    print('\n{} checks, {} failed'.format(len(r['checks']), r['failed']))
