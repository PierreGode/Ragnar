#!/usr/bin/env python3
"""isiswatch_selftest.py — offline self-test for isiswatch (no Scapy, no NIC).

Builds raw IS-IS frames in pure Python and drives them through the parser and
the detector engine. Run via `python3 isiswatch.py --self-test`.
"""

import struct
import sys

import isiswatch as iw


# --------------------------------------------------------------------------
# Pure-Python frame builders
# --------------------------------------------------------------------------
def _sid_bytes(s):
    return bytes.fromhex(s.replace('.', ''))


def _mac(s):
    return bytes(int(x, 16) for x in s.split(':'))


def frame(payload, src='de:ad:be:ef:00:01', dst='01:80:c2:00:00:15', tagged=False):
    llc = b'\xfe\xfe\x03' + payload
    length = struct.pack('!H', len(llc) & 0xffff)
    tag = b'\x81\x00\x00\x64' if tagged else b''      # VLAN 100
    return _mac(dst) + _mac(src) + tag + length + llc


def common(pdu_type, id_len=0, max_area=3):
    return bytes([0x83, 27, 1, id_len, pdu_type, 1, 0, max_area])


def tlv(t, v):
    return bytes([t, len(v)]) + v


def area_tlv(areas):
    v = b''
    for a in areas:
        ab = bytes.fromhex(a)
        v += bytes([len(ab)]) + ab
    return tlv(iw.TLV_AREA, v)


def auth_tlv(atype, extra=b''):
    return tlv(iw.TLV_AUTH, bytes([atype]) + extra)


def hostname_tlv(name):
    return tlv(iw.TLV_HOSTNAME, name.encode())


def padding_tlv(n=10):
    return tlv(iw.TLV_PADDING, b'\x00' * n)


def threeway_tlv():
    return tlv(iw.TLV_THREE_WAY, b'\x00')


def narrow_tlv():
    return tlv(iw.TLV_IP_INT_REACH, b'\x00' * 12)


def lan_iih(sysid, level=2, tlvs=b'', priority=64):
    ptype = iw.PDU_L1_LAN_IIH if level == 1 else iw.PDU_L2_LAN_IIH
    sid = _sid_bytes(sysid)
    body = bytes([3]) + sid + struct.pack('!H', 30) + struct.pack('!H', 0)
    body += bytes([priority & 0x7f]) + sid + b'\x01'      # priority + LAN id (7)
    return common(ptype) + body + tlvs


def p2p_iih(sysid, tlvs=b''):
    sid = _sid_bytes(sysid)
    body = bytes([3]) + sid + struct.pack('!H', 30) + struct.pack('!H', 0) + bytes([1])
    return common(iw.PDU_P2P_IIH) + body + tlvs


def lsp(sysid, level=2, lifetime=1199, seq=0x10, overload=False, tlvs=b''):
    ptype = iw.PDU_L1_LSP if level == 1 else iw.PDU_L2_LSP
    lspid = _sid_bytes(sysid) + b'\x00\x00'
    flags = (0x04 if overload else 0) | (level & 0x03)
    body = (struct.pack('!H', 0) + struct.pack('!H', lifetime) + lspid
            + struct.pack('!I', seq) + struct.pack('!H', 0) + bytes([flags]))
    return common(ptype) + body + tlvs


def csnp(sysid, level=2, tlvs=b''):
    ptype = iw.PDU_L1_CSNP if level == 1 else iw.PDU_L2_CSNP
    sid = _sid_bytes(sysid)
    body = struct.pack('!H', 0) + sid + b'\x00'          # source id + circuit
    body += b'\x00' * 8 + b'\xff' * 8                    # start + end LSP id
    return common(ptype) + body + tlvs


def psnp(sysid, level=2, tlvs=b''):
    ptype = iw.PDU_L1_PSNP if level == 1 else iw.PDU_L2_PSNP
    sid = _sid_bytes(sysid)
    body = struct.pack('!H', 0) + sid + b'\x00'
    return common(ptype) + body + tlvs


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------
class H:
    def __init__(self, verbose):
        self.n = 0
        self.fail = 0
        self.verbose = verbose

    def ck(self, name, cond):
        self.n += 1
        ok = bool(cond)
        if not ok:
            self.fail += 1
        if self.verbose:
            print('  [{}] {}'.format('PASS' if ok else 'FAIL', name))


def _codes(watch):
    return {f['code'] for f in watch.findings.values()}


def _find(watch, code):
    return next((f for f in watch.findings.values() if f['code'] == code), None)


def _watch(pdu_bytes_list, baseline=None, start=0.0, step=0.0, **kw):
    w = iw.IsisWatch(baseline=baseline, **kw)
    now = start
    for pb in pdu_bytes_list:
        w.observe(iw.parse_isis_frame(frame(pb)), now)
        now += step
    return w


def run(verbose=True):
    h = H(verbose)

    # ---- parser: PDU types & fields ---------------------------------------
    p = iw.parse_isis_frame(frame(lan_iih('0000.0000.0001', level=2, priority=64)))
    h.ck('parse L2 LAN IIH kind', p and p['kind'] == 'iih')
    h.ck('parse L2 LAN IIH level', p and p['level'] == 2)
    h.ck('parse L2 LAN IIH system_id', p and p['system_id'] == '0000.0000.0001')
    h.ck('parse LAN IIH priority', p and p['priority'] == 64)
    h.ck('parse src_mac', p and p['src_mac'] == 'de:ad:be:ef:00:01')

    p = iw.parse_isis_frame(frame(lan_iih('0000.0000.0002', level=1)))
    h.ck('parse L1 LAN IIH level', p and p['level'] == 1)

    p = iw.parse_isis_frame(frame(p2p_iih('0000.0000.0003')))
    h.ck('parse P2P IIH p2p flag', p and p['p2p'] is True)
    h.ck('parse P2P IIH level None', p and p['level'] is None)

    p = iw.parse_isis_frame(frame(lsp('0000.0000.0001', level=2, seq=0x2a, lifetime=1000)))
    h.ck('parse L2 LSP kind', p and p['kind'] == 'lsp')
    h.ck('parse LSP seq', p and p['seq'] == 0x2a)
    h.ck('parse LSP lifetime', p and p['lifetime'] == 1000)
    h.ck('parse LSP lsp_id', p and p['lsp_id'] == '0000.0000.0001.00-00')

    p = iw.parse_isis_frame(frame(lsp('0000.0000.0001', level=1)))
    h.ck('parse L1 LSP level', p and p['level'] == 1)

    p = iw.parse_isis_frame(frame(csnp('0000.0000.0001')))
    h.ck('parse CSNP kind', p and p['kind'] == 'csnp')
    p = iw.parse_isis_frame(frame(psnp('0000.0000.0001')))
    h.ck('parse PSNP kind', p and p['kind'] == 'psnp')

    p = iw.parse_isis_frame(frame(lan_iih('0000.0000.0001', tlvs=area_tlv(['490001']))))
    h.ck('parse area TLV', p and p['areas'] == ['490001'])
    p = iw.parse_isis_frame(frame(lan_iih('0000.0000.0001',
                                          tlvs=area_tlv(['490001', '490002']))))
    h.ck('parse multiple areas', p and p['areas'] == ['490001', '490002'])

    p = iw.parse_isis_frame(frame(lsp('0000.0000.0001', tlvs=hostname_tlv('core-1'))))
    h.ck('parse hostname TLV', p and p['hostname'] == 'core-1')

    p = iw.parse_isis_frame(frame(lan_iih('0000.0000.0001',
                                          tlvs=auth_tlv(iw.AUTH_CLEARTEXT, b'secret'))))
    h.ck('parse auth cleartext type', p and p['auth_type'] == iw.AUTH_CLEARTEXT)
    h.ck('parse auth pw len', p and p.get('auth_pw_len') == 6)
    h.ck('parse auth pw first char', p and p.get('auth_pw_first') == 's')

    p = iw.parse_isis_frame(frame(lan_iih('0000.0000.0001',
                                          tlvs=auth_tlv(iw.AUTH_HMAC_MD5, b'\x00' * 16))))
    h.ck('parse auth hmac-md5 type', p and p['auth_type'] == iw.AUTH_HMAC_MD5)

    p = iw.parse_isis_frame(frame(lsp('0000.0000.0001', overload=True)))
    h.ck('parse overload flag', p and p['overload'] is True)
    p = iw.parse_isis_frame(frame(lsp('0000.0000.0001', lifetime=0)))
    h.ck('parse lifetime 0', p and p['lifetime'] == 0)

    p = iw.parse_isis_frame(frame(p2p_iih('0000.0000.0003', tlvs=threeway_tlv())))
    h.ck('parse three-way TLV', p and p['three_way'] is True)
    p = iw.parse_isis_frame(frame(lan_iih('0000.0000.0001', tlvs=padding_tlv())))
    h.ck('parse padding TLV', p and p['padding'] is True)
    p = iw.parse_isis_frame(frame(lsp('0000.0000.0001', tlvs=narrow_tlv())))
    h.ck('parse narrow metrics TLV', p and p['narrow_metrics'] is True)

    # non-IS-IS frame
    h.ck('non-IS-IS frame -> None',
         iw.parse_isis_frame(_mac('11:22:33:44:55:66') + _mac('aa:bb:cc:dd:ee:ff')
                             + b'\x08\x00' + b'\x45' + b'\x00' * 30) is None)

    # VLAN-tagged
    p = iw.parse_isis_frame(frame(lan_iih('0000.0000.0007'), tagged=True))
    h.ck('parse VLAN-tagged frame', p and p['system_id'] == '0000.0000.0007')

    # malformed: truncated LSP header
    bad = common(iw.PDU_L2_LSP) + b'\x00\x00\x04'      # far too short
    p = iw.parse_isis_frame(frame(bad))
    h.ck('parse truncated LSP -> malformed', p and p['malformed'])

    # ---- detectors --------------------------------------------------------
    w = _watch([lan_iih('0000.0000.0001', tlvs=auth_tlv(iw.AUTH_CLEARTEXT, b'secret'))])
    f = _find(w, 'ISIS-AUTH-CLEARTEXT')
    h.ck('AUTH-CLEARTEXT fires', f is not None)
    h.ck('AUTH-CLEARTEXT critical', f and f['severity'] == 'critical')

    w = _watch([lan_iih('0000.0000.0001')])
    f = _find(w, 'ISIS-AUTH-MISSING')
    h.ck('AUTH-MISSING fires', f is not None)
    h.ck('AUTH-MISSING medium (no expected_auth)', f and f['severity'] == 'medium')

    w = _watch([lan_iih('0000.0000.0001')], baseline={'expected_auth': 'crypto'})
    f = _find(w, 'ISIS-AUTH-MISSING')
    h.ck('AUTH-MISSING escalates to high with expected_auth',
         f and f['severity'] == 'high')

    w = _watch([lan_iih('0000.0000.0001', tlvs=auth_tlv(iw.AUTH_HMAC_MD5, b'\x00' * 16))])
    h.ck('AUTH-HMAC-MD5 fires', 'ISIS-AUTH-HMAC-MD5' in _codes(w))

    # mixed: keyed LSP + unkeyed IIH, same system+level
    w = _watch([lsp('0000.0000.0001', level=2, tlvs=auth_tlv(iw.AUTH_HMAC_MD5, b'\x00' * 16)),
                lan_iih('0000.0000.0001', level=2)])
    h.ck('AUTH-MIXED fires', 'ISIS-AUTH-MIXED' in _codes(w))

    # only keyed -> no mixed
    w = _watch([lsp('0000.0000.0001', level=2, tlvs=auth_tlv(iw.AUTH_HMAC_MD5, b'\x00' * 16)),
                lan_iih('0000.0000.0001', level=2, tlvs=auth_tlv(iw.AUTH_HMAC_MD5, b'\x00' * 16))])
    h.ck('AUTH-MIXED quiet when all keyed', 'ISIS-AUTH-MIXED' not in _codes(w))

    w = _watch([lan_iih('0000.0000.0001', tlvs=auth_tlv(99, b'\x00' * 4))])
    f = _find(w, 'ISIS-AUTH-UNKNOWN')
    h.ck('AUTH-UNKNOWN fires', f is not None and f['severity'] == 'low')

    # rogue: baseline known, unknown speaker
    w = _watch([lan_iih('0000.0000.0666')],
               baseline={'known_systems': ['0000.0000.0001']})
    f = _find(w, 'ISIS-ROGUE-SYSTEM')
    h.ck('ROGUE-SYSTEM fires', f is not None and f['severity'] == 'high')
    # known speaker -> no rogue
    w = _watch([lan_iih('0000.0000.0001')],
               baseline={'known_systems': ['0000.0000.0001']})
    h.ck('ROGUE quiet for known system', 'ISIS-ROGUE-SYSTEM' not in _codes(w))
    # no baseline + no learn -> quiet
    w = _watch([lan_iih('0000.0000.0666')])
    h.ck('ROGUE quiet with no baseline', 'ISIS-ROGUE-SYSTEM' not in _codes(w))

    # area mismatch (L1 only)
    w = _watch([lan_iih('0000.0000.0001', level=1, tlvs=area_tlv(['490009']))],
               baseline={'known_systems': ['0000.0000.0001'],
                         'expected_areas': ['490001']})
    h.ck('AREA-MISMATCH fires (L1)', 'ISIS-AREA-MISMATCH' in _codes(w))
    w = _watch([lan_iih('0000.0000.0001', level=1, tlvs=area_tlv(['490001']))],
               baseline={'known_systems': ['0000.0000.0001'],
                         'expected_areas': ['490001']})
    h.ck('AREA ok when expected', 'ISIS-AREA-MISMATCH' not in _codes(w))
    # L2 area not flagged
    w = _watch([lan_iih('0000.0000.0001', level=2, tlvs=area_tlv(['490009']))],
               baseline={'known_systems': ['0000.0000.0001'],
                         'expected_areas': ['490001']})
    h.ck('AREA-MISMATCH not flagged at L2', 'ISIS-AREA-MISMATCH' not in _codes(w))

    # lsp attacks
    w = _watch([lsp('0000.0000.0001', lifetime=0)])
    f = _find(w, 'ISIS-LSP-PURGE')
    h.ck('LSP-PURGE fires', f is not None and f['severity'] == 'high')
    w = _watch([lsp('0000.0000.0001', overload=True)])
    h.ck('LSP-OVERLOAD fires', 'ISIS-LSP-OVERLOAD' in _codes(w))
    w = _watch([lsp('0000.0000.0001', overload=False)])
    h.ck('LSP-OVERLOAD quiet when OL clear', 'ISIS-LSP-OVERLOAD' not in _codes(w))
    w = _watch([lsp('0000.0000.0001', seq=0xFFFFFFF0)])
    h.ck('LSP-SEQ-ANOMALY fires', 'ISIS-LSP-SEQ-ANOMALY' in _codes(w))
    w = _watch([lsp('0000.0000.0001', seq=0x100)])
    h.ck('LSP-SEQ-ANOMALY quiet at low seq', 'ISIS-LSP-SEQ-ANOMALY' not in _codes(w))
    w = _watch([lsp('0000.0000.0001', tlvs=narrow_tlv())])
    h.ck('NARROW-METRICS fires', 'ISIS-NARROW-METRICS' in _codes(w))

    # churn: 5 refloods of one LSP within window
    w = _watch([lsp('0000.0000.0001')] * 5, step=1.0,
               churn_threshold=5, churn_window=20.0)
    h.ck('LSP-CHURN fires at threshold', 'ISIS-LSP-CHURN' in _codes(w))
    # below threshold
    w = _watch([lsp('0000.0000.0001')] * 3, step=1.0,
               churn_threshold=5, churn_window=20.0)
    h.ck('LSP-CHURN quiet below threshold', 'ISIS-LSP-CHURN' not in _codes(w))
    # spread beyond the window -> quiet
    w = _watch([lsp('0000.0000.0001')] * 5, step=30.0,
               churn_threshold=5, churn_window=20.0)
    h.ck('LSP-CHURN quiet when spread past window', 'ISIS-LSP-CHURN' not in _codes(w))

    # DIS max priority
    w = _watch([lan_iih('0000.0000.0001', priority=127)])
    h.ck('DIS-MAXPRIO fires', 'ISIS-DIS-MAXPRIO' in _codes(w))
    w = _watch([lan_iih('0000.0000.0001', priority=64)])
    h.ck('DIS-MAXPRIO quiet at prio 64', 'ISIS-DIS-MAXPRIO' not in _codes(w))

    # p2p 3-way
    w = _watch([p2p_iih('0000.0000.0003')])
    h.ck('P2P-NO-3WAY fires', 'ISIS-P2P-NO-3WAY' in _codes(w))
    w = _watch([p2p_iih('0000.0000.0003', tlvs=threeway_tlv())])
    h.ck('P2P-NO-3WAY quiet with 3-way TLV', 'ISIS-P2P-NO-3WAY' not in _codes(w))

    # padding
    w = _watch([lan_iih('0000.0000.0001', tlvs=padding_tlv())])
    f = _find(w, 'ISIS-HELLO-PADDING')
    h.ck('HELLO-PADDING fires (info)', f is not None and f['severity'] == 'info')

    # malformed
    w = _watch([common(iw.PDU_L2_LSP) + b'\x00\x00\x04'])
    h.ck('MALFORMED fires', 'ISIS-MALFORMED' in _codes(w))

    # CSNP/PSNP don't generate auth/rogue findings
    w = _watch([csnp('0000.0000.0666')],
               baseline={'known_systems': ['0000.0000.0001']})
    h.ck('CSNP no AUTH-MISSING', 'ISIS-AUTH-MISSING' not in _codes(w))
    h.ck('CSNP no ROGUE', 'ISIS-ROGUE-SYSTEM' not in _codes(w))

    # ---- baseline / learn window ------------------------------------------
    w = iw.IsisWatch(baseline={'learn_window': 100})
    w.observe(iw.parse_isis_frame(frame(lan_iih('0000.0000.0001'))), 10.0)
    h.ck('learn window absorbs sid (no rogue)', 'ISIS-ROGUE-SYSTEM' not in _codes(w))
    w.observe(iw.parse_isis_frame(frame(lan_iih('0000.0000.0009'))), 200.0)
    h.ck('rogue after learn window for new sid', 'ISIS-ROGUE-SYSTEM' in _codes(w))
    w.observe(iw.parse_isis_frame(frame(lan_iih('0000.0000.0001'))), 201.0)
    rc = [f for f in w.findings.values()
          if f['code'] == 'ISIS-ROGUE-SYSTEM' and f['system'] == '0000.0000.0001']
    h.ck('learned sid stays trusted after window', not rc)

    # ---- findings model ---------------------------------------------------
    w = _watch([lan_iih('0000.0000.0001')] * 3, start=5.0, step=2.0)
    f = _find(w, 'ISIS-AUTH-MISSING')
    h.ck('dedup: one record for repeats', f and f['count'] == 3)
    h.ck('first_seen set', f and f['first_seen'] == 5.0)
    h.ck('last_seen advances', f and f['last_seen'] == 9.0)

    # snapshot sorting + summary
    w = _watch([lan_iih('0000.0000.0001', tlvs=auth_tlv(iw.AUTH_CLEARTEXT, b'x')),
                lsp('0000.0000.0002', tlvs=padding_tlv())])
    snap = w.snapshot()
    sevs = [f['severity'] for f in snap['findings']]
    h.ck('snapshot sorted severity-desc',
         sevs == sorted(sevs, key=lambda s: -iw.SEV_RANK[s]))
    h.ck('snapshot module field', snap['module'] == 'isiswatch')
    h.ck('snapshot pdu_count', snap['pdu_count'] == 2)
    h.ck('snapshot summary total matches', snap['summary']['total'] == len(snap['findings']))
    h.ck('snapshot by_severity has counts', sum(snap['summary']['by_severity'].values())
         == len(snap['findings']))
    h.ck('snapshot by_code has counts', sum(snap['summary']['by_code'].values())
         == len(snap['findings']))

    # system inventory
    w = _watch([lan_iih('0000.0000.0001', tlvs=area_tlv(['490001'])),
                lsp('0000.0000.0001', tlvs=hostname_tlv('core-1'))])
    snap = w.snapshot()
    sysrec = next((s for s in snap['systems'] if s['system_id'] == '0000.0000.0001'), None)
    h.ck('system inventory hostname', sysrec and sysrec['hostname'] == 'core-1')
    h.ck('system inventory areas', sysrec and sysrec['areas'] == ['490001'])
    h.ck('system inventory levels', sysrec and sysrec['levels'] == [2])
    h.ck('system inventory macs', sysrec and 'de:ad:be:ef:00:01' in sysrec['macs'])

    # multiple systems tracked
    w = _watch([lan_iih('0000.0000.0001'), lan_iih('0000.0000.0002'),
                lan_iih('0000.0000.0003')])
    h.ck('multiple systems tracked', w.snapshot()['system_count'] == 3)

    # ---- PDU-Length bounding (Ethernet-padding regression) ----------------
    # An LSP with a *correct* PDU Length field; the frame is then padded to the
    # 60-byte Ethernet minimum. The TLV walk must stop at the PDU Length, not
    # parse the trailing zeros as type=0 TLVs (the cdpwatch-class false positive).
    def _lsp_with_plen(sysid, tlvs=b''):
        pdu = lsp(sysid, tlvs=tlvs)
        return pdu[:8] + struct.pack('!H', len(pdu)) + pdu[10:]   # PDU Length @ body[0:2]

    pdu = _lsp_with_plen('0000.0000.0001', tlvs=area_tlv(['490001']))
    fr = frame(pdu)
    fr_pad = fr + b'\x00' * max(0, 60 - len(fr))                  # kernel min-frame pad
    p = iw.parse_isis_frame(fr_pad)
    h.ck('pad: no spurious type-0 TLVs', p and 0 not in p['tlv_types'])
    h.ck('pad: area TLV still parsed', p and p['areas'] == ['490001'])
    h.ck('pad: not flagged malformed', p and p['malformed'] is None)
    h.ck('pad: zero pad is benign (no non-zero trailer)', p and not p['trailing_nonzero'])

    # Non-zero bytes past the PDU end are smuggled data, not a malformed PDU.
    p = iw.parse_isis_frame(fr + b'\xde\xad\xbe\xef')
    h.ck('smuggle: flagged trailing_nonzero', p and p['trailing_nonzero'])
    h.ck('smuggle: not malformed', p and p['malformed'] is None)
    w = iw.IsisWatch()
    w.observe(p, 0.0)
    h.ck('smuggle: ISIS-TRAILING-DATA raised', 'ISIS-TRAILING-DATA' in _codes(w))
    w = iw.IsisWatch()
    w.observe(iw.parse_isis_frame(fr_pad), 0.0)
    h.ck('pad: ISIS-TRAILING-DATA quiet on zero pad',
         'ISIS-TRAILING-DATA' not in _codes(w))

    total = h.n
    passed = total - h.fail
    print('isiswatch self-test: {}/{} {}'.format(
        passed, total, 'OK' if h.fail == 0 else 'FAILED'))
    return 0 if h.fail == 0 else 1


if __name__ == '__main__':
    sys.exit(run(verbose=True))
