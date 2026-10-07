#!/usr/bin/env python3
"""blewatch_selftest.py — offline self-test (no radio, no root, no Scapy).

Builds BLE Link-Layer PDUs wrapped in a LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (256)
pseudo-header in pure Python and drives them through BleWatch.process_frame() —
the exact path the live sniffer/replay uses — exercising every BLE-0xx finding
code plus negative controls (benign advertising, a normal connection, a single
scan) that must stay silent. Run via `python3 blewatch.py --self-test`.
"""

import struct
import sys

import blewatch as b


# ---- frame builders --------------------------------------------------------
def phdr(channel=37, crc_ok=True):
    flags = 0x0400 | (0x0800 if crc_ok else 0)          # CRC checked (+ valid)
    return bytes([channel & 0xFF, 0, 0, 0]) + b'\x00\x00\x00\x00' + struct.pack('<H', flags)


def _aw(mac):
    """'aa:bb:..:ff' (MSB-first) -> little-endian wire bytes."""
    return bytes(int(x, 16) for x in mac.split(':'))[::-1]


def ad(*structs):
    out = b''
    for atype, val in structs:
        out += bytes([len(val) + 1, atype]) + val
    return out


def name_ad(name):
    return (b.AD_NAME_FULL, name.encode())


def uuid16_ad(u):
    return (b.AD_UUID16_ALL, struct.pack('<H', u))


def manuf_ad(company, data=b''):
    return (b.AD_MANUF, struct.pack('<H', company) + data)


def ibeacon_ad(uuid16b, major, minor, tx=0xC5):
    data = b'\x02\x15' + uuid16b + struct.pack('>HH', major, minor) + bytes([tx & 0xFF])
    return (b.AD_MANUF, struct.pack('<H', 0x004C) + data)


def ll_adv(ptype, adva, payload=b'', tx_add=0, rx_add=0, extra_before=b''):
    body = extra_before + (_aw(adva) if adva else b'') + payload
    hdr0 = (ptype & 0x0F) | ((tx_add & 1) << 6) | ((rx_add & 1) << 7)
    aa = struct.pack('<I', b.ADV_ACCESS_ADDR)
    return aa + bytes([hdr0, len(body) & 0x3F]) + body + b'\x00\x00\x00'


def ll_connect(adva, inita, conn_aa, tx_add=0):
    lldata = struct.pack('<I', conn_aa) + b'\x00' * 18          # AA + 18 more = 22
    body = _aw(inita) + _aw(adva) + lldata
    hdr0 = (b.CONNECT_IND & 0x0F) | ((tx_add & 1) << 7)         # AdvA uses RxAdd
    aa = struct.pack('<I', b.ADV_ACCESS_ADDR)
    return aa + bytes([hdr0, len(body) & 0x3F]) + body + b'\x00\x00\x00'


def ll_data(conn_aa, llid, body):
    aa = struct.pack('<I', conn_aa)
    return aa + bytes([llid & 0x03, len(body) & 0xFF]) + body + b'\x00\x00\x00'


def ll_version(conn_aa, version, company, sub):
    return ll_data(conn_aa, 0x03, bytes([b.LL_VERSION_IND, version])
                   + struct.pack('<HH', company, sub))


def ll_terminate(conn_aa, err=0x13):
    return ll_data(conn_aa, 0x03, bytes([b.LL_TERMINATE_IND, err]))


def smp_pairing_req(conn_aa, authreq):
    smp = bytes([b.SMP_PAIRING_REQ, 0x03, 0x00, authreq, 0x10, 0x07, 0x07])
    body = struct.pack('<HH', len(smp), b.SMP_CID) + smp
    return ll_data(conn_aa, 0x02, body)


def nordic_record(ll, proto=3, pid=0x02, channel=37, rssi=60, flags=0x01):
    """One DLT 272 record as SnifferAPI/Pcap.py stores it: board id + UART
    header + BLE header (len 10, flags, channel, rssi, evt ctr, timestamp) + LL
    (the hardware padding byte already removed by the extcap)."""
    ble = bytes([10, flags, channel, rssi]) + struct.pack('<HI', 1, 1000) + ll
    if proto == 1:
        hdr = bytes([6, len(ble), 1, 0, 0, pid])
    else:
        hdr = struct.pack('<H', len(ble)) + bytes([proto, 0, 0, pid])
    return b'\x00' + hdr + ble


def nordic_decoder_roundtrip(ll):
    """Feed a raw UART packet (with the hardware padding byte) through Nordic's
    vendored SnifferAPI.Packet, store it as the extcap does and check our parser
    recovers the LL PDU. None when the vendored copy can't be imported."""
    import os
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nrf_sniffer')
    try:
        if d not in sys.path:
            sys.path.insert(0, d)
        from SnifferAPI import Packet as NP
    except Exception:
        return None
    ok = True
    for proto, pid in ((1, 0x06), (2, 0x06), (3, 0x02), (3, 0x06)):
        raw = nordic_record(ll[:6] + b'\x00' + ll[6:], proto, pid)[1:]
        pk = NP.Packet(list(raw))
        if not (pk.valid and pk.OK):
            return False
        meta, out = b.strip_to_ll(b.DLT_NORDIC_BLE, bytes([0] + pk.getList()))
        ok &= out == ll
    return ok


def replay_272_pcap():
    """Write a DLT 272 pcap like the extcap and replay it: one AdvA advertising
    two identities in the same instant must alert."""
    import os
    import tempfile
    fd, path = tempfile.mkstemp(suffix='.pcap')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 0xffff, b.DLT_NORDIC_BLE))
            for i, name in enumerate(('Lock-A', 'Lock-B', 'Lock-A', 'Lock-B')):
                rec = nordic_record(ll_adv(b.ADV_IND, 'c0:ff:ee:00:00:02', ad(name_ad(name))))
                f.write(struct.pack('<IIII', 1, i * 1000, len(rec), len(rec)) + rec)
        al = []
        g = b.BleWatch({}, emit=al.append)
        b.run_replay(path, g)
        return g.frames == 4 and bool(al)
    finally:
        os.remove(path)


def feed(guard, ll, ts, channel=37):
    return guard.process_frame(b.DLT_BLE_LL_PHDR, phdr(channel) + ll, ts)


# ---- harness ---------------------------------------------------------------
class H:
    def __init__(self, verbose):
        self.n = self.fail = 0
        self.verbose = verbose
        self.results = []

    def ck(self, name, cond):
        self.n += 1
        if not cond:
            self.fail += 1
        self.results.append({'name': name, 'pass': bool(cond)})
        if self.verbose:
            print('  [%s] %s' % ('PASS' if cond else 'FAIL', name))


def _w(cfg=None):
    al = []
    return b.BleWatch(cfg or {}, emit=al.append), al


def _codes(al):
    return {c for a in al for c in a['codes']}


def _run_checks(verbose):
    h = H(verbose)

    # ---- parser sanity ----------------------------------------------------
    g, al = _w()
    p = b.parse_ble(ll_adv(b.ADV_IND, 'c0:11:ec:00:00:01', ad(name_ad('Lamp'))), {'channel': 37})
    h.ck('parse ADV_IND adva/name',
         p['kind'] == 'adv' and p['adva'] == 'c0:11:ec:00:00:01' and p['ad']['name'] == 'Lamp')
    p = b.parse_ble(ll_version(0x11223344, 7, 0x000f, 0x1234), {})
    h.ck('parse LL_VERSION_IND', p['kind'] == 'data' and p['ll_ctrl']['version'] == 7
         and p['ll_ctrl']['company'] == 0x000f)

    # ---- BLE-001 clone (identity drift) -----------------------------------
    g, al = _w()
    feed(g, ll_adv(b.ADV_IND, 'c0:11:ec:00:00:01', ad(name_ad('Lamp'))), 1)
    feed(g, ll_adv(b.ADV_IND, 'c0:11:ec:00:00:01', ad(name_ad('Pwned'))), 2)
    h.ck('BLE-001 identity clone', 'BLE-001' in _codes(al))

    # ---- BLE-002 impersonation (payload flap) -----------------------------
    g, al = _w({'clone_flap_count': 4})
    for i in range(6):
        feed(g, ll_adv(b.ADV_NONCONN_IND, 'be:ac:00:00:00:02',
                       ad(manuf_ad(0x0059, bytes([i, i, i])))), 1 + i * 0.1)
    h.ck('BLE-002 two radios one AdvA', 'BLE-002' in _codes(al))

    # ---- BLE-003 public address reused across names -----------------------
    g, al = _w()
    feed(g, ll_adv(b.ADV_IND, 'ab:cd:00:00:00:03', ad(name_ad('Printer')), tx_add=0), 1)
    feed(g, ll_adv(b.ADV_IND, 'ab:cd:00:00:00:03', ad(name_ad('Camera')), tx_add=0), 2)
    h.ck('BLE-003 public addr, two names', 'BLE-003' in _codes(al))

    # ---- BLE-004 RPA rotation storm ---------------------------------------
    g, al = _w({'rpa_count': 6})
    for i in range(7):
        feed(g, ll_adv(b.ADV_IND, '4%x:00:00:00:00:%02x' % (i % 10, i),
                       ad(name_ad('x')), tx_add=1), 1 + i * 0.1)   # MSB 0x4.. = resolvable
    h.ck('BLE-004 RPA rotation storm', 'BLE-004' in _codes(al))

    # ---- BLE-005 beacon spoof ---------------------------------------------
    uuidb = bytes(range(16))
    g, al = _w({'beacon_baseline': [{'uuid': uuidb.hex(), 'addr': 'be:ac:00:00:00:aa'}]})
    feed(g, ll_adv(b.ADV_NONCONN_IND, 'ba:ad:00:00:00:05',
                   ad(ibeacon_ad(uuidb, 1, 2))), 1)
    h.ck('BLE-005 beacon UUID from new addr', 'BLE-005' in _codes(al))

    # ---- BLE-006 per-AdvA flood -------------------------------------------
    g, al = _w({'adv_flood_count': 10})
    for i in range(11):
        feed(g, ll_adv(b.ADV_IND, 'f1:00:00:00:00:06', ad(name_ad('beam'))), 1 + i * 0.05)
    h.ck('BLE-006 adv-interval collapse', 'BLE-006' in _codes(al))

    # ---- BLE-007 advertiser flood (generic) -------------------------------
    g, al = _w({'advertiser_flood_count': 6})
    for i in range(7):
        feed(g, ll_adv(b.ADV_IND, 'a0:00:00:00:00:%02x' % i, ad(name_ad('dev%d' % i))),
             1 + i * 0.05)
    h.ck('BLE-007 advertiser flood', 'BLE-007' in _codes(al))

    # ---- BLE-013 spam-shaped flood ----------------------------------------
    g, al = _w({'advertiser_flood_count': 6})
    for i in range(7):
        feed(g, ll_adv(b.ADV_NONCONN_IND, 'a1:00:00:00:00:%02x' % i,
                       ad(manuf_ad(0x004C, bytes([0x07, 0x19, i])))), 1 + i * 0.05)
    h.ck('BLE-013 BLE-spam tooling flood', 'BLE-013' in _codes(al))

    # ---- BLE-008 CONNECT_IND to known device ------------------------------
    g, al = _w({'trusted_devices': ['c0:11:ec:70:00:08']})
    feed(g, ll_connect('c0:11:ec:70:00:08', 'de:ad:00:00:00:01', 0x12345678), 1)
    h.ck('BLE-008 hijack attempt on known device', 'BLE-008' in _codes(al))

    # ---- BLE-009 duplicate CONNECT_IND race -------------------------------
    g, al = _w()
    feed(g, ll_connect('c0:11:ec:70:00:09', 'de:ad:00:00:00:01', 0x11111111), 1)
    feed(g, ll_connect('c0:11:ec:70:00:09', 'be:ef:00:00:00:02', 0x22222222), 2)
    h.ck('BLE-009 connection MITM race', 'BLE-009' in _codes(al))

    # ---- BLE-010 version swap mid-connection ------------------------------
    g, al = _w()
    feed(g, ll_version(0x33334444, 7, 0x000f, 0x0100), 1, channel=10)
    feed(g, ll_version(0x33334444, 10, 0x0059, 0x0200), 2, channel=10)
    h.ck('BLE-010 LL_VERSION_IND swap', 'BLE-010' in _codes(al))

    # ---- BLE-011 pairing downgrade (Just-Works) ---------------------------
    g, al = _w({'trusted_devices': {'c0:11:ec:70:00:11': {'mitm': True}}})
    feed(g, ll_connect('c0:11:ec:70:00:11', 'de:ad:00:00:00:01', 0x55556666), 1)
    feed(g, smp_pairing_req(0x55556666, authreq=0x01), 2, channel=10)  # bonding, no MITM bit
    h.ck('BLE-011 Just-Works downgrade', 'BLE-011' in _codes(al))

    # ---- BLE-012 forced re-pair storm -------------------------------------
    g, al = _w({'terminate_count': 4})
    for i in range(5):
        feed(g, ll_terminate(0x77778888), 1 + i * 0.1, channel=10)
    h.ck('BLE-012 terminate storm', 'BLE-012' in _codes(al))

    # ---- BLE-014 malformed PDU --------------------------------------------
    g, al = _w()
    r = feed(g, b'\xd6\xbe\x89\x8e\x00\x20\x01\x02', 1)        # len=0x20 but body short
    h.ck('BLE-014 malformed (no crash)', r is not None and 'BLE-014' in r['codes'])

    # ---- BLE-015 vendor shape mismatch ------------------------------------
    g, al = _w()
    feed(g, ll_adv(b.ADV_IND, 'a9:91:e0:00:00:15', ad(manuf_ad(0x004C, b''))), 1)
    h.ck('BLE-015 empty Apple manuf payload', 'BLE-015' in _codes(al))

    # ---- BLE-016 GATT service masquerade ----------------------------------
    g, al = _w({'trusted_services': ['180f']})                 # Battery Service
    feed(g, ll_adv(b.ADV_IND, 'ba:d0:00:00:00:16', ad(uuid16_ad(0x180F), name_ad('fake'))), 1)
    h.ck('BLE-016 protected service from untrusted AdvA', 'BLE-016' in _codes(al))

    # ---- sniffer detection (firmware probe, no hardware) ------------------
    raw = bytes([0x00, 0xAB, 0xBC, 0xCD, 0x7F])
    h.ck('SLIP round-trip with escaped bytes', b.slip_frames(b.slip_encode(raw)) == [raw])
    h.ck('PING_REQ wire bytes',
         b.sniffer_ping_packet(1) == bytes([0xAB, 6, 0, 1, 1, 0, 0x0D, 0xBC]))
    # PING_RESP carrying fw 0x04AB (escaped on the wire), after line noise
    resp = b'\x00\xff' + b.slip_encode(bytes([6, 2, 1, 1, 0, b.SNIFFER_PING_RESP, 0xAB, 0x04]))
    h.ck('nRF Sniffer PING_RESP identified + version',
         b.parse_sniffer_reply(resp) == (True, 0x04AB))
    friend = (b'ATI\r\nBLEFRIEND32\r\nnRF51822 QFACA10\r\n4BEC0DC8C5BB9C3B\r\n'
              b'0.6.7\r\n0.6.7\r\nSep 17 2015\r\nS110 8.0.0, 0.2\r\nOK\r\n')
    fi = b.parse_friend_ati(friend)
    h.ck('Bluefruit LE Friend ATI identified',
         bool(fi) and fi['board'] == 'BLEFRIEND32' and fi.get('firmware') == '0.6.7')
    h.ck('Friend AT reply is not a sniffer', b.parse_sniffer_reply(friend) == (False, None))
    esp_boot = b'ets Jun  8 2016 00:22:57\r\nrst:0x1 (POWERON_RESET)\r\nOK\r\n'
    h.ck('ESP32 boot log is neither', b.parse_friend_ati(esp_boot) is None
         and b.parse_sniffer_reply(esp_boot) == (False, None))
    # Protocol v2 (Bluefruit LE Sniffer V2 firmware) / v3 (nRF52) headers carry a
    # 16-bit payload length in bytes 0-1, not a header length.
    h.ck('PING_RESP protocol v2 (Bluefruit V2 fw) identified + version',
         b.parse_sniffer_reply(b.slip_encode(bytes([2, 0, 2, 1, 0, b.SNIFFER_PING_RESP,
                                                    0x10, 0x05]))) == (True, 0x0510))
    h.ck('protocol v3 frame identified',
         b.parse_sniffer_reply(b.slip_encode(bytes([0, 0, 3, 1, 0, 0x1E]))) == (True, None))

    # ---- DLT 272: the record nrf_sniffer_ble.py writes ---------------------
    ll = ll_adv(b.ADV_IND, 'a1:b2:c3:d4:e5:f6', ad(name_ad('Thermo')))
    ok272 = True
    for proto, pid in ((2, 0x06), (3, 0x02)):
        meta, out = b.strip_to_ll(b.DLT_NORDIC_BLE, nordic_record(ll, proto, pid, 38, 61))
        ok272 &= out == ll and meta['channel'] == 38 and meta['rssi'] == -61 and meta['crc_ok']
    h.ck('DLT 272 v2/v3 record -> LL PDU + channel/RSSI/CRC', ok272)
    h.ck('DLT 272 non-packet event (PING_RESP) ignored',
         b.strip_to_ll(b.DLT_NORDIC_BLE, b'\x00' + bytes([2, 0, 2, 1, 0, 0x0E, 1, 2]))
         == (None, None))
    nordic = nordic_decoder_roundtrip(ll)
    if nordic is not None:                        # vendored SnifferAPI importable
        h.ck("DLT 272 matches Nordic's own decoder (vendored SnifferAPI)", nordic)
    h.ck('DLT 272 pcap replay end-to-end', replay_272_pcap())
    h.ck('extcap interface is PORT-VERSION on the real tty',
         b.extcap_capture_cmd('/x/nrf_sniffer_ble.py', '/dev/null', '/tmp/p.pcap', 460800)[4:]
         == ['--capture', '--extcap-interface', '/dev/null-' + b.EXTCAP_PROTO_VERSION,
             '--fifo', '/tmp/p.pcap', '--scan-follow-rsp', '--baudrate', '460800'])

    cands = [{'path': '/dev/ttyUSB0', 'kind': 'bluefruit-friend'},
             {'path': '/dev/ttyUSB1', 'kind': 'unknown'}]
    h.ck('Friend alone is never picked as the sniffer',
         b.find_sniffer(candidates=cands) is None)
    h.ck('sniffer picked by firmware, not by name',
         b.find_sniffer(candidates=cands + [{'path': '/dev/ttyUSB2', 'kind': 'nrf-sniffer'}])
         == '/dev/ttyUSB2')

    # ---- negative controls ------------------------------------------------
    g, al = _w({'trusted_services': ['fff0']})
    feed(g, ll_adv(b.ADV_IND, 'd0:0d:00:00:00:fe', ad(name_ad('Thermo'), uuid16_ad(0x181A))), 1)
    feed(g, ll_adv(b.ADV_IND, 'd0:0d:00:00:00:fe', ad(name_ad('Thermo'), uuid16_ad(0x181A))), 2)
    feed(g, ll_adv(b.SCAN_REQ, 'd0:0d:00:00:00:fe', _aw('c0:ff:ee:00:00:01')), 3)
    feed(g, ll_connect('99:99:00:00:00:fe', 'c0:ff:ee:00:00:01', 0xAABBCCDD), 4)
    feed(g, ll_version(0xAABBCCDD, 8, 0x000f, 0x0100), 5, channel=10)
    h.ck('benign adv/scan/connect/version are silent', not al)

    return h


def run(verbose=True):
    h = _run_checks(verbose)
    passed = h.n - h.fail
    print('blewatch self-test: %d/%d %s' % (passed, h.n, 'OK' if h.fail == 0 else 'FAILED'))
    return 0 if h.fail == 0 else 1


def selftest():
    """Scenario-dict form for the web 'validate detectors' aggregator."""
    h = _run_checks(verbose=False)
    return {'success': h.fail == 0, 'scenarios': h.results}


if __name__ == '__main__':
    sys.exit(run(verbose=True))
