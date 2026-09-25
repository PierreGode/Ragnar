#!/usr/bin/env python3
"""ndpwatch_selftest.py — offline self-test (no root, no Scapy, no IPv6 kernel).

Builds raw Ethernet+IPv6+ICMPv6 ND frame bytes in pure Python and drives them
through NdpWatch.process_packet() — the exact path the live sniffer uses —
exercising every NDP-0xx finding code plus negative controls (benign NA/RA, a
DAD probe, a non-ND echo) that must stay silent. Run via
`python3 ndpwatch.py --self-test`.
"""

import ipaddress
import struct
import sys

import ndpwatch as n


def _macb(s):
    return bytes(int(x, 16) for x in s.split(':'))


def _ip6b(s):
    return ipaddress.IPv6Address(s).packed


def eth(payload, src='de:ad:be:ef:00:99', dst='33:33:00:00:00:01'):
    return _macb(dst) + _macb(src) + struct.pack('!H', n.ETH_P_IPV6) + payload


def ipv6(payload, src, dst, hlim=255):
    hdr = struct.pack('!I', 0x60000000) + struct.pack('!H', len(payload))
    hdr += bytes([n.IPPROTO_ICMPV6, hlim]) + _ip6b(src) + _ip6b(dst)
    return hdr + payload


def _icmp6(itype, body):
    return bytes([itype, 0]) + b'\x00\x00' + body


def opt_lla(otype, mac):
    return bytes([otype, 1]) + _macb(mac)


def opt_pio(prefix, plen=64, valid=2592000, preferred=604800, flags=0xc0):
    return bytes([n.OPT_PIO, 4, plen, flags]) + struct.pack('!II', valid, preferred) \
        + b'\x00\x00\x00\x00' + _ip6b(prefix)


def opt_mtu(mtu):
    return bytes([n.OPT_MTU, 1]) + b'\x00\x00' + struct.pack('!I', mtu)


def opt_rdnss(addr, lifetime=600):
    return bytes([n.OPT_RDNSS, 3]) + b'\x00\x00' + struct.pack('!I', lifetime) + _ip6b(addr)


def na(target, src='fe80::99', tlla='de:ad:be:ef:00:99', R=0, S=0, O=1,
       eth_src='de:ad:be:ef:00:99', hlim=255):
    flags = (R << 7) | (S << 6) | (O << 5)
    body = bytes([flags, 0, 0, 0]) + _ip6b(target)
    if tlla:
        body += opt_lla(n.OPT_TLLA, tlla)
    return eth(ipv6(_icmp6(n.NA, body), src, 'ff02::1', hlim), src=eth_src)


def ns(target, src='fe80::5', slla=None, eth_src='aa:aa:aa:00:00:05', hlim=255):
    body = b'\x00\x00\x00\x00' + _ip6b(target)
    if slla:
        body += opt_lla(n.OPT_SLLA, slla)
    return eth(ipv6(_icmp6(n.NS, body), src, 'ff02::1:ff00:5', hlim), src=eth_src)


def ra(src='fe80::66', eth_src='de:ad:be:ef:00:66', lifetime=1800, prf=0,
       opts=b'', hlim=255):
    flags = (prf & 0x3) << 3
    body = bytes([64, flags]) + struct.pack('!H', lifetime) + b'\x00' * 8 + opts
    return eth(ipv6(_icmp6(n.RA, body), src, 'ff02::1', hlim), src=eth_src)


def rs(src='fe80::5', eth_src='aa:aa:aa:00:00:05', hlim=255):
    return eth(ipv6(_icmp6(n.RS, b'\x00\x00\x00\x00'), src, 'ff02::2', hlim), src=eth_src)


def redirect(src='fe80::66', eth_src='de:ad:be:ef:00:66', hlim=255):
    body = b'\x00\x00\x00\x00' + _ip6b('fe80::66') + _ip6b('2001:db8::9')
    return eth(ipv6(_icmp6(n.REDIRECT, body), src, 'fe80::5', hlim), src=eth_src)


class H:
    def __init__(self, verbose):
        self.n = self.fail = 0
        self.verbose = verbose

    def ck(self, name, cond):
        self.n += 1
        if not cond:
            self.fail += 1
        if self.verbose:
            print('  [%s] %s' % ('PASS' if cond else 'FAIL', name))


def _w(cfg=None):
    al = []
    return n.NdpWatch(cfg or {}, emit=al.append), al


def _codes(al):
    return {c for a in al for c in a['codes']}


TRUSTED = {'trusted_routers': ['fe80::1', '02:00:00:00:00:01'],
           'trusted_prefixes': ['2001:db8:0:1::/64']}


def run(verbose=True):
    h = H(verbose)

    # ---- parser sanity ----------------------------------------------------
    p = n.parse_ndp(na('fe80::1'))
    h.ck('parse NA type/target', p and p['type'] == n.NA and p['target'] == 'fe80::1')
    p = n.parse_ndp(ra(opts=opt_pio('2001:db8:0:1::') + opt_mtu(1500)))
    h.ck('parse RA lifetime/pio/mtu',
         p and p['ra']['router_lifetime'] == 1800
         and p['opts']['prefixes'][0]['prefix'] == '2001:db8:0:1::'
         and p['opts']['mtu'] == 1500)
    h.ck('parse non-ND -> None',
         n.parse_ndp(eth(ipv6(bytes([128, 0, 0, 0, 0, 0]), 'fe80::1', 'fe80::2'))) is None)

    # ---- NDP-001 cache poison --------------------------------------------
    g, al = _w()
    g.process_packet(na('2001:db8::5', tlla='aa:aa:aa:00:00:05', eth_src='aa:aa:aa:00:00:05'), ts=1)
    g.process_packet(na('2001:db8::5', tlla='de:ad:be:ef:00:99', eth_src='de:ad:be:ef:00:99'), ts=2)
    h.ck('NDP-001 NA cache poison', 'NDP-001' in _codes(al))

    # ---- NDP-002 override flood ------------------------------------------
    g, al = _w({'na_override_count': 8})
    g.process_packet(na('2001:db8::5', tlla='aa:aa:aa:00:00:05', eth_src='aa:aa:aa:00:00:05'), ts=1)
    for i in range(9):
        g.process_packet(na('2001:db8::5', tlla='de:ad:be:ef:00:99', eth_src='de:ad:be:ef:00:99', O=1), ts=2 + i * 0.1)
    h.ck('NDP-002 override NA flood', 'NDP-002' in _codes(al))

    # ---- NDP-003 flap ----------------------------------------------------
    g, al = _w({'flap_count': 3})
    for i in range(4):
        m = 'aa:aa:aa:00:00:05' if i % 2 == 0 else 'de:ad:be:ef:00:99'
        g.process_packet(na('2001:db8::5', tlla=m, eth_src=m), ts=1 + i)
    h.ck('NDP-003 binding flap -> critical',
         any('NDP-003' in a['codes'] and a['severity'] == 'critical' for a in al))

    # ---- NDP-004 router flag flip ----------------------------------------
    g, al = _w()
    g.process_packet(na('2001:db8::1', tlla='02:00:00:00:00:01', eth_src='02:00:00:00:00:01', R=1), ts=1)
    g.process_packet(na('2001:db8::1', tlla='02:00:00:00:00:01', eth_src='02:00:00:00:00:01', R=0), ts=2)
    h.ck('NDP-004 router flag flip', 'NDP-004' in _codes(al))

    # ---- NDP-005 LLA/eth mismatch ----------------------------------------
    g, al = _w()
    g.process_packet(na('2001:db8::7', tlla='11:11:11:11:11:11', eth_src='de:ad:be:ef:00:99'), ts=1)
    h.ck('NDP-005 LLA != eth source', 'NDP-005' in _codes(al))

    # ---- NDP-006 rogue RA + NDP-020 untrusted router ---------------------
    g, al = _w(TRUSTED)
    g.process_packet(ra(src='fe80::66', eth_src='de:ad:be:ef:00:66',
                        opts=opt_pio('2001:db8:0:1::')), ts=1)
    h.ck('NDP-006 rogue RA', 'NDP-006' in _codes(al))
    h.ck('NDP-020 untrusted router', 'NDP-020' in _codes(al))

    # ---- NDP-007 gateway demotion (trusted RA lifetime 0) ----------------
    g, al = _w(TRUSTED)
    g.process_packet(ra(src='fe80::1', eth_src='02:00:00:00:00:01', lifetime=0,
                        opts=opt_pio('2001:db8:0:1::')), ts=1)
    h.ck('NDP-007 gateway demotion', 'NDP-007' in _codes(al))

    # ---- NDP-008 prefix hijack -------------------------------------------
    g, al = _w({'trusted_routers': ['fe80::1'], 'trusted_prefixes': ['2001:db8:0:1::/64']})
    g.process_packet(ra(src='fe80::1', eth_src='02:00:00:00:00:01',
                        opts=opt_pio('2001:db8:bad::')), ts=1)
    h.ck('NDP-008 prefix hijack', 'NDP-008' in _codes(al))

    # ---- NDP-009 preference High (rogue) ---------------------------------
    g, al = _w(TRUSTED)
    g.process_packet(ra(src='fe80::66', eth_src='de:ad:be:ef:00:66', prf=1,
                        opts=opt_pio('2001:db8:0:1::')), ts=1)
    h.ck('NDP-009 preference High', 'NDP-009' in _codes(al))

    # ---- NDP-010 RDNSS spoof (untrusted) ---------------------------------
    g, al = _w(TRUSTED)
    g.process_packet(ra(src='fe80::66', eth_src='de:ad:be:ef:00:66',
                        opts=opt_pio('2001:db8:0:1::') + opt_rdnss('2001:db8:bad::53')), ts=1)
    h.ck('NDP-010 RDNSS spoof', 'NDP-010' in _codes(al))

    # ---- NDP-011 MTU anomaly ---------------------------------------------
    g, al = _w({'trusted_routers': ['fe80::1'], 'trusted_prefixes': ['2001:db8:0:1::/64']})
    g.process_packet(ra(src='fe80::1', eth_src='02:00:00:00:00:01',
                        opts=opt_pio('2001:db8:0:1::') + opt_mtu(1200)), ts=1)
    h.ck('NDP-011 low MTU', 'NDP-011' in _codes(al))

    # ---- NDP-012 RA flood ------------------------------------------------
    g, al = _w({'ra_flood_count': 10})
    for i in range(11):
        g.process_packet(ra(src='fe80::66', eth_src='de:ad:be:ef:00:66'), ts=1 + i * 0.1)
    h.ck('NDP-012 RA flood', 'NDP-012' in _codes(al))

    # ---- NDP-013 NS sweep -------------------------------------------------
    g, al = _w({'ns_sweep_count': 20})
    for i in range(21):
        g.process_packet(ns('2001:db8::%d' % (i + 1), src='fe80::66', eth_src='de:ad:be:ef:00:66'), ts=1 + i * 0.05)
    h.ck('NDP-013 NS sweep', 'NDP-013' in _codes(al))

    # ---- NDP-014 DAD DoS --------------------------------------------------
    g, al = _w({'dad_defend_count': 3})
    g.process_packet(ns('2001:db8::dad', src='::', eth_src='aa:aa:aa:00:00:05'), ts=1)  # DAD probe
    for i in range(4):
        g.process_packet(na('2001:db8::dad', tlla='de:ad:be:ef:00:99', eth_src='de:ad:be:ef:00:99'), ts=2 + i * 0.1)
    h.ck('NDP-014 DAD DoS', 'NDP-014' in _codes(al))

    # ---- NDP-015 RS flood -------------------------------------------------
    g, al = _w({'rs_flood_count': 20})
    for i in range(21):
        g.process_packet(rs(src='fe80::%d' % (i + 10), eth_src='aa:aa:aa:00:%02x:05' % i), ts=1 + i * 0.05)
    h.ck('NDP-015 RS flood', 'NDP-015' in _codes(al))

    # ---- NDP-016 spoofed redirect ----------------------------------------
    g, al = _w(TRUSTED)
    g.process_packet(redirect(src='fe80::66', eth_src='de:ad:be:ef:00:66'), ts=1)
    h.ck('NDP-016 spoofed redirect', 'NDP-016' in _codes(al))

    # ---- NDP-017 bad hop limit -------------------------------------------
    g, al = _w()
    g.process_packet(na('2001:db8::5', tlla='de:ad:be:ef:00:99', eth_src='de:ad:be:ef:00:99', hlim=64), ts=1)
    h.ck('NDP-017 bad hop limit', 'NDP-017' in _codes(al))

    # ---- NDP-018 malformed ------------------------------------------------
    g, al = _w()
    r = g.process_packet(na('2001:db8::5')[:48], ts=1)     # truncated
    h.ck('NDP-018 malformed (no crash)', r is not None and 'NDP-018' in r['codes'])

    # ---- NDP-019 table pressure ------------------------------------------
    g, al = _w({'neigh_max': 25, 'table_window_s': 60})
    for i in range(26):
        g.process_packet(ns('2001:db8:%x::1' % i, src='fe80::5', eth_src='aa:aa:aa:00:00:05'), ts=1 + i * 0.01)
    h.ck('NDP-019 table pressure', 'NDP-019' in _codes(al))

    # ---- negative controls -----------------------------------------------
    g, al = _w(TRUSTED)
    # benign NA (first sighting), benign RA from trusted router with baseline prefix
    g.process_packet(na('2001:db8:0:1::5', tlla='aa:aa:aa:00:00:05', eth_src='aa:aa:aa:00:00:05'), ts=1)
    g.process_packet(ra(src='fe80::1', eth_src='02:00:00:00:00:01', lifetime=1800,
                        opts=opt_pio('2001:db8:0:1::') + opt_mtu(1500)), ts=2)
    g.process_packet(ns('2001:db8:0:1::9', src='fe80::1', slla='02:00:00:00:00:01', eth_src='02:00:00:00:00:01'), ts=3)
    g.process_packet(ns('2001:db8:0:1::7', src='::', eth_src='aa:aa:aa:00:00:05'), ts=4)  # DAD probe alone
    h.ck('benign NA/RA/NS/DAD are silent', not al)

    total = h.n
    passed = total - h.fail
    print('ndpwatch self-test: %d/%d %s' % (passed, total, 'OK' if h.fail == 0 else 'FAILED'))
    return 0 if h.fail == 0 else 1


if __name__ == '__main__':
    sys.exit(run(verbose=True))
