#!/usr/bin/env python3
"""ndpwatch.py — passive IPv6 Neighbor Discovery attack monitor (Ragnar).

The IPv6 counterpart to arp_guard: IPv6 has no ARP — hosts resolve neighbours
and discover routers via ICMPv6 Neighbor Discovery (RS/RA/NS/NA/Redirect), and
the same MITM threat model maps over (NA-spoofing == ARP-spoofing; rogue RA ==
gateway impersonation; RA/prefix floods; DAD DoS; spoofed Redirects).

Detection only — it never sends an ND packet or corrects anything. Passive:
Scapy is only the live-capture front end; field extraction is a hand-rolled
raw-byte parser (no dissector), so `--self-test`/`--replay` need no NIC/IPv6 and
the self-test needs no Scapy. Findings carry a stable NDP-0xx code; findings
about one packet are merged into a single alert (highest severity + evidence).

See docs/ndpwatch.md.
"""

import argparse
import ipaddress
import json
import os
import struct
import sys
import time
from collections import defaultdict, deque

MODULE = 'ndpwatch'
SEV_RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
IPPROTO_ICMPV6 = 58
# ND ICMPv6 types
RS, RA, NS, NA, REDIRECT = 133, 134, 135, 136, 137
# ND option types
OPT_SLLA, OPT_TLLA, OPT_PIO, OPT_MTU, OPT_ROUTE, OPT_RDNSS = 1, 2, 3, 5, 24, 25
UNSPECIFIED = '::'

# Stable finding codes (severity, one-line meaning). 18 are reachable on the wire
# (an injector can produce them); NDP-018 (malformed) and NDP-019 (table
# pressure) are parser-robustness / sustained-flood cases.
CODES = {
    'NDP-001': ('critical', 'NA overriding a learned neighbour binding (cache poison)'),
    'NDP-002': ('high', 'override-flag NA flood for one target (active poisoning)'),
    'NDP-003': ('critical', 'target IPv6 flapping between MACs (two hosts racing)'),
    'NDP-004': ('medium', 'NA Router (R) flag inconsistent for a host/router'),
    'NDP-005': ('high', 'ND option link-layer addr != Ethernet source (forged)'),
    'NDP-006': ('critical', 'RA from a router not in the trusted set (rogue gateway)'),
    'NDP-007': ('high', 'trusted gateway RA with router-lifetime 0 (kill default route)'),
    'NDP-008': ('high', 'RA advertises a prefix outside the baseline (SLAAC hijack)'),
    'NDP-009': ('high', 'RA router-preference High from an untrusted source'),
    'NDP-010': ('high', 'RA RDNSS (DNS) option from an untrusted router (DNS hijack)'),
    'NDP-011': ('medium', 'RA MTU implausibly low / changed (PMTU blackhole)'),
    'NDP-012': ('high', 'Router Advertisement flood (RA rate over threshold)'),
    'NDP-013': ('medium', 'one source soliciting many distinct targets (NS sweep)'),
    'NDP-014': ('high', 'answering NS for tentative (DAD) addresses (DAD DoS)'),
    'NDP-015': ('medium', 'Router Solicitation flood'),
    'NDP-016': ('high', 'ICMPv6 Redirect not from the first-hop router (spoofed)'),
    'NDP-017': ('high', 'ND message with IPv6 Hop Limit != 255 (off-link injection)'),
    'NDP-018': ('medium', 'malformed / truncated ND message'),
    'NDP-019': ('high', 'distinct-target flood approaching neigh_max (table pressure)'),
    'NDP-020': ('high', 'a router link-local speaking ND that is not the pinned gateway'),
}

DEFAULTS = {
    'trusted_routers': [],          # link-local src IPs or MACs of legit routers
    'trusted_prefixes': [],         # prefixes routers may advertise (CIDR)
    'ra_flood_window_s': 10.0, 'ra_flood_count': 10,
    'rs_flood_window_s': 10.0, 'rs_flood_count': 20,
    'ns_sweep_window_s': 10.0, 'ns_sweep_count': 20,      # distinct targets / source
    'na_override_window_s': 10.0, 'na_override_count': 8,
    'dad_defend_window_s': 10.0, 'dad_defend_count': 3,
    'flap_window_s': 30.0, 'flap_count': 3,
    'low_mtu': 1280, 'neigh_max': 20000, 'table_window_s': 30.0,
}


# ===========================================================================
# Raw-byte Ethernet + IPv6 + ICMPv6 ND parser
# ===========================================================================
def _mac(b, i):
    return ':'.join('%02x' % x for x in b[i:i + 6])


def _ip6(b, i):
    return str(ipaddress.IPv6Address(bytes(b[i:i + 16])))


def _u16(b, i):
    return (b[i] << 8) | b[i + 1]


def _u32(b, i):
    return struct.unpack_from('!I', b, i)[0]


def _parse_options(b, i):
    """Walk ND options from offset i. Returns dict + a 'malformed' flag."""
    opts = {'slla': None, 'tlla': None, 'prefixes': [], 'mtu': None,
            'rdnss': [], 'route_info': [], 'malformed': False}
    n = len(b)
    while i + 2 <= n:
        otype = b[i]
        olen = b[i + 1]                              # in units of 8 bytes
        if olen == 0:
            opts['malformed'] = True
            break
        total = olen * 8
        if i + total > n:
            opts['malformed'] = True
            break
        val = b[i:i + total]
        if otype == OPT_SLLA and total >= 8:
            opts['slla'] = _mac(val, 2)
        elif otype == OPT_TLLA and total >= 8:
            opts['tlla'] = _mac(val, 2)
        elif otype == OPT_PIO and total >= 32:
            opts['prefixes'].append({
                'prefix': str(ipaddress.IPv6Address(bytes(val[16:32]))),
                'prefix_len': val[2], 'flags': val[3],
                'valid': _u32(val, 4), 'preferred': _u32(val, 8)})
        elif otype == OPT_MTU and total >= 8:
            opts['mtu'] = _u32(val, 4)
        elif otype == OPT_RDNSS and total >= 16:
            cnt = (total - 8) // 16
            opts['rdnss'] = [str(ipaddress.IPv6Address(bytes(val[8 + 16 * k:24 + 16 * k])))
                             for k in range(cnt)]
        elif otype == OPT_ROUTE:
            opts['route_info'].append(True)
        i += total
    return opts


def parse_ndp(raw):
    """Parse an Ethernet(/802.1Q) IPv6 ICMPv6 ND frame, or None if not ND.
    Never raises: truncation/garbage returns malformed set for NDP-018."""
    if len(raw) < 14:
        return None
    off = 12
    etype = _u16(raw, 12)
    if etype == ETH_P_8021Q:
        if len(raw) < 18:
            return None
        off = 16
        etype = _u16(raw, 16)
    if etype != ETH_P_IPV6:
        return None
    ip = off + 2
    d = {'eth_src': _mac(raw, 6), 'eth_dst': _mac(raw, 0), 'src': None, 'dst': None,
         'hop_limit': None, 'type': None, 'code': None, 'target': None,
         'dest': None, 'na_flags': 0, 'ra': None, 'opts': None,
         'truncated': False, 'malformed': None}
    if len(raw) < ip + 40:
        d['truncated'] = True
        d['malformed'] = 'IPv6 header truncated'
        return d
    next_hdr = raw[ip + 6]
    d['hop_limit'] = raw[ip + 7]
    d['src'] = _ip6(raw, ip + 8)
    d['dst'] = _ip6(raw, ip + 24)
    if next_hdr != IPPROTO_ICMPV6:
        return None                                  # ext headers / not ICMPv6
    ic = ip + 40
    if len(raw) < ic + 4:
        d['truncated'] = True
        d['malformed'] = 'ICMPv6 header truncated'
        return d
    itype = raw[ic]
    if itype not in (RS, RA, NS, NA, REDIRECT):
        return None
    d['type'] = itype
    d['code'] = raw[ic + 1]
    body = ic + 4
    try:
        if itype == RS:
            d['opts'] = _parse_options(raw, body + 4)
        elif itype == RA:
            if len(raw) < body + 12:
                raise ValueError('RA body short')
            d['ra'] = {'cur_hop_limit': raw[body], 'flags': raw[body + 1],
                       'router_lifetime': _u16(raw, body + 2),
                       'reachable': _u32(raw, body + 4),
                       'retrans': _u32(raw, body + 8),
                       'preference': (raw[body + 1] >> 3) & 0x3}   # prf field
            d['opts'] = _parse_options(raw, body + 12)
        elif itype == NS:
            if len(raw) < body + 20:
                raise ValueError('NS body short')
            d['target'] = _ip6(raw, body + 4)
            d['opts'] = _parse_options(raw, body + 20)
        elif itype == NA:
            if len(raw) < body + 20:
                raise ValueError('NA body short')
            d['na_flags'] = raw[body]                # R(0x80) S(0x40) O(0x20)
            d['target'] = _ip6(raw, body + 4)
            d['opts'] = _parse_options(raw, body + 20)
        elif itype == REDIRECT:
            if len(raw) < body + 36:
                raise ValueError('Redirect body short')
            d['target'] = _ip6(raw, body + 4)
            d['dest'] = _ip6(raw, body + 20)
            d['opts'] = _parse_options(raw, body + 36)
    except (ValueError, IndexError, struct.error) as e:
        d['malformed'] = 'ND body: %s' % e
        return d
    if d['opts'] and d['opts'].get('malformed'):
        d['malformed'] = 'ND option overruns message'
    return d


def _in_prefixes(pfx, plen, trusted):
    try:
        net = ipaddress.ip_network('%s/%d' % (pfx, plen), strict=False)
        for t in trusted:
            tn = ipaddress.ip_network(t, strict=False)
            if net.subnet_of(tn) or net == tn:
                return True
    except (ValueError, TypeError):
        return False
    return False


# ===========================================================================
# Engine
# ===========================================================================
class NdpWatch:
    def __init__(self, config=None, emit=None):
        c = dict(DEFAULTS)
        c.update(config or {})
        self.cfg = c
        self.emit = emit or (lambda a: None)
        self.trusted_routers = {str(x).lower() for x in (c.get('trusted_routers') or [])}
        self.trusted_prefixes = list(c.get('trusted_prefixes') or [])
        # state
        self._nbr = {}                               # target -> {'mac', 'since', 'flaps'}
        self._na_override = defaultdict(deque)       # target -> ts
        self._ra_times = deque()                     # ts of RAs
        self._rs_times = deque()                     # ts of RS
        self._ns_targets = defaultdict(deque)        # src -> (ts, target)
        self._dad_defend = defaultdict(deque)        # target -> ts (answers to :: NS)
        self._pending_dad = {}                       # target -> ts (a DAD NS seen)
        self._gw_ra_mtu = {}                         # router -> last mtu
        self._table = deque()                        # (ts, target) distinct-target pressure
        self.frames = 0
        self.stats = defaultdict(int)

    @staticmethod
    def _trim(dq, ts, window, keyed=True):
        while dq and ts - (dq[0][0] if keyed else dq[0]) > window:
            dq.popleft()

    def _is_trusted_router(self, pkt):
        return (pkt['src'].lower() in self.trusted_routers or
                pkt['eth_src'].lower() in self.trusted_routers or
                (pkt['opts'] and (pkt['opts'].get('slla') or '').lower() in self.trusted_routers))

    def process_packet(self, raw, ts=None):
        pkt = parse_ndp(raw)
        if pkt is None:
            return None
        if ts is None:
            ts = time.time()
        self.frames += 1
        f = []
        if pkt.get('malformed'):
            f.append(('NDP-018', pkt['malformed']))
            return self._merge(pkt, f, ts)
        f += self._structural(pkt, ts)
        t = pkt['type']
        if t == NA:
            f += self._on_na(pkt, ts)
        elif t == NS:
            f += self._on_ns(pkt, ts)
        elif t == RA:
            f += self._on_ra(pkt, ts)
        elif t == RS:
            f += self._on_rs(pkt, ts)
        elif t == REDIRECT:
            f += self._on_redirect(pkt, ts)
        f += self._table_pressure(pkt, ts)
        if f:
            return self._merge(pkt, f, ts)
        return None

    # -- structural ----------------------------------------------------------
    def _structural(self, pkt, ts):
        out = []
        # RFC 4861: all ND messages MUST have IPv6 Hop Limit 255. Anything else
        # is off-link injection (a router/host too many hops away).
        if pkt['hop_limit'] is not None and pkt['hop_limit'] != 255:
            out.append(('NDP-017', 'ND %s arrived with Hop Limit %d (must be 255) — '
                        'off-link injection' % (_TNAME[pkt['type']], pkt['hop_limit'])))
        # ND option link-layer address must match the Ethernet source.
        opts = pkt['opts'] or {}
        lla = opts.get('slla') or opts.get('tlla')
        if lla and pkt['eth_src'] and lla.lower() != pkt['eth_src'].lower():
            out.append(('NDP-005', 'ND link-layer option %s != Ethernet source %s — forged'
                        % (lla, pkt['eth_src'])))
        return out

    # -- NA: cache poison / flap / override flood / router flip --------------
    def _on_na(self, pkt, ts):
        out = []
        target = pkt['target']
        mac = (pkt['opts'] or {}).get('tlla') or pkt['eth_src']
        if not target or target == UNSPECIFIED or not mac:
            return out
        override = bool(pkt['na_flags'] & 0x20)
        router = bool(pkt['na_flags'] & 0x80)
        b = self._nbr.get(target)
        if b is None:
            self._nbr[target] = {'mac': mac, 'since': ts, 'flaps': deque(), 'router': router}
        elif b['mac'] != mac:
            b['flaps'].append((ts, mac))
            self._trim(b['flaps'], ts, self.cfg['flap_window_s'])
            macs = {m for _t, m in b['flaps']} | {b['mac']}
            b['mac'], b['since'] = mac, ts
            if len(b['flaps']) >= self.cfg['flap_count'] and len(macs) >= 2:
                out.append(('NDP-003', '%s is flapping between %d MACs — two hosts racing '
                            '(active NA spoofing)' % (target, len(macs))))
            else:
                out.append(('NDP-001', '%s neighbour binding overridden to %s%s — cache '
                            'poisoning' % (target, mac, ' (override flag)' if override else '')))
        else:
            if b.get('router') != router:
                out.append(('NDP-004', '%s NA Router (R) flag changed — role confusion' % target))
            b['router'] = router
        if override:
            dq = self._na_override[target]
            dq.append(ts)
            self._trim(dq, ts, self.cfg['na_override_window_s'], keyed=False)
            if len(dq) >= self.cfg['na_override_count']:
                out.append(('NDP-002', '%s override NA flood (%d in %.0fs) — active poisoning'
                            % (target, len(dq), self.cfg['na_override_window_s'])))
        # answering a DAD probe for a tentative address the segment is claiming
        if target in self._pending_dad:
            dq = self._dad_defend[target]
            dq.append(ts)
            self._trim(dq, ts, self.cfg['dad_defend_window_s'], keyed=False)
            if len(dq) >= self.cfg['dad_defend_count']:
                out.append(('NDP-014', 'repeated NA defending DAD target %s — Duplicate '
                            'Address Detection DoS (nothing can configure)' % target))
        return out

    # -- NS: sweep + DAD tracking --------------------------------------------
    def _on_ns(self, pkt, ts):
        out = []
        src, target = pkt['src'], pkt['target']
        if src == UNSPECIFIED and target:            # DAD probe (tentative addr)
            self._pending_dad[target] = ts
            return out
        if src and target:
            dq = self._ns_targets[src]
            dq.append((ts, target))
            self._trim(dq, ts, self.cfg['ns_sweep_window_s'])
            if len({t for _s, t in dq}) >= self.cfg['ns_sweep_count']:
                out.append(('NDP-013', '%s solicited %d distinct targets in %.0fs — NS sweep '
                            '(scan / cache exhaustion)' % (src, len({t for _s, t in dq}),
                            self.cfg['ns_sweep_window_s'])))
        return out

    # -- RA: rogue router / prefix / RDNSS / MTU / demotion / flood ----------
    def _on_ra(self, pkt, ts):
        out = []
        ra = pkt['ra'] or {}
        trusted = self._is_trusted_router(pkt)
        self._ra_times.append(ts)
        self._trim(self._ra_times, ts, self.cfg['ra_flood_window_s'], keyed=False)
        if len(self._ra_times) >= self.cfg['ra_flood_count']:
            out.append(('NDP-012', 'Router Advertisement flood (%d in %.0fs) — control-plane DoS'
                        % (len(self._ra_times), self.cfg['ra_flood_window_s'])))
        if self.trusted_routers and not trusted:
            out.append(('NDP-006', 'RA from %s (%s) not in the trusted router set — rogue '
                        'gateway / fake_router6' % (pkt['src'], pkt['eth_src'])))
            out.append(('NDP-020', 'router link-local %s speaking ND is not the pinned gateway'
                        % pkt['src']))
            if ra.get('preference') == 1:            # 01 = High
                out.append(('NDP-009', 'rogue RA advertises router-preference High — winning '
                            'the default-router election'))
        if trusted and ra.get('router_lifetime') == 0:
            out.append(('NDP-007', 'trusted gateway RA with router-lifetime 0 — a spoofed RA '
                        'killing the real default route'))
        for p in (pkt['opts'] or {}).get('prefixes', []):
            if self.trusted_prefixes and not _in_prefixes(p['prefix'], p['prefix_len'],
                                                          self.trusted_prefixes):
                out.append(('NDP-008', 'RA advertises prefix %s/%d outside the baseline — '
                            'SLAAC prefix hijack' % (p['prefix'], p['prefix_len'])))
        if (pkt['opts'] or {}).get('rdnss') and self.trusted_routers and not trusted:
            out.append(('NDP-010', 'untrusted RA carries RDNSS %s — DNS hijack via RA'
                        % ', '.join(pkt['opts']['rdnss'][:2])))
        mtu = (pkt['opts'] or {}).get('mtu')
        if mtu is not None and mtu < self.cfg['low_mtu']:
            out.append(('NDP-011', 'RA MTU %d below the IPv6 minimum %d — PMTU blackhole'
                        % (mtu, self.cfg['low_mtu'])))
        return out

    def _on_rs(self, pkt, ts):
        self._rs_times.append(ts)
        self._trim(self._rs_times, ts, self.cfg['rs_flood_window_s'], keyed=False)
        if len(self._rs_times) >= self.cfg['rs_flood_count']:
            return [('NDP-015', 'Router Solicitation flood (%d in %.0fs)'
                     % (len(self._rs_times), self.cfg['rs_flood_window_s']))]
        return []

    def _on_redirect(self, pkt, ts):
        # A legitimate Redirect comes only from the current first-hop router.
        if self.trusted_routers and not self._is_trusted_router(pkt):
            return [('NDP-016', 'ICMPv6 Redirect from %s, not the first-hop router — traffic '
                     'redirection' % pkt['src'])]
        return []

    def _table_pressure(self, pkt, ts):
        tgt = pkt.get('target')
        if not tgt or tgt == UNSPECIFIED:
            return []
        self._table.append((ts, tgt))
        self._trim(self._table, ts, self.cfg['table_window_s'])
        if len({t for _s, t in self._table}) >= self.cfg['neigh_max']:
            return [('NDP-019', 'distinct ND targets in %.0fs approaching neigh_max %d — '
                     'neighbour-table exhaustion' % (self.cfg['table_window_s'],
                     self.cfg['neigh_max']))]
        return []

    # -- merge ---------------------------------------------------------------
    def _merge(self, pkt, findings, ts):
        seen, uniq = set(), []
        for code, detail in findings:
            if code not in seen:
                seen.add(code)
                uniq.append((code, detail))
        worst = max(uniq, key=lambda c: SEV_RANK[CODES[c[0]][0]])
        alert = {
            'ts': ts, 'module': MODULE, 'severity': CODES[worst[0]][0],
            'type': _TNAME.get(pkt.get('type')), 'src': pkt.get('src'),
            'eth_src': pkt.get('eth_src'), 'target': pkt.get('target'),
            'codes': [c for c, _ in uniq], 'summary': worst[1],
            'evidence': [{'code': c, 'severity': CODES[c][0], 'detail': d}
                         for c, d in sorted(uniq, key=lambda x: -SEV_RANK[CODES[x[0]][0]])],
        }
        self.stats[alert['severity']] += 1
        self.emit(alert)
        return alert


_TNAME = {RS: 'RS', RA: 'RA', NS: 'NS', NA: 'NA', REDIRECT: 'Redirect'}


# ===========================================================================
# Live capture / replay (scapy, lazy)
# ===========================================================================
def run_live(iface, guard):
    from scapy.all import sniff
    sys.stderr.write('ndpwatch: passive on %s (icmp6 ND) — Ctrl-C to stop\n' % iface)
    try:
        sniff(iface=iface, filter='icmp6', store=False,
              prn=lambda p: guard.process_packet(bytes(p), float(getattr(p, 'time', 0)) or time.time()))
    except Exception:                                # libpcap/BPF absent: no filter
        sniff(iface=iface, store=False,
              prn=lambda p: guard.process_packet(bytes(p), float(getattr(p, 'time', 0)) or time.time()))


def run_replay(path, guard):
    from scapy.all import PcapReader
    with PcapReader(path) as pr:
        for p in pr:
            guard.process_packet(bytes(p), float(getattr(p, 'time', 0)) or time.time())


def make_emitter(out_fh, echo):
    def emit(a):
        if out_fh:
            out_fh.write(json.dumps(a) + '\n')
            out_fh.flush()
        if echo:
            sys.stderr.write('  !! [%s] %s %s :: %s\n' % (a['severity'], a.get('type') or '',
                             ','.join(a['codes']), a['summary']))
    return emit


def main(argv=None):
    ap = argparse.ArgumentParser(prog='ndpwatch',
                                 description='Passive IPv6 Neighbor Discovery attack monitor (detection-only).')
    ap.add_argument('-i', '--iface', help='live capture interface')
    ap.add_argument('--replay', help='replay a pcap instead of live capture')
    ap.add_argument('-c', '--config', help='JSON config (trusted_routers/prefixes + thresholds)')
    ap.add_argument('--jsonl', '-o', help="JSON-lines output path ('-' = stdout)")
    ap.add_argument('--echo', action='store_true', help='echo alerts to stderr')
    ap.add_argument('--self-test', action='store_true')
    args = ap.parse_args(argv)

    if args.self_test:
        import ndpwatch_selftest
        return ndpwatch_selftest.run(verbose=True)

    cfg = {}
    if args.config:
        with open(args.config) as f:
            cfg = json.load(f)
    out_fh = sys.stdout if args.jsonl == '-' else (open(args.jsonl, 'a') if args.jsonl else None)
    guard = NdpWatch(cfg, emit=make_emitter(out_fh, args.echo or not args.jsonl))

    if args.replay:
        run_replay(args.replay, guard)
    elif args.iface:
        if os.geteuid() != 0:
            sys.stderr.write('error: live capture needs root / CAP_NET_RAW.\n')
            return 2
        try:
            run_live(args.iface, guard)
        except KeyboardInterrupt:
            pass
    else:
        ap.error('one of --iface, --replay or --self-test is required')
    sys.stderr.write('ndpwatch: %d frames, alerts %s\n' % (guard.frames, dict(guard.stats)))
    if out_fh and out_fh is not sys.stdout:
        out_fh.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
