#!/usr/bin/env python3
"""arp_guard_selftest.py — offline self-test (no root, no Scapy, no NIC).

Builds raw Ethernet+ARP frame bytes in pure Python and feeds them straight into
ArpGuard.process_packet() — the exact path the live sniffer uses. Includes
negative controls (baseline traffic, a legit ARP probe, a truncated frame) that
must NOT alert or crash. Run via `python3 arp_guard.py --self-test`.
"""

import struct
import sys

import arp_guard as ag


def _macb(s):
    return bytes(int(x, 16) for x in s.split(':'))


def _ipb(s):
    return bytes(int(x) for x in s.split('.'))


def arp(opcode, sender_mac, sender_ip, target_mac, target_ip,
        eth_src=None, eth_dst='ff:ff:ff:ff:ff:ff', hwtype=1, ptype=0x0800,
        hwlen=6, plen=4, trunc=None):
    eth_src = eth_src or sender_mac
    frame = _macb(eth_dst) + _macb(eth_src) + struct.pack('!H', ag.ETH_P_ARP)
    frame += struct.pack('!HHBBH', hwtype, ptype, hwlen, plen, opcode)
    frame += _macb(sender_mac) + _ipb(sender_ip) + _macb(target_mac) + _ipb(target_ip)
    if trunc is not None:
        frame = frame[:trunc]
    return frame


REQ, REPLY = 1, 2
A_MAC, B_MAC, GW_MAC, ATT_MAC = ('aa:aa:aa:00:00:01', 'bb:bb:bb:00:00:02',
                                 'cc:cc:cc:00:00:0f', 'de:ad:be:ef:00:99')


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


def _guard(cfg=None):
    alerts = []
    return ag.ArpGuard(cfg or {}, emit=alerts.append), alerts


def run(verbose=True):
    h = H(verbose)

    # 1. baseline traffic is silent: a normal request + unicast reply.
    g, al = _guard()
    g.process_packet(arp(REQ, A_MAC, '10.0.0.5', '00:00:00:00:00:00', '10.0.0.1'), ts=1)
    g.process_packet(arp(REPLY, GW_MAC, '10.0.0.1', A_MAC, '10.0.0.5',
                         eth_dst=A_MAC), ts=1.1)
    h.ck('baseline traffic is silent', not al)

    # 2. a legitimate ARP probe (opcode 1, sender 0.0.0.0) must NOT alert.
    g, al = _guard()
    g.process_packet(arp(REQ, A_MAC, '0.0.0.0', '00:00:00:00:00:00', '10.0.0.77'), ts=1)
    h.ck('legit ARP probe is silent', not al)

    # 3. gateway impersonation (trusted pin) -> CRITICAL.
    g, al = _guard({'trusted_bindings': {'10.0.0.1': GW_MAC}})
    g.process_packet(arp(REPLY, ATT_MAC, '10.0.0.1', A_MAC, '10.0.0.5', eth_dst=A_MAC), ts=1)
    h.ck('gateway impersonation -> critical',
         al and al[0]['severity'] == 'critical' and 'trusted_impersonation' in al[0]['codes'])

    # 4. subnet-wide gratuitous-ARP flood (one MAC, many IPs) -> breadth.
    g, al = _guard({'garp_breadth_threshold': 4})
    for i in range(1, 6):
        ipx = '10.0.0.%d' % i
        g.process_packet(arp(REPLY, ATT_MAC, ipx, ATT_MAC, ipx), ts=1 + i * 0.1)
    h.ck('subnet-wide GARP flood -> breadth',
         any('garp_subnet_poison' in a['codes'] for a in al))

    # 5. single-target gratuitous-ARP rate flood.
    g, al = _guard({'garp_rate_threshold': 5, 'garp_breadth_threshold': 99})
    for i in range(6):
        g.process_packet(arp(REPLY, ATT_MAC, '10.0.0.1', ATT_MAC, '10.0.0.1'), ts=1 + i * 0.1)
    h.ck('single-target GARP rate flood',
         any('garp_rate_flood' in a['codes'] for a in al))

    # 6. Ethernet-source vs ARP-sender-hardware mismatch.
    g, al = _guard()
    g.process_packet(arp(REPLY, A_MAC, '10.0.0.5', B_MAC, '10.0.0.9',
                         eth_src=ATT_MAC, eth_dst=B_MAC), ts=1)
    h.ck('eth/arp source mismatch -> high',
         al and 'src_mismatch' in al[0]['codes'] and al[0]['severity'] == 'high')

    # 7. broadcast reply anomaly (opcode 2 to ff:ff:ff:ff:ff:ff).
    g, al = _guard()
    g.process_packet(arp(REPLY, A_MAC, '10.0.0.5', B_MAC, '10.0.0.9',
                         eth_dst='ff:ff:ff:ff:ff:ff'), ts=1)
    h.ck('broadcast reply flagged', al and 'broadcast_reply' in al[0]['codes'])

    # 8. invalid 0.0.0.0 reply.
    g, al = _guard()
    g.process_packet(arp(REPLY, A_MAC, '0.0.0.0', B_MAC, '10.0.0.9', eth_dst=B_MAC), ts=1)
    h.ck('invalid 0.0.0.0 reply flagged', al and 'zero_reply' in al[0]['codes'])

    # 9. rapid MAC flapping (one IP bounces between two MACs).
    g, al = _guard({'flap_count': 3})
    macs = [A_MAC, ATT_MAC, A_MAC, ATT_MAC]
    for i, m in enumerate(macs):
        g.process_packet(arp(REPLY, m, '10.0.0.5', B_MAC, '10.0.0.9', eth_dst=B_MAC), ts=1 + i)
    h.ck('rapid MAC flapping -> critical',
         any(a['severity'] == 'critical' and 'binding_flap' in a['codes'] for a in al))

    # 10. a frame truncated shorter than its declared field lengths: no crash,
    #     flagged malformed, and the stateful layers are NOT fed junk.
    g, al = _guard()
    try:
        r = g.process_packet(arp(REPLY, A_MAC, '10.0.0.5', B_MAC, '10.0.0.9', trunc=30), ts=1)
        h.ck('truncated frame handled (malformed, no crash)',
             r is not None and 'malformed' in r['codes'])
    except Exception:
        h.ck('truncated frame handled (malformed, no crash)', False)
    h.ck('truncated frame did not poison binding table', not g._bind)

    # extra: a stable binding conflict (not flapping) is medium/high, and a
    # non-ARP frame returns None.
    g, al = _guard({'stable_threshold_s': 100})
    g.process_packet(arp(REPLY, A_MAC, '10.0.0.5', B_MAC, '10.0.0.9', eth_dst=B_MAC), ts=1)
    g.process_packet(arp(REPLY, ATT_MAC, '10.0.0.5', B_MAC, '10.0.0.9', eth_dst=B_MAC), ts=500)
    h.ck('long-stable binding change -> high',
         any('binding_conflict' in a['codes'] and a['severity'] == 'high' for a in al))
    h.ck('non-ARP frame -> None',
         ag.parse_arp(_macb('11:22:33:44:55:66') * 2 + b'\x08\x00' + b'\x00' * 30) is None)
    # gratuitous single announce (normal, e.g. after DHCP) must stay silent
    g, al = _guard()
    g.process_packet(arp(REPLY, A_MAC, '10.0.0.5', A_MAC, '10.0.0.5', eth_dst='ff:ff:ff:ff:ff:ff'), ts=1)
    h.ck('single gratuitous announce is silent', not al)

    # ---- FHRP (HSRP/VRRP) virtual-MAC awareness ----------------------------
    VIP, VMAC = '10.0.0.1', '00:00:0c:07:ac:01'   # HSRP group 1 virtual MAC
    fhrp_cfg = {'trusted_fhrp_groups': [
        {'protocol': 'hsrp', 'group': 1, 'virtual_ip': VIP, 'virtual_mac': VMAC}]}

    # a clean failover (physical MAC -> confirmed virtual MAC) is de-escalated to
    # info (FHRP_TRANSITION), not treated as poisoning.
    g, al = _guard(fhrp_cfg)
    g.process_packet(arp(REPLY, GW_MAC, VIP, GW_MAC, VIP, eth_dst='ff:ff:ff:ff:ff:ff'), ts=1)
    g.process_packet(arp(REPLY, VMAC, VIP, VMAC, VIP, eth_dst='ff:ff:ff:ff:ff:ff'), ts=2)
    h.ck('FHRP failover -> info fhrp_transition',
         any('fhrp_transition' in a['codes'] and a['severity'] == 'info' for a in al))

    # moving AWAY from the confirmed virtual MAC (gateway identity theft) is the
    # dangerous direction — escalated to critical, never suppressed.
    g, al = _guard(fhrp_cfg)
    g.process_packet(arp(REPLY, VMAC, VIP, VMAC, VIP, eth_dst='ff:ff:ff:ff:ff:ff'), ts=1)
    g.process_packet(arp(REPLY, ATT_MAC, VIP, ATT_MAC, VIP, eth_dst='ff:ff:ff:ff:ff:ff'), ts=2)
    h.ck('FHRP virtual-MAC hijack -> critical',
         any('fhrp_hijack' in a['codes'] and a['severity'] == 'critical' for a in al))

    # a confirmed virtual MAC announcing its own IP repeatedly (failover churn) is
    # NOT a gratuitous flood.
    g, al = _guard(fhrp_cfg)
    for i in range(8):
        g.process_packet(arp(REPLY, VMAC, VIP, VMAC, VIP, eth_dst='ff:ff:ff:ff:ff:ff'), ts=1 + i * 0.1)
    h.ck('confirmed FHRP gratuitous is suppressed', not al)

    # an UNTRUSTED MAC that merely *looks* like an FHRP virtual MAC (shape match,
    # not pinned) is still flagged, with an annotation — a spoofable shape is not
    # a basis for trust.
    g, al = _guard({'garp_rate_threshold': 5, 'garp_breadth_threshold': 99})
    SHAPED = '00:00:0c:07:ac:63'                  # HSRP-range MAC, not in config
    for i in range(6):
        g.process_packet(arp(REPLY, SHAPED, '10.0.0.7', SHAPED, '10.0.0.7',
                             eth_dst='ff:ff:ff:ff:ff:ff'), ts=1 + i * 0.1)
    h.ck('shape-only FHRP MAC is still flagged + annotated',
         any('garp_rate_flood' in a['codes'] for a in al)
         and any('not in trusted_fhrp_groups' in a['summary'] for a in al))

    # classify + derive round-trip: the derived MAC re-classifies to the same group.
    h.ck('classify HSRPv1 virtual MAC', ag._classify_virtual_mac('00:00:0c:07:ac:01') == ('hsrp', 1, 1))
    h.ck('classify VRRP virtual MAC', ag._classify_virtual_mac('00:00:5e:00:01:05') == ('vrrp', 5, None))
    h.ck('ordinary MAC is not FHRP-shaped', ag._classify_virtual_mac(A_MAC) is None)
    h.ck('derive HSRP vmac', ag._derive_fhrp_vmac('hsrp', 1) == '00:00:0c:07:ac:01')
    h.ck('derive VRRP vmac', ag._derive_fhrp_vmac('vrrp', 5) == '00:00:5e:00:01:05')

    # cross-pivot: FHRP-Watch baseline -> suggested trusted_fhrp_groups.
    import json as _json, tempfile as _tmp, os as _os
    fd, p = _tmp.mkstemp(suffix='.json'); _os.close(fd)
    _json.dump({'groups': {'hsrp/1': {'proto': 'hsrp', 'group': 1, 'vips': [VIP]}}},
               open(p, 'w'))
    sug = ag.suggest_fhrp_groups(p)
    _os.remove(p)
    h.ck('suggest_fhrp_groups derives (ip, vmac) pair',
         len(sug) == 1 and sug[0]['virtual_ip'] == VIP and sug[0]['virtual_mac'] == VMAC)

    total = h.n
    passed = total - h.fail
    print('arp_guard self-test: %d/%d %s' % (passed, total, 'OK' if h.fail == 0 else 'FAILED'))
    return 0 if h.fail == 0 else 1


if __name__ == '__main__':
    sys.exit(run(verbose=True))
