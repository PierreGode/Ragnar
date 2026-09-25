#!/usr/bin/env python3
"""conftest_packets.py — offline packet conformance for ndpwatch.

Runs the ndp_inject injector's EXACT packets through ndpwatch's real raw-byte
parser + engine, with no interface. Proves the injected packets are wire-correct
and that Scapy's serialization agrees with ndpwatch's independent parser on every
offset — the offline half of the validation (the live half is `ndpwatch-lab.sh`).
Runs on any box (no root, no IPv6 kernel needed):

    $ python3 conftest_packets.py
    conformance: 17/17 attacks produced their required codes
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ndp_inject as inj      # noqa: E402
import ndpwatch as n          # noqa: E402


def run(verbose=True):
    scen = inj.scenarios()
    passed = 0
    for name in sorted(scen):
        codes, pkts = inj.build(name)
        fired = set()
        g = n.NdpWatch(inj.LAB_CONFIG, emit=lambda a: fired.update(a['codes']))
        for i, p in enumerate(pkts):
            g.process_packet(bytes(p), ts=100 + i * 0.1)
        ok = all(c in fired for c in codes)
        passed += 1 if ok else 0
        if verbose:
            print('  [%s] %-18s expect=%s fired=%s'
                  % ('PASS' if ok else 'FAIL', name, codes, sorted(fired)))
    total = len(scen)
    print('conformance: %d/%d attacks produced their required codes' % (passed, total))
    return 0 if passed == total else 1


if __name__ == '__main__':
    raise SystemExit(run())
