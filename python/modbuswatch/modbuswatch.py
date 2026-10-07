#!/usr/bin/env python3
"""
modbuswatch — service entrypoint.

Live passive capture on an interface, or offline pcap replay. Receive-only.

  modbuswatch.py --iface eth0 [--ot-subnet 10.20.0.0/24] [--window 3600]
  modbuswatch.py --pcap capture.pcap

Findings are written to stdout (one per line) and, when --log is given, appended
to that file. systemd runs the --iface form; see modbuswatch.service.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys

# Ragnar: relative imports inside the vendored package (see findings.py).
try:
    from .findings import Engine
    from .state import Baseline
    from .sensor import process_packet, run_pcap
except ImportError:
    from findings import Engine
    from state import Baseline
    from sensor import process_packet, run_pcap


def _parse_subnets(specs):
    out = []
    for s in specs or []:
        net = ipaddress.ip_network(s, strict=False)
        fam = socket.AF_INET6 if net.version == 6 else socket.AF_INET
        out.append((fam, net))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="modbuswatch")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="interface to sniff (live)")
    src.add_argument("--pcap", help="pcap file to replay (offline)")
    ap.add_argument("--ot-subnet", action="append", default=[],
                    help="declared OT subnet (enables MBW-040); repeatable")
    ap.add_argument("--window", type=float, default=3600.0,
                    help="baseline learning window, seconds (default 3600)")
    ap.add_argument("--log", help="append findings to this file")
    args = ap.parse_args(argv)

    baseline = Baseline(window_s=args.window)
    engine = Engine(baseline=baseline, ot_subnets=_parse_subnets(args.ot_subnet))

    logfh = open(args.log, "a") if args.log else None

    def emit_new(seen_before):
        for f in engine.findings[seen_before:]:
            line = str(f)
            print(line, flush=True)
            if logfh:
                logfh.write(line + "\n"); logfh.flush()

    if args.pcap:
        run_pcap(args.pcap, engine)
        emit_new(0)
        return 0

    # live capture
    from scapy.all import sniff
    seen = [0]

    def handle(pkt):
        process_packet(pkt, engine)
        emit_new(seen[0])
        seen[0] = len(engine.findings)

    # store=False: never buffer; bpf narrows to the two Modbus ports
    sniff(iface=args.iface, prn=handle, store=False,
          filter="tcp port 502 or tcp port 802")
    return 0


if __name__ == "__main__":
    sys.exit(main())
