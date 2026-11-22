#!/usr/bin/env python3
"""
modbuswatch — service entrypoint.

Live passive capture on an interface, or offline pcap replay. Receive-only.

  modbuswatch.py --iface eth0 [--ot-subnet 10.20.0.0/24[,2001:db8:ac::/64]] [--window 3600]
  modbuswatch.py --pcap capture.pcap

OT subnets may also come from the MBW_OT_SUBNET environment variable
(comma-separated; empty = MBW-040 disabled). systemd sets it via the unit.

The LoRaWAN backhaul tier (MBW-100..105) is configured the same way:
  MBW_LORA_PORTS     UDP ports carrying Semtech GWMP (default 1700; empty = tier off)
  MBW_LORA_SERVERS   declared network-server addresses (empty = learn in window)
  MBW_LORA_GW_ALLOW  per-EUI declared source addresses:
                     "<eui>=<addr>[+<addr>...][,<eui>=...]"
  MBW_LORA_FCNT_LOW / MBW_LORA_FCNT_HIGH   MBW-105 reset thresholds (16 / 1024)
  MBW_LORA_GW_WINDOW MBW-102 conflict window, seconds (default 600)

The backhaul tier has no learning window. MBW_WINDOW (default 3600) remains the
Modbus master-baseline window and applies to Modbus only; the LoRa network
server is the destination of the gateway's own PULL_DATA, which needs no
learning, and MBW-103 simply stays silent until one PULL_DATA has been seen.

Findings are written to stdout (one per line) and, when --log is given, appended
to that file. systemd runs the --iface form; see modbuswatch.service.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import sys

try:  # Ragnar: relative inside the vendored package, bare for flat standalone.
    from .findings import Engine, LoraConfig
    from .state import Baseline
    from .sensor import process_packet, run_pcap
    from .lora import DEFAULT_LORA_PORT
    from .state import LORA_FCNT_LOW, LORA_FCNT_HIGH, LORA_GW_WINDOW_S
except ImportError:
    from findings import Engine, LoraConfig
    from state import Baseline
    from sensor import process_packet, run_pcap
    from lora import DEFAULT_LORA_PORT
    from state import LORA_FCNT_LOW, LORA_FCNT_HIGH, LORA_GW_WINDOW_S

OT_SUBNET_ENV = "MBW_OT_SUBNET"
LORA_PORTS_ENV = "MBW_LORA_PORTS"
LORA_SERVERS_ENV = "MBW_LORA_SERVERS"
LORA_GW_ALLOW_ENV = "MBW_LORA_GW_ALLOW"
LORA_FCNT_LOW_ENV = "MBW_LORA_FCNT_LOW"
LORA_FCNT_HIGH_ENV = "MBW_LORA_FCNT_HIGH"
LORA_GW_WINDOW_ENV = "MBW_LORA_GW_WINDOW"


def build_bpf(lora_ports=(DEFAULT_LORA_PORT,)) -> str:
    """
    Kernel capture filter. IPv4 stays port-scoped; IPv6 is admitted whole.

    libpcap's "tcp port N" reads the IPv6 Next Header at a fixed offset, so any
    v6 packet carrying a Hop-by-Hop / Routing / Destination Options / Fragment
    header is dropped in the kernel before sensor._l4_from_v6 can walk the
    chain. The port decision for v6 therefore lives in sensor.process_packet,
    which already makes it. Same shape as tlswatch build_bpf.

    The LoRaWAN backhaul ports join the IPv4-scoped group; the trailing
    "or ip6" already admits their v6 traffic.
    """
    terms = ["tcp port 502", "tcp port 802"]
    terms += [f"udp port {int(p)}" for p in (lora_ports or ())]
    return "(" + " or ".join(terms) + ") or ip6"


def _parse_ports(spec: str | None, default=(DEFAULT_LORA_PORT,)):
    """Comma-separated UDP ports. Unset = default; set-but-empty = tier off."""
    if spec is None:
        return tuple(default)
    out = []
    for s in spec.split(","):
        s = s.strip()
        if not s:
            continue
        port = int(s)
        if not 1 <= port <= 65535:
            raise ValueError(f"LoRa port out of range: {port}")
        out.append(port)
    return tuple(out)


def _parse_csv(spec: str | None, lower=False) -> frozenset:
    items = []
    for s in (spec or "").split(","):
        s = s.strip()
        if s:
            items.append(s.lower() if lower else s)
    return frozenset(items)


def _parse_gw_allow(spec: str | None) -> dict:
    """
    Per-EUI source-address lists: "<eui>=<addr>[+<addr>...][,<eui>=...]".

    '=' and '+' are the separators because IPv6 literals contain ':'. An EUI
    with a declared list makes any other source MBW-102 at once.
    """
    out: dict = {}
    for entry in (spec or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        if "=" not in entry:
            raise ValueError(
                f"MBW_LORA_GW_ALLOW entry needs <eui>=<addr>: {entry!r}")
        eui, addrs = entry.split("=", 1)
        eui = eui.strip().lower()
        parsed = {a.strip() for a in addrs.split("+") if a.strip()}
        if not eui or not parsed:
            raise ValueError(f"MBW_LORA_GW_ALLOW entry incomplete: {entry!r}")
        out.setdefault(eui, set()).update(parsed)
    return {k: frozenset(v) for k, v in out.items()}


def lora_config(args=None, env=None) -> LoraConfig:
    """Build the LoRaWAN tier config from CLI args plus the environment."""
    env = os.environ if env is None else env
    get = (lambda k: getattr(args, k, None)) if args is not None else (lambda k: None)

    ports_spec = get("lora_ports")
    if ports_spec is None:
        ports_spec = env.get(LORA_PORTS_ENV)
    servers = _parse_csv(get("lora_server") or env.get(LORA_SERVERS_ENV))
    gw_allow = _parse_gw_allow(get("lora_gw_allow") or env.get(LORA_GW_ALLOW_ENV))
    low = get("lora_fcnt_low")
    high = get("lora_fcnt_high")
    if low is None:
        low = int(env.get(LORA_FCNT_LOW_ENV) or LORA_FCNT_LOW)
    if high is None:
        high = int(env.get(LORA_FCNT_HIGH_ENV) or LORA_FCNT_HIGH)
    gw_window = get("lora_gw_window")
    if gw_window is None:
        gw_window = float(env.get(LORA_GW_WINDOW_ENV) or LORA_GW_WINDOW_S)
    return LoraConfig(ports=_parse_ports(ports_spec), servers=servers,
                      gw_allow=gw_allow, fcnt_low=int(low), fcnt_high=int(high),
                      gw_window=float(gw_window))


def _parse_subnets(specs):
    """Accept a list of entries, each optionally comma-separated. Blanks ignored."""
    out = []
    for spec in specs or []:
        for s in spec.split(","):
            s = s.strip()
            if not s:
                continue
            net = ipaddress.ip_network(s, strict=False)
            fam = socket.AF_INET6 if net.version == 6 else socket.AF_INET
            out.append((fam, net))
    return out


def ot_subnets(cli_specs, env=None):
    """CLI --ot-subnet values plus MBW_OT_SUBNET from the environment."""
    env = os.environ if env is None else env
    return _parse_subnets(list(cli_specs or []) + [env.get(OT_SUBNET_ENV, "")])


def main(argv=None):
    ap = argparse.ArgumentParser(prog="modbuswatch")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="interface to sniff (live)")
    src.add_argument("--pcap", help="pcap file to replay (offline)")
    ap.add_argument("--ot-subnet", action="append", default=[],
                    help="declared OT subnet(s), comma-separated or repeated "
                         "(enables MBW-040); also read from $MBW_OT_SUBNET")
    ap.add_argument("--window", type=float, default=3600.0,
                    help="baseline learning window, seconds (default 3600)")
    ap.add_argument("--log", help="append findings to this file")
    ap.add_argument("--lora-ports", default=None,
                    help="UDP ports carrying Semtech GWMP, comma-separated "
                         f"(default {DEFAULT_LORA_PORT}; empty string = tier off); "
                         f"also ${LORA_PORTS_ENV}")
    ap.add_argument("--lora-server", default=None,
                    help=f"declared LoRa network-server address(es); also ${LORA_SERVERS_ENV}")
    ap.add_argument("--lora-gw-allow", default=None,
                    help="per-EUI source addresses, <eui>=<addr>[+<addr>] "
                         f"comma-separated; also ${LORA_GW_ALLOW_ENV}")
    ap.add_argument("--lora-fcnt-low", type=int, default=None,
                    help=f"MBW-105 low threshold (default {LORA_FCNT_LOW}); "
                         f"also ${LORA_FCNT_LOW_ENV}")
    ap.add_argument("--lora-fcnt-high", type=int, default=None,
                    help=f"MBW-105 high-water threshold (default {LORA_FCNT_HIGH}); "
                         f"also ${LORA_FCNT_HIGH_ENV}")
    ap.add_argument("--lora-gw-window", type=float, default=None,
                    help="MBW-102 conflict window, seconds "
                         f"(default {LORA_GW_WINDOW_S:.0f}); "
                         f"also ${LORA_GW_WINDOW_ENV}")
    args = ap.parse_args(argv)

    baseline = Baseline(window_s=args.window)
    lora = lora_config(args)
    engine = Engine(baseline=baseline, ot_subnets=ot_subnets(args.ot_subnet),
                    lora=lora)

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

    # store=False: never buffer
    sniff(iface=args.iface, prn=handle, store=False,
          filter=build_bpf(lora.ports))
    return 0


if __name__ == "__main__":
    sys.exit(main())
