"""CLI entrypoint.

Passive by design: opens the capture interface in receive-only mode with a
BPF filter of ``ip proto 2`` so the kernel drops everything non-IGMP before it
reaches Python. igmpwatch never transmits — no queries, no reports, no joins.
Active IGMP probing is deliberately unsupported: sending a general query to
enumerate groups is exactly the reconnaissance signature this tool detects.
"""
from __future__ import annotations

import argparse
import signal
import sys
import threading
import time

from . import config as configmod
from .pipeline import Pipeline


def _run_maintenance(pipeline: Pipeline, stop: threading.Event, interval: float):
    while not stop.wait(interval):
        try:
            pipeline.maintenance()
        except Exception as e:  # pragma: no cover
            sys.stderr.write(f"[maintenance] {e}\n")


def _run_dataplane(pipeline: Pipeline, stop: threading.Event, interval: float):
    while not stop.wait(interval):
        try:
            pipeline.poll_dataplane()
        except Exception as e:  # pragma: no cover
            sys.stderr.write(f"[dataplane] {e}\n")


def _run_snmp(pipeline: Pipeline, stop: threading.Event, interval: float):
    while not stop.wait(interval):
        try:
            pipeline.poll_snmp()
        except Exception as e:  # pragma: no cover
            sys.stderr.write(f"[snmp] {e}\n")


def _snmp_probe(cfg, args) -> int:
    from .snmp import NetSnmpClient, probe, format_probe, CapabilityCache
    s = cfg["snmp"]
    if args.snmp_host:
        s["host"] = args.snmp_host
    if args.snmp_community:
        s["community"] = args.snmp_community
    if args.snmp_version:
        s["version"] = args.snmp_version
    if not s.get("host"):
        sys.stderr.write("--snmp-probe: no switch host (use --snmp-host or set "
                         "snmp.host in config)\n")
        return 2
    client = NetSnmpClient(s)
    report = probe(client, s)
    print(format_probe(report, s))

    # Seed the capability cache so the poller can skip walks this platform
    # doesn't answer. A probe is authoritative: one look is enough, no strikes.
    if not args.no_cache:
        grp = next((r for r in report if r["is_group"]), None)
        if grp is not None and grp["reachable"]:
            from .storage import Storage
            try:
                storage = Storage(s.get("cache_db") or cfg["db_path"])
            except OSError as e:
                sys.stderr.write(f"--snmp-probe: cache not written ({e})\n")
            else:
                caps = CapabilityCache(storage)
                rows = grp["rows"]
                storage.upsert_snmp_capability(
                    s["host"], 1 if rows > 0 else 0, rows,
                    0 if rows > 0 else caps.strikes, "probe", time.time())
                sys.stderr.write(
                    f"--snmp-probe: cached group_table="
                    f"{'supported' if rows > 0 else 'empty (walk will be skipped)'} "
                    f"for {s['host']}\n")
                storage.close()
    return 0 if any(r["reachable"] for r in report) else 1


def build_filter(cfg) -> str:
    """BPF for the capture. IGMP is IP proto 2; MLD is ICMPv6 (types 130-132,143)
    which the kernel can't cheaply match past the mandatory Hop-by-Hop header, so
    we capture all icmp6 and drop non-MLD in decode(). An explicit
    capture_filter in config overrides this."""
    override = (cfg.get("capture_filter") or "").strip()
    if override:
        return override
    f = "ip proto 2"
    if cfg.get("mld", {}).get("enable", True):
        f = f + " or icmp6"
    return f


def main(argv=None):
    ap = argparse.ArgumentParser(prog="igmpwatch",
                                 description="Passive IGMP snooping security monitor")
    ap.add_argument("-c", "--config", help="YAML config path")
    ap.add_argument("-i", "--interface", help="capture interface (overrides config)")
    ap.add_argument("--db", help="sqlite path (overrides config)")
    ap.add_argument("--log", help="jsonl event log path (overrides config)")
    ap.add_argument("--enforce", action="store_true",
                    help="run policy in enforce mode (default from config)")
    ap.add_argument("--stats-interval", type=float, default=60.0)
    ap.add_argument("--snmp-probe", action="store_true",
                    help="one-shot: report which target OIDs the switch answers, then exit")
    ap.add_argument("--snmp-host", help="switch mgmt IP for --snmp-probe (overrides config)")
    ap.add_argument("--snmp-community", help="v1/v2c community for --snmp-probe")
    ap.add_argument("--snmp-version", help="SNMP version for --snmp-probe (1|2c|3)")
    ap.add_argument("--no-cache", action="store_true",
                    help="--snmp-probe: report only, don't seed the capability cache")
    args = ap.parse_args(argv)

    cfg = configmod.load(args.config)
    if args.interface:
        cfg["interface"] = args.interface
    if args.db:
        cfg["db_path"] = args.db
    if args.log:
        cfg["log_path"] = args.log
    if args.enforce:
        cfg["policy"]["mode"] = "enforce"

    # --snmp-probe: one-shot platform validation. Runs before scapy import so
    # it needs no root and no capture interface.
    if args.snmp_probe:
        return _snmp_probe(cfg, args)

    # Import scapy lazily so --help etc. work without it / without root.
    from scapy.sendrecv import AsyncSniffer
    from .decode import decode

    pipeline = Pipeline(cfg)
    stop = threading.Event()

    def handle(pkt):
        ev = decode(pkt)
        if ev is None:
            return
        if ev.ts == 0.0:
            ev.ts = time.time()
        pipeline.process_event(ev)

    sniffer = AsyncSniffer(iface=cfg["interface"], filter=build_filter(cfg),
                           store=False, prn=handle)

    maint = threading.Thread(
        target=_run_maintenance, args=(pipeline, stop, cfg["flood"]["window"]),
        daemon=True)

    dp = None
    if pipeline.dataplane_enabled:
        dp = threading.Thread(
            target=_run_dataplane,
            args=(pipeline, stop, cfg["dataplane"]["interval"]),
            daemon=True)

    snmp_t = None
    if pipeline.snmp_enabled:
        snmp_t = threading.Thread(
            target=_run_snmp,
            args=(pipeline, stop, cfg["snmp"]["interval"]),
            daemon=True)

    def shutdown(signum, frame):
        stop.set()
        try:
            sniffer.stop()
        except Exception:
            pass

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    sys.stderr.write(f"igmpwatch: capturing on {cfg['interface']} "
                     f"(policy={cfg['policy']['mode']}, "
                     f"learning={cfg['learning_period']}s, "
                     f"dataplane={'on' if pipeline.dataplane_enabled else 'off'}, "
                     f"snmp={'on' if pipeline.snmp_enabled else 'off'})\n")
    sniffer.start()
    maint.start()
    if dp is not None:
        dp.start()
    if snmp_t is not None:
        snmp_t.start()

    last_stats = time.time()
    try:
        while not stop.is_set():
            time.sleep(1.0)
            if time.time() - last_stats >= args.stats_interval:
                last_stats = time.time()
                sys.stderr.write(
                    f"igmpwatch: pkts={pipeline.stats['packets']} "
                    f"alerts={pipeline.stats['alerts']} "
                    f"dp_samples={pipeline.stats['dp_samples']} "
                    f"snmp_polls={pipeline.stats['snmp_polls']}\n")
    finally:
        stop.set()
        try:
            sniffer.stop()
        except Exception:
            pass
        pipeline.close()
        sys.stderr.write("igmpwatch: stopped\n")


if __name__ == "__main__":
    sys.exit(main())
