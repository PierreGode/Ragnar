#!/usr/bin/env python3
"""
DNS Doctor passive tier -- three-thread engine.

  1. CAPTURE   blocks in scapy's sniff(), enqueues raw frames
  2. DETECT    dequeues, parses, runs the detectors, enqueues findings
  3. EMIT      formats JSON-lines, rate-limits, writes

Splitting capture from detection is what keeps a slow detector from
dropping packets: the capture thread does nothing but hand bytes to a
BOUNDED queue. When the queue is full frames are DROPPED and COUNTED
rather than buffered without limit -- an unbounded queue on a 512 MB
Pi is just a slower crash, and a silent drop is worse than a counted
one.

PASSIVE INVARIANT: this module never transmits. Unlike ntpwatch (which
has a --probe mode and therefore needs an allowlist), DNS Doctor's
passive tier is transmit-free outright, so the invariant is a flat ban
on sending primitives -- enforced by an AST check in conformance.py
rather than a grep, because a grep trips over this very docstring
(the legacywatch lesson).
"""
import argparse
import json
import queue
import sys
import threading
import time

import parse
import detect
from bailiwick import zone_of_query
from state import Config, ZoneTable, InFlight, XferTable
from findings import FINDINGS, BASELINE_DEPENDENT

BPF_FILTER = "(udp or tcp) and port 53"


class Stats:
    __slots__ = ("frames", "parsed", "dropped", "findings", "malformed", "not_dns")

    def __init__(self):
        self.frames = self.parsed = self.dropped = 0
        self.findings = self.malformed = self.not_dns = 0


class Engine:
    """
    Detection core. Deliberately constructible and drivable WITHOUT
    any capture: handle_frame() takes bytes. Every offline tier uses
    this entry point, and the lab drives the same one through a real
    NIC, so there is no separate 'test path' that can diverge from
    production.
    """

    def __init__(self, cfg=None, emit=None):
        self.cfg = cfg or Config()
        self.zones = ZoneTable(self.cfg)
        self.inflight = InFlight(self.cfg)
        self.xfers = XferTable(self.cfg)
        self.stats = Stats()
        self._emit = emit or (lambda f: None)
        self._last_sweep = 0.0

    # -- detection ----------------------------------------------------
    def handle_frame(self, frame, now=None):
        now = time.monotonic() if now is None else now
        self.stats.frames += 1

        r = parse.parse_l3_l4(frame)
        if r is None:
            self.stats.not_dns += 1
            return []
        src, dst, sport, dport, proto, payload = r
        is_tcp = proto == "tcp"

        msg = parse.parse_dns(payload)
        self.stats.parsed += 1
        if msg.malformed:
            self.stats.malformed += 1

        q = msg.questions[0] if msg.questions else None
        zone = zone_of_query(q["name"]) if q else "."
        zstate = self.zones.get(zone, now)
        cfg = self.cfg
        out = []

        # TuDoor first: a malformed message may still have partial
        # sections worth looking at, but the malformation is itself
        # the finding and should be reported even if nothing else is.
        out += detect.detect_tudoor(msg, cfg, zone)
        # DNSD-008 is deliberately evaluated alongside (not instead of)
        # DNSD-007: a pointer anomaly is a memory-safety primitive and
        # must not be buried under the generic malformed-packet notice.
        out += detect.detect_pointer_anomaly(msg, cfg, zone)

        if msg.qr:
            # ---- response path ----
            out += detect.detect_keytrap(msg, cfg, zone)
            out += detect.detect_nxnsattack(msg, cfg, zone, zstate, now)
            out += detect.detect_maginotdns(msg, cfg, zone)
            out += detect.detect_nsec3_iterations(msg, cfg, zone)
            out += detect.detect_algo_downgrade(msg, cfg, zone)
            out += detect.detect_dnskey_malformed(msg, cfg, zone)
            out += detect.detect_rrsig_label_mismatch(msg, cfg, zone)
            out += detect.detect_nsec_next_out_of_zone(msg, cfg, zone)
            out += detect.detect_nsec3_apex_impersonation(msg, cfg, zone)
            out += detect.detect_nsec_nsec3_coexistence(msg, cfg, zone)
            out += detect.detect_svcb_alias_abuse(msg, cfg, zone)
            out += detect.detect_edns_option_duplication(msg, cfg, zone)
            out += detect.detect_duplicate_rr_flood(msg, cfg, zone)
            out += detect.detect_dnsbomb(msg, cfg, zone, zstate, now)
            out += detect.detect_nsec3_encloser(msg, cfg, zone, zstate, now)
            out += detect.detect_water_torture(msg, cfg, zone, zstate, now)
            if q is not None:
                key = (msg.txid, tuple(q["name"].lower_labels()), q["qtype"], dport)
                out += detect.detect_sad_dns_conflict(msg, cfg, zone, self.inflight, key, now)
            if is_tcp and q is not None and q["qtype"] in (parse.QT_IXFR, parse.QT_AXFR):
                xkey = (bytes(src), bytes(dst), sport, dport)
                xs = self.xfers.get(xkey, now, q["qtype"])
                out += detect.detect_xfr_tsig_absent(msg, cfg, zone, xs, now, is_tcp)
        else:
            # ---- query path ----
            out += detect.detect_tkey_query(msg, cfg, zone)
            if is_tcp and q is not None and q["qtype"] in (parse.QT_IXFR, parse.QT_AXFR):
                # Register the transfer from the QUERY side so the
                # response stream is keyed on the same conversation.
                self.xfers.get((bytes(dst), bytes(src), dport, sport), now, q["qtype"])
            if q is not None:
                key = (msg.txid, tuple(q["name"].lower_labels()), q["qtype"], sport)
                self.inflight.note_query(key, now)
                zstate.push("query_times", now, cfg.ring_size)
                out += detect.detect_source_port_entropy(cfg, zone, zstate, sport, now)

        if now - self._last_sweep > 5.0:
            self.inflight.sweep(now)
            self.xfers.sweep(now)
            self._last_sweep = now

        for f in out:
            self.stats.findings += 1
            self._emit(f)
        return out

    # -- live capture (LESSON C: the one path no offline tier runs) ---
    def sniff_live(self, iface, count=0, timeout=None, _sniff=None, _queue=None):
        """
        Wraps scapy's sniff(). scapy is imported HERE, lazily, so every
        offline tier can import this module on a host without it.

        `_sniff` and `_queue` exist so conformance.py can drive this
        exact function with a recorder and assert what it passes:
        iface, BPF filter installed, store=False, and offline= NOT set
        (an offline= kwarg would mean it was reading a file, not a
        wire). That is the whole point of the seam -- the live path is
        otherwise never executed until it runs on a Pi.
        """
        if _sniff is None:
            from scapy.all import sniff as _sniff  # noqa: N806

        q = _queue if _queue is not None else queue.Queue(maxsize=4096)

        def _cb(pkt):
            try:
                raw = bytes(pkt)
            except Exception:
                return
            try:
                q.put_nowait(raw)
            except queue.Full:
                self.stats.dropped += 1

        _sniff(iface=iface, filter=BPF_FILTER, prn=_cb, store=False,
               count=count, timeout=timeout)
        return q

    def drain(self, q, now=None):
        """Detection thread body, callable synchronously for tests."""
        out = []
        while True:
            try:
                frame = q.get_nowait()
            except queue.Empty:
                break
            out += self.handle_frame(frame, now)
        return out


class RateLimiter:
    """Per-zone emission cap. A flood must not turn into a finding
    flood -- the alert path is a phone notification, and 10k pages is
    the same as none."""
    __slots__ = ("per_second", "buckets")

    def __init__(self, per_second=100):
        self.per_second = per_second
        self.buckets = {}

    def allow(self, zone, now):
        sec = int(now)
        cur = self.buckets.get(zone)
        if cur is None or cur[0] != sec:
            self.buckets[zone] = [sec, 1]
            return True
        if cur[1] >= self.per_second:
            return False
        cur[1] += 1
        return True


def run(iface, cfg=None, out_stream=None, timeout=None):
    """Wire the three threads together."""
    cfg = cfg or Config()
    out_stream = out_stream or sys.stdout
    frames = queue.Queue(maxsize=4096)
    findings_q = queue.Queue(maxsize=4096)
    limiter = RateLimiter()
    stop = threading.Event()

    engine = Engine(cfg, emit=lambda f: findings_q.put_nowait(f))

    def capture():
        try:
            engine.sniff_live(iface, timeout=timeout, _queue=frames)
        finally:
            stop.set()

    def detect_loop():
        while not stop.is_set() or not frames.empty():
            try:
                frame = frames.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                engine.handle_frame(frame)
            except Exception as e:  # a detector bug must not kill capture
                print(f"detector error: {type(e).__name__}: {e}", file=sys.stderr)

    def emit_loop():
        while not stop.is_set() or not findings_q.empty():
            try:
                f = findings_q.get(timeout=0.2)
            except queue.Empty:
                continue
            now = time.time()
            if not limiter.allow(f["zone"], now):
                continue
            f["ts"] = now
            out_stream.write(json.dumps(f) + "\n")
            out_stream.flush()

    threads = [threading.Thread(target=t, daemon=True)
               for t in (capture, detect_loop, emit_loop)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return engine.stats


def main():
    p = argparse.ArgumentParser(description="DNS Doctor -- passive DNS/DNSSEC tier")
    p.add_argument("-i", "--iface")
    p.add_argument("--timeout", type=float, default=None)
    p.add_argument("--enable-baseline-detectors", action="store_true",
                   help=f"enable the baseline-dependent detectors "
                        f"({', '.join(sorted(BASELINE_DEPENDENT))}). OFF by default: they "
                        f"cannot emit until a per-zone baseline is warm, which a "
                        f"grab-and-go deployment does not have time to build.")
    p.add_argument("--exclude-zone", action="append", default=[],
                   help="zone to suppress behavioural findings for (repeatable)")
    p.add_argument("--max-zones", type=int, default=None)
    p.add_argument("--print-codes", action="store_true",
                   help="print the finding-code registry and exit")
    args = p.parse_args()

    if args.print_codes:
        for code in sorted(FINDINGS):
            m = FINDINGS[code]
            gate = "  [baseline-gated]" if code in BASELINE_DEPENDENT else ""
            print(f"{code}  {m['name']:34s} {m['severity']:8s} {m['confidence']:6s}{gate}")
        return 0

    if not args.iface:
        p.error("-i/--iface is required unless --print-codes is given")

    cfg = Config()
    cfg.enable_baseline_detectors = args.enable_baseline_detectors
    cfg.excluded_zones = set(args.exclude_zone)
    if args.max_zones:
        cfg.max_zones = args.max_zones

    stats = run(args.iface, cfg, timeout=args.timeout)
    print(f"frames={stats.frames} parsed={stats.parsed} findings={stats.findings} "
          f"malformed={stats.malformed} dropped={stats.dropped}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
