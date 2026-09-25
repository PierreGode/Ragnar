"""Pipeline: sniff (BPF ip proto 2) -> decode -> [detectors] -> alert(dedup) ->
state.apply. Detectors run read-only; state mutates only after they return."""

import sys
import threading
import time

from . import decode
from .alert import Deduper
from .detectors import Detectors
from .state import SharedState
from .dataplane import DataPlaneSampler


class Pipeline:
    def __init__(self, config, storage=None, emit=None, verbose=False):
        self.cfg = config
        self.storage = storage
        self.verbose = verbose
        self.state = SharedState()
        self.detectors = Detectors(config.get('detectors'))
        self.dedup = Deduper(config.get('dedup_window', 60.0))
        self._emit_cb = emit
        self.alerts = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads = []

    def emit(self, alert):
        with self._lock:
            admitted = self.dedup.admit(alert)
        if admitted is None:
            return
        self.alerts.append(admitted)
        if self.storage:
            self.storage.record_event(admitted)
        if self._emit_cb:
            self._emit_cb(admitted)
        if self.verbose:
            sys.stderr.write('  !! [{}] {}/{} {} {}\n'.format(
                admitted.sev, admitted.module, admitted.rule,
                admitted.identity or '', admitted.signal))

    def process_frame(self, raw, now=None):
        msg = decode.decode_frame(raw)
        if msg is None:
            return None
        if now is None:
            now = time.time()
        for a in self.detectors.evaluate(msg, self.state, now):
            self.emit(a)
        self.state.apply(msg, now)                 # mutate AFTER detectors
        return msg

    # -- background tiers ----------------------------------------------------
    def start_background(self):
        dp = self.cfg.get('dataplane') or {}
        if self.cfg.get('iface'):
            s = DataPlaneSampler(self.cfg['iface'], self.state, self.emit, dp, self._stop)
            s.start()
            self._threads.append(s)
        sn = self.cfg.get('snmp') or {}
        if sn.get('enable') and sn.get('host'):
            from .snmp import SnmpPoller
            p = SnmpPoller(self.state, self.emit, sn, self.storage, self._stop)
            p.start()
            self._threads.append(p)

    def stop(self):
        self._stop.set()

    def run_live(self, iface):
        from scapy.all import sniff
        self.start_background()
        sys.stderr.write('igmpwatch: passive on {} (BPF ip proto 2) — Ctrl-C to stop\n'
                         .format(iface))
        try:
            sniff(iface=iface, filter='ip proto 2', store=False,
                  prn=lambda p: self.process_frame(bytes(p)),
                  stop_filter=lambda p: self._stop.is_set())
        finally:
            self.stop()
            if self.storage:
                self.storage.persist_state(self.state)
