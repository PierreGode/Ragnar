"""Pipeline orchestration: decode -> detectors -> alert -> state.apply.

Kept import-light so the self-test harness can drive process_event() without
a live interface or root.
"""
from __future__ import annotations

import threading
import time
from typing import List

from .alerting import Alerter
from .dataplane import DataPlaneSampler, read_sysfs_counters
from .detectors import (AnomalyDetector, CveDetector, FloodDetector,
                        PolicyDetector, PostureDetector, ReconDetector)
from .models import IgmpEvent
from .snmp import (CapabilityCache, NetSnmpClient, SnmpPoller,
                   collect_snapshot)
from .state import State
from .storage import Storage


class Pipeline:
    def __init__(self, cfg: dict, storage: Storage | None = None,
                 alerter: Alerter | None = None, now: float | None = None):
        self.cfg = cfg
        now = now if now is not None else time.time()
        self.storage = storage or Storage(cfg["db_path"])
        self.alerter = alerter or Alerter(cfg, self.storage)
        self.state = State(self.storage, cfg["learning_period"], now)
        self.detectors = [
            FloodDetector(cfg),
            AnomalyDetector(cfg),
            ReconDetector(cfg),
            PolicyDetector(cfg),
            CveDetector(cfg),
            PostureDetector(cfg),
        ]
        self._lock = threading.Lock()
        self.stats = {"packets": 0, "alerts": 0, "dp_samples": 0, "snmp_polls": 0,
                      "snmp_group_walks_skipped": 0}
        self.dataplane_enabled = bool(cfg.get("dataplane", {}).get("enable"))
        self.dataplane = DataPlaneSampler(cfg) if self.dataplane_enabled else None
        self.snmp_enabled = bool(cfg.get("snmp", {}).get("enable"))
        self.snmp = SnmpPoller(cfg) if self.snmp_enabled else None
        self.snmp_client = NetSnmpClient(cfg["snmp"]) if self.snmp_enabled else None
        self.snmp_caps = None
        if self.snmp_enabled and cfg["snmp"].get("cache_capabilities", True):
            self.snmp_caps = CapabilityCache(
                self.storage,
                ttl=cfg["snmp"].get("capability_ttl", 3600),
                strikes=cfg["snmp"].get("capability_strikes", 3),
            )

    def process_event(self, ev: IgmpEvent) -> List:
        """Run all detectors on one normalized event; emit + persist; update state."""
        with self._lock:
            self.stats["packets"] += 1
            fired = []
            for det in self.detectors:
                for alert in det.inspect(ev, self.state, ev.ts):
                    if self.alerter.emit(alert, ev.ts):
                        self.stats["alerts"] += 1
                    fired.append(alert)
            # state mutation happens only after detectors have read prior state
            self.state.apply(ev)
            return fired

    def poll_dataplane(self, now: float | None = None,
                       counters: dict | None = None) -> List:
        """Sample NIC counters, cross-reference against the joined-group census,
        and emit any data-plane alerts. ``counters`` can be injected for tests;
        otherwise it's read from sysfs for the configured interface.
        """
        if self.dataplane is None:
            return []
        now = now if now is not None else time.time()
        if counters is None:
            counters = read_sysfs_counters(self.cfg["interface"])
        with self._lock:
            self.stats["dp_samples"] += 1
            active = self.state.active_data_group_count()
            fired = self.dataplane.sample(now, counters, active)
            for alert in fired:
                if self.alerter.emit(alert, now):
                    self.stats["alerts"] += 1
            return fired

    def poll_snmp(self, now: float | None = None,
                  snapshot=None) -> List:
        """Poll the switch over SNMP for per-interface / per-group multicast
        state and cross-reference it against the IGMP census. ``snapshot`` can
        be injected for tests; otherwise it's collected from the configured
        switch. SNMP collection (network I/O) happens outside the pipeline lock;
        only the census snapshot + evaluate + emit are locked.
        """
        if self.snmp is None:
            return []
        now = now if now is not None else time.time()
        if snapshot is None:
            snapshot = collect_snapshot(self.snmp_client, self.cfg["snmp"],
                                        caps=self.snmp_caps, now=now)
        with self._lock:
            self.stats["snmp_polls"] += 1
            active = self.state.active_group_set()
            known = self.state.known_group_set()
            learning = self.state.learning(now)
            if snapshot is not None and snapshot.group_walk_skipped:
                self.stats["snmp_group_walks_skipped"] += 1
            fired = self.snmp.evaluate(now, snapshot, active, known, learning)
            for alert in fired:
                if self.alerter.emit(alert, now):
                    self.stats["alerts"] += 1
            return fired

    def maintenance(self, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        with self._lock:
            for det in self.detectors:
                det.prune(now)
            self.state.prune(now - self.cfg["membership_timeout"])

    def close(self):
        self.alerter.close()
        self.storage.close()
