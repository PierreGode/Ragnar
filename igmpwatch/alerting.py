"""Alert emission with per-(rule,host,group) cooldown so a storm can't storm
the log. Suppressed duplicates are counted and rolled up on the next emit.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Dict, Tuple

from .detectors import Alert
from .models import Severity


class Alerter:
    def __init__(self, cfg: dict, storage):
        a = cfg["alerting"]
        self.cooldown = a["cooldown"]
        self.min_sev = Severity[a["min_severity"]]
        self.to_stdout = a["stdout"]
        self.storage = storage
        self.log_path = cfg["log_path"]
        if self.log_path and self.log_path != "-":
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            self._fh = open(self.log_path, "a", buffering=1)
        else:
            self._fh = None
        # key -> (last_emit_ts, suppressed_count)
        self._last: Dict[Tuple, Tuple[float, int]] = {}

    def emit(self, alert: Alert, ts: float) -> bool:
        if alert.severity < self.min_sev:
            return False
        key = (alert.rule, alert.host_mac, alert.group)
        prev = self._last.get(key)
        last, suppressed = prev if prev is not None else (None, 0)
        if last is not None and ts - last < self.cooldown:
            self._last[key] = (last, suppressed + 1)
            return False
        self._last[key] = (ts, 0)

        rec = {
            "ts": ts,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)),
            "rule": alert.rule,
            "severity": alert.severity.label(),
            "host_mac": alert.host_mac,
            "host_ip": alert.host_ip,
            "group": alert.group,
            "detail": alert.detail,
        }
        if suppressed:
            rec["suppressed_since_last"] = suppressed
        line = json.dumps(rec, separators=(",", ":"))
        if self._fh:
            self._fh.write(line + "\n")
        if self.to_stdout:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
        self.storage.record_event(
            ts, alert.rule, int(alert.severity), alert.host_mac,
            alert.host_ip, alert.group, alert.detail, count=1 + suppressed,
        )
        return True

    def close(self):
        if self._fh:
            self._fh.close()
