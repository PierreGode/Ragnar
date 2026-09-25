"""Alert record + a time-windowed deduplicator with suppressed-count rollup."""

import time

SEV_RANK = {'INFO': 0, 'LOW': 1, 'MED': 2, 'HIGH': 3}


class Alert:
    __slots__ = ('module', 'rule', 'sev', 'signal', 'identity', 'group', 'ts',
                 'suppressed')

    def __init__(self, module, rule, sev, signal, identity=None, group=None, ts=None):
        self.module = module
        self.rule = rule
        self.sev = sev
        self.signal = signal
        self.identity = identity
        self.group = group
        self.ts = ts if ts is not None else time.time()
        self.suppressed = 0

    def key(self):
        return (self.module, self.rule, self.identity, self.group)

    def to_dict(self):
        return {'module': self.module, 'rule': self.rule, 'sev': self.sev,
                'signal': self.signal, 'identity': self.identity,
                'group': self.group, 'ts': self.ts, 'suppressed': self.suppressed}


class Deduper:
    """Collapse repeats of the same (module, rule, identity, group) within
    `window` seconds; the first re-emission after the window carries the
    suppressed count."""

    def __init__(self, window=60.0):
        self.window = float(window)
        self._last = {}          # key -> (ts, suppressed_since)

    def admit(self, alert):
        """Return the alert to emit (with rollup) or None to suppress."""
        k = alert.key()
        prev = self._last.get(k)
        if prev is None or alert.ts - prev[0] >= self.window:
            alert.suppressed = prev[1] if prev else 0
            self._last[k] = (alert.ts, 0)
            return alert
        self._last[k] = (prev[0], prev[1] + 1)
        return None
