"""
modbuswatch — flow state, baselining, arming.

Per (family, src, dst, unit_id) flow. The module self-arms when Modbus is first
seen on a monitored segment, runs a learning window to establish the legitimate
master set per slave, then arms. Writes / UMAS from outside the baseline fire
after the window closes.

Dual-stack: FlowKey carries the address family. Master identity, baselines and
every per-flow counter are tracked independently for v4 and v6, so IPv6 is never
collapsed onto v4. No finding is single-stack.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class FlowKey:
    family: int   # socket.AF_INET or socket.AF_INET6
    src: str
    dst: str
    unit_id: int


@dataclass
class SlaveProfile:
    """What we have learned about one (family, slave-ip, unit) target."""
    masters_seen: set[str] = field(default_factory=set)
    fcs_seen: set[int] = field(default_factory=set)
    first_seen: float = 0.0


class Baseline:
    """
    Learn-then-arm master baseline, keyed by (family, dst, unit_id) so a slave's
    legitimate masters are tracked per address family.

    The module stays dark until the first Modbus ADU is seen (self-arm), then the
    learning window runs for `window_s` seconds of wall time from first sight.
    An operator allowlist short-circuits learning where talkers are already known.
    """

    def __init__(self, window_s: float = 3600.0, allowlist: dict | None = None):
        self.window_s = window_s
        self.armed_at: float | None = None       # when first Modbus was seen
        self.profiles: dict[tuple[int, str, int], SlaveProfile] = {}
        # allowlist: {(family, dst, unit_id): set(master_ips)} declared by operator
        self.allowlist = allowlist or {}

    # --- arming ---
    def note_traffic(self, now: float) -> None:
        if self.armed_at is None:
            self.armed_at = now

    def learning(self, now: float) -> bool:
        if self.armed_at is None:
            return True
        return (now - self.armed_at) < self.window_s

    # --- baseline maintenance ---
    def observe(self, key: FlowKey, fc: int, now: float) -> None:
        slot = (key.family, key.dst, key.unit_id)
        prof = self.profiles.get(slot)
        if prof is None:
            prof = SlaveProfile(first_seen=now)
            self.profiles[slot] = prof
        prof.fcs_seen.add(fc)
        if self.learning(now):
            prof.masters_seen.add(key.src)

    def is_known_master(self, key: FlowKey) -> bool:
        slot = (key.family, key.dst, key.unit_id)
        allowed = self.allowlist.get(slot)
        if allowed is not None and key.src in allowed:
            return True
        prof = self.profiles.get(slot)
        if prof is None:
            return False
        return key.src in prof.masters_seen

    def is_new_master(self, key: FlowKey, now: float) -> bool:
        """True if, after the window, this src was never learned for the slave."""
        if self.learning(now):
            return False
        return not self.is_known_master(key)


class SweepTracker:
    """
    Unit-ID sweep detector (MBW-021): one source cycling many unit IDs against a
    single (family, dst) within a short window. Per address family.
    """

    def __init__(self, threshold: int = 8, window_s: float = 10.0):
        self.threshold = threshold
        self.window_s = window_s
        # (family, src, dst) -> list[(unit_id, ts)]
        self.hits: dict[tuple[int, str, str], list[tuple[int, float]]] = {}

    def record(self, key: FlowKey, now: float) -> bool:
        slot = (key.family, key.src, key.dst)
        seq = self.hits.setdefault(slot, [])
        seq.append((key.unit_id, now))
        cutoff = now - self.window_s
        seq[:] = [(u, t) for (u, t) in seq if t >= cutoff]
        distinct = {u for (u, _) in seq}
        return len(distinct) >= self.threshold


class EnumTracker:
    """
    FC43/MEI-14 device-enumeration burst detector (MBW-020): repeated Read Device
    ID from one source in a short window. Per address family.
    """

    def __init__(self, threshold: int = 3, window_s: float = 10.0):
        self.threshold = threshold
        self.window_s = window_s
        self.hits: dict[tuple[int, str], list[float]] = {}

    def record(self, key: FlowKey, now: float) -> bool:
        slot = (key.family, key.src)
        seq = self.hits.setdefault(slot, [])
        seq.append(now)
        cutoff = now - self.window_s
        seq[:] = [t for t in seq if t >= cutoff]
        return len(seq) >= self.threshold


class UmasSession:
    """
    ModiPwn (CVE-2021-22779) sub-code sequence tracker over FC90, per flow.

    The chain we flag, in order, from one source to one controller:
        1. a memory-block / physical read sub-code (hash-leak primitive)
        2. a subsequent write / reconfigure sub-code (passwordless reconfigure)

    We do not decode Schneider's full private command set; we track the ordered
    appearance of the read-then-write primitives that make up the published
    exploit flow. This is trigger detection (MBW-011), not confirmation.
    """

    # Observed UMAS sub-codes from the Armis/Kaspersky writeups.
    READ_PRIMITIVES = {0x20, 0x21, 0x2A, 0x2B}   # memory/physical reads
    WRITE_PRIMITIVES = {0x22, 0x23, 0x24, 0x28}  # memory/physical writes, reconfigure

    def __init__(self, window_s: float = 30.0):
        self.window_s = window_s
        # (family, src, dst, unit) -> (saw_read_ts)
        self.saw_read: dict[tuple, float] = {}

    def record(self, key: FlowKey, subcode: int, now: float) -> bool:
        slot = (key.family, key.src, key.dst, key.unit_id)
        if subcode in self.READ_PRIMITIVES:
            self.saw_read[slot] = now
            return False
        if subcode in self.WRITE_PRIMITIVES:
            ts = self.saw_read.get(slot)
            if ts is not None and (now - ts) <= self.window_s:
                del self.saw_read[slot]
                return True
        return False
