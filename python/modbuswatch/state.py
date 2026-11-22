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

try:  # Ragnar: relative inside the vendored package, bare for flat standalone.
    from .lora import FCNT_ROLLOVER_GUARD as LORA_FCNT_ROLLOVER_GUARD
except ImportError:
    from lora import FCNT_ROLLOVER_GUARD as LORA_FCNT_ROLLOVER_GUARD


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


# ---------------------------------------------------------------------------
# LoRaWAN gateway-backhaul trackers (MBW-100..106)
#
# Keyed by address family throughout, exactly like the Modbus trackers above:
# the Semtech UDP backhaul runs over IPv4 or IPv6 and a gateway EUI seen on one
# family is never collapsed onto the other.
#
# Budgets follow the preflight so the whole LoRa tier stays inside the Pi Zero
# 2W floor: gateway maps LRU 512, DevNonce rings 16 deep over an LRU of 2,048
# DevEUIs, FCnt map LRU 8,192 DevAddrs. Roughly 0.5 MB.
# ---------------------------------------------------------------------------

from collections import OrderedDict, deque

LORA_MAX_GATEWAYS = 512
LORA_MAX_DEVEUIS = 2048
LORA_MAX_DEVADDRS = 8192
LORA_NONCE_RING = 16
LORA_MAX_SOURCES_PER_GW = 8

# MBW-102 conflict window: two source addresses for one gateway EUI are only a
# conflict if both were active inside it. A gateway re-addressed by DHCP hours
# ago is not an impersonator.
LORA_GW_WINDOW_S = 600.0

# MBW-105 thresholds: a DevAddr that climbed above `high` and is next seen at or
# below `low`. 16-bit FCnt wraps legitimately at 65,535, so a device already
# near the wrap is never reported.
LORA_FCNT_LOW = 16
LORA_FCNT_HIGH = 1024


def _lru_put(od: OrderedDict, key, value, cap: int):
    """Insert and evict the least recently used entry past `cap`."""
    od[key] = value
    od.move_to_end(key)
    while len(od) > cap:
        od.popitem(last=False)
    return value


def _lru_get(od: OrderedDict, key):
    if key in od:
        od.move_to_end(key)
        return od[key]
    return None


class GatewayServerMap:
    """
    Which address is the network server for a given gateway (MBW-103).

    Derived the way the preflight specifies: the server is the address the
    gateway has been **sending PULL_DATA to**. That is a destination, not a
    sender, so nothing an attacker transmits can nominate itself -- which is why
    this needs no learning window at all. Declared addresses
    (MBW_LORA_SERVERS) override, for an anycast or load-balanced server.

    A PULL_RESP carries no gateway EUI, so the gateway it is aimed at is
    identified by the datagram's destination address, learned from the gateway's
    own PUSH_DATA / PULL_DATA / TX_ACK.
    """

    def __init__(self, declared=None):
        self.declared: set[str] = set(declared or ())
        # (family, eui) -> set(server addresses the gateway sends PULL_DATA to)
        self.servers: "OrderedDict[tuple, set]" = OrderedDict()
        # (family, gateway address) -> set(EUIs seen sourcing from it)
        self.gw_addr: "OrderedDict[tuple, set]" = OrderedDict()

    def note_gateway_addr(self, family: int, addr: str, eui: str) -> None:
        slot = (family, addr)
        cur = _lru_get(self.gw_addr, slot)
        if cur is None:
            _lru_put(self.gw_addr, slot, {eui}, LORA_MAX_GATEWAYS)
        elif len(cur) < LORA_MAX_SOURCES_PER_GW:
            cur.add(eui)

    def note_pull_data(self, family: int, eui: str, dst: str) -> None:
        """A PULL_DATA from this gateway names its network server."""
        if dst is None:
            return
        slot = (family, eui)
        cur = _lru_get(self.servers, slot)
        if cur is None:
            _lru_put(self.servers, slot, {dst}, LORA_MAX_GATEWAYS)
        elif len(cur) < LORA_MAX_SOURCES_PER_GW:
            cur.add(dst)

    def euis_at(self, family: int, addr: str) -> set:
        return _lru_get(self.gw_addr, (family, addr)) or set()

    def armed(self, family: int, eui: str) -> bool:
        """MBW-103 stays silent until the gateway-to-server map is known."""
        if self.declared:
            return True
        return bool(_lru_get(self.servers, (family, eui)))

    def is_expected(self, family: int, eui: str, addr: str) -> bool:
        if addr in self.declared:
            return True
        return addr in (_lru_get(self.servers, (family, eui)) or set())

    def expected_for(self, family: int, eui: str) -> set:
        return set(self.declared) | (_lru_get(self.servers, (family, eui)) or set())


class GatewayCensus:
    """
    Gateway EUI census (MBW-100) and source-address conflict (MBW-102).

    Two modes, per the preflight's false-positive table:
      - with a declared address list for that EUI (MBW_LORA_GW_ALLOW), any
        source outside the list is a conflict immediately;
      - otherwise, two distinct sources both active inside the window are.

    Per-source first and last seen are kept for the finding's metadata.
    """

    def __init__(self, window_s: float = LORA_GW_WINDOW_S, gw_allow=None):
        self.window_s = window_s
        # eui (lowercase hex) -> frozenset(declared source addresses)
        self.gw_allow = dict(gw_allow or {})
        # (family, eui) -> {addr: [first_seen, last_seen]}
        self.sources: "OrderedDict[tuple, dict]" = OrderedDict()
        # (family, eui, addr) already reported, so one offender fires once
        self._reported: set[tuple] = set()

    def record(self, family: int, gw_eui: str, src: str,
               now: float) -> tuple[bool, str | None]:
        """(is_new_gateway, conflict_reason or None)."""
        slot = (family, gw_eui)
        seen = _lru_get(self.sources, slot)
        is_new = seen is None
        if is_new:
            seen = _lru_put(self.sources, slot, {}, LORA_MAX_GATEWAYS)
        span = seen.get(src)
        if span is None:
            if len(seen) < LORA_MAX_SOURCES_PER_GW:
                seen[src] = [now, now]
        else:
            span[1] = now

        declared = self.gw_allow.get(gw_eui.lower())
        tag = (family, gw_eui, src)
        if declared is not None:
            if src not in declared and tag not in self._reported:
                self._reported.add(tag)
                return is_new, ("source outside the declared address list "
                                f"({', '.join(sorted(declared))})")
            return is_new, None

        cutoff = now - self.window_s
        active = sorted(a for a, (_f, l) in seen.items() if l >= cutoff)
        if len(active) > 1 and tag not in self._reported:
            self._reported.add(tag)
            return is_new, (f"{len(active)} sources active within "
                            f"{self.window_s:.0f}s: " + ", ".join(active))
        return is_new, None

    def sources_for(self, family: int, gw_eui: str) -> dict:
        return _lru_get(self.sources, (family, gw_eui)) or {}

    def source_spans(self, family: int, gw_eui: str) -> str:
        """"addr(first..last)" per source, for the finding metadata."""
        seen = self.sources_for(family, gw_eui)
        return ", ".join(f"{a}(first={f:.0f} last={l:.0f})"
                         for a, (f, l) in sorted(seen.items()))


class DevNonceTracker:
    """
    JoinRequest DevNonce reuse (MBW-104), per (family, DevEUI).

    A DevNonce repeated for the same device is a replayed join: LoRaWAN 1.0.4
    and 1.1 require DevNonce to increment, so reuse is a replay attempt or a
    non-compliant device -- the same exposure from the defender's side either
    way. State is the preflight's: a 16-deep ring per device over an LRU of
    2,048 DevEUIs. The repeat count rides along in the finding.
    """

    def __init__(self, ring: int = LORA_NONCE_RING, cap: int = LORA_MAX_DEVEUIS):
        self.ring = ring
        self.cap = cap
        # (family, dev_eui) -> deque(maxlen=ring)
        self.seen: "OrderedDict[tuple, deque]" = OrderedDict()
        # (family, dev_eui, nonce) -> times seen
        self.repeats: "OrderedDict[tuple, int]" = OrderedDict()

    def record(self, family: int, dev_eui: str, nonce: int) -> int:
        """Returns the repeat count (>=2) on reuse, else 0."""
        slot = (family, dev_eui)
        ring = _lru_get(self.seen, slot)
        if ring is None:
            _lru_put(self.seen, slot, deque([nonce], maxlen=self.ring), self.cap)
            return 0
        if nonce in ring:
            rk = (family, dev_eui, nonce)
            count = (_lru_get(self.repeats, rk) or 1) + 1
            _lru_put(self.repeats, rk, count, self.cap)
            return count
        ring.append(nonce)
        return 0


class FCntTracker:
    """
    Frame-counter reset (MBW-105), per (family, DevAddr), LRU 8,192.

    Fires when a DevAddr that had climbed above `high` is next seen at or below
    `low`. Rollover guard: the air interface carries only the 16 LSBs of FCnt,
    so 0xFFFF -> 0x0000 is legitimate and a device already near the wrap point
    is never reported, however low the next counter is.
    """

    def __init__(self, low: int = LORA_FCNT_LOW, high: int = LORA_FCNT_HIGH,
                 cap: int = LORA_MAX_DEVADDRS):
        self.low = low
        self.high = high
        self.cap = cap
        self.high_water: "OrderedDict[tuple, int]" = OrderedDict()

    def record(self, family: int, dev_addr: str, fcnt: int) -> int | None:
        """Returns the previous high-water mark when a reset is detected."""
        slot = (family, dev_addr)
        prev = _lru_get(self.high_water, slot)
        if prev is None:
            _lru_put(self.high_water, slot, fcnt, self.cap)
            return None
        if (prev > self.high and fcnt <= self.low
                and prev < LORA_FCNT_ROLLOVER_GUARD):
            _lru_put(self.high_water, slot, fcnt, self.cap)
            return prev
        if fcnt > prev:
            _lru_put(self.high_water, slot, fcnt, self.cap)
        return None
