"""Data-plane rate sampler.

The IGMP detectors watch the multicast *control plane* (joins, leaves,
queries). This module closes the loop on the *data plane*: it reads the NIC's
own kernel counters from ``/sys/class/net/<iface>/statistics`` at an interval,
turns them into rates, and cross-references those rates against the live
IGMP-subscribed group census that ``State`` maintains.

Still passive: it only *reads* sysfs counters that the kernel already keeps for
frames the mirror delivered. It transmits nothing and opens no network handle.

The kernel counters are segment-level, not per-group (per-group data-plane
accounting isn't exposed in sysfs), so the cross-reference is: a sustained
multicast packet rate while *no data groups are subscribed* means multicast is
being flooded to groups nobody joined -- an unregistered-multicast flood, a
switch snooping failure, or injected traffic. That's the signal that a
control-plane-only view misses.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .detectors import Alert
from .models import Severity

_COUNTERS = ("rx_bytes", "rx_packets", "multicast", "rx_dropped")


def read_sysfs_counters(iface: str) -> Optional[Dict[str, int]]:
    """Read the RX counters for ``iface``. Returns None if unavailable.

    ``multicast`` is the kernel's count of received multicast packets;
    ``rx_dropped`` rising indicates the ring buffer / capture path is losing
    frames, which is itself a storm symptom.
    """
    base = f"/sys/class/net/{iface}/statistics/"
    out: Dict[str, int] = {}
    try:
        for name in _COUNTERS:
            with open(base + name, "r") as fh:
                out[name] = int(fh.read().strip())
    except (OSError, ValueError):
        return None
    return out


@dataclass
class _Sample:
    ts: float
    c: Dict[str, int]


class DataPlaneSampler:
    """Turns successive counter reads into rates and emits data-plane alerts.

    ``sample()`` is pure w.r.t. the outside world: hand it a timestamp, a
    counter dict, and the current active-data-group count, and it returns a
    list of Alerts. The first call (or the first after a counter reset) only
    primes the baseline and returns nothing.
    """

    def __init__(self, cfg: dict):
        d = cfg["dataplane"]
        self.c = d
        self._last: Optional[_Sample] = None

    def sample(self, now: float, counters: Optional[Dict[str, int]],
               active_data_groups: int) -> List[Alert]:
        if counters is None:
            return []
        prev = self._last
        self._last = _Sample(now, counters)
        if prev is None:
            return []

        dt = now - prev.ts
        if dt <= 0:
            return []

        # Counter reset / wrap (iface bounce, 32-bit rollover): re-prime, don't alert.
        if any(counters[k] < prev.c.get(k, 0) for k in _COUNTERS):
            return []

        d_pkts = counters["rx_packets"] - prev.c["rx_packets"]
        d_mcast = counters["multicast"] - prev.c["multicast"]
        d_drop = counters["rx_dropped"] - prev.c["rx_dropped"]

        pps = d_pkts / dt
        mcast_pps = d_mcast / dt
        drop_pps = d_drop / dt

        out: List[Alert] = []

        # 1. Absolute multicast storm on the wire.
        if mcast_pps > self.c["mcast_pps"]:
            out.append(Alert(
                rule="dataplane.mcast_storm",
                severity=Severity.HIGH,
                detail={"mcast_pps": round(mcast_pps, 1),
                        "threshold": self.c["mcast_pps"],
                        "active_data_groups": active_data_groups,
                        "window_s": round(dt, 2)},
            ))
        # 2. Multicast flooding to groups nobody joined (the cross-reference).
        elif (active_data_groups < self.c["members_floor"]
              and mcast_pps > self.c["mcast_pps_floor"]):
            out.append(Alert(
                rule="dataplane.mcast_flood_no_members",
                severity=Severity.HIGH,
                detail={"mcast_pps": round(mcast_pps, 1),
                        "floor": self.c["mcast_pps_floor"],
                        "active_data_groups": active_data_groups,
                        "note": "multicast on the wire with no subscribed data groups",
                        "window_s": round(dt, 2)},
            ))

        # 3. Multicast dominates the link (with a floor so idle links stay quiet).
        if (pps >= self.c["ratio_min_pps"]
                and mcast_pps / pps > self.c["mcast_ratio"]):
            out.append(Alert(
                rule="dataplane.mcast_ratio",
                severity=Severity.MEDIUM,
                detail={"mcast_frac": round(mcast_pps / pps, 3),
                        "threshold": self.c["mcast_ratio"],
                        "pps": round(pps, 1),
                        "window_s": round(dt, 2)},
            ))

        # 4. Capture-path loss -- ring buffer can't keep up (storm symptom).
        if drop_pps > self.c["rx_drop_pps"]:
            out.append(Alert(
                rule="dataplane.rx_drops",
                severity=Severity.MEDIUM,
                detail={"drop_pps": round(drop_pps, 1),
                        "threshold": self.c["rx_drop_pps"],
                        "window_s": round(dt, 2)},
            ))

        return out
