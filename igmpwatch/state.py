"""Shared, persisted state that detectors read and the pipeline updates.

Design note: detectors are *read-only* against this state. The pipeline calls
``apply()`` after all detectors have run, so e.g. the recon detector can compare
an incoming query against the *previous* querier before the querier is updated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple

from .models import IgmpEvent, MsgType


@dataclass
class Membership:
    mac: str
    ip: Optional[str]
    version: int
    sources: list
    first_seen: float
    last_seen: float


@dataclass
class QuerierInfo:
    ip: str
    mac: Optional[str]
    version: int
    first_seen: float
    last_seen: float


class State:
    def __init__(self, storage, learning_period: float, now: float):
        self.storage = storage
        self.learning_period = learning_period
        self.started = now

        # group -> mac -> Membership
        self.memberships: Dict[str, Dict[str, Membership]] = {}
        # mac -> set(groups) ever seen (baseline)
        self.host_groups: Dict[str, Set[str]] = storage.load_host_groups()
        self.host_ip: Dict[str, str] = {}
        # groups ever observed on the segment
        self.known_groups: Set[str] = set()
        for g in self.memberships:
            self.known_groups.add(g)

        self.current_querier: Dict[int, QuerierInfo] = {}       # family -> elected
        self.queriers: Dict[int, Dict[str, QuerierInfo]] = {4: {}, 6: {}}
        self.segment_version: Dict[int, int] = {4: 0, 6: 0}      # highest version per family

    # -- lifecycle ----------------------------------------------------------
    def learning(self, now: float) -> bool:
        return (now - self.started) < self.learning_period

    def segment_version_for(self, fam: int) -> int:
        return self.segment_version.get(fam, 0)

    def current_querier_for(self, fam: int) -> Optional[QuerierInfo]:
        return self.current_querier.get(fam)

    # -- queries used by detectors -----------------------------------------
    def is_known_group(self, group: str) -> bool:
        return group in self.known_groups

    def host_has_group(self, mac: str, group: str) -> bool:
        return group in self.host_groups.get(mac, set())

    def active_data_group_count(self) -> int:
        """Groups with at least one live membership, excluding 224.0.0.0/24
        link-local control (mDNS/LLMNR/etc). This is the subscriber census the
        data-plane sampler cross-references a multicast byte/packet storm
        against: heavy multicast with zero subscribed data groups means traffic
        is being flooded to groups nobody joined (snooping failure / injection).
        """
        from .models import in_local_control
        n = 0
        for group, macs in self.memberships.items():
            if macs and not in_local_control(group):
                n += 1
        return n

    def active_group_set(self) -> set:
        """Set of data groups (excluding 224.0.0.0/24) with a live membership."""
        from .models import in_local_control
        return {g for g, macs in self.memberships.items()
                if macs and not in_local_control(g)}

    def known_group_set(self) -> set:
        """Every group igmpwatch has ever observed IGMP for (data groups only)."""
        from .models import in_local_control
        return {g for g in self.known_groups if not in_local_control(g)}

    # -- mutation (pipeline only) ------------------------------------------
    def apply(self, ev: IgmpEvent) -> None:
        if ev.version > self.segment_version.get(ev.family, 0):
            self.segment_version[ev.family] = ev.version

        # host baseline
        self.host_ip[ev.eth_src] = ev.ip_src
        hg = self.host_groups.setdefault(ev.eth_src, set())

        for group, sources in ev.joined_groups():
            self.known_groups.add(group)
            hg.add(group)
            gt = self.memberships.setdefault(group, {})
            m = gt.get(ev.eth_src)
            if m:
                m.last_seen = ev.ts
                m.ip = ev.ip_src
                m.version = ev.version
                m.sources = sources
            else:
                gt[ev.eth_src] = Membership(
                    ev.eth_src, ev.ip_src, ev.version, sources, ev.ts, ev.ts
                )
            self.storage.upsert_membership(
                group, ev.eth_src, ev.ip_src, ev.version, sources, ev.ts
            )

        for group in ev.left_groups():
            gt = self.memberships.get(group)
            if gt and ev.eth_src in gt:
                del gt[ev.eth_src]
                self.storage.delete_membership(group, ev.eth_src)

        self.storage.upsert_host(ev.eth_src, ev.ip_src, ev.ts, hg)

        if ev.msg_type == MsgType.QUERY_GENERAL:
            self._apply_querier(ev)

    def _apply_querier(self, ev: IgmpEvent) -> None:
        fam = ev.family
        bucket = self.queriers.setdefault(fam, {})
        info = bucket.get(ev.ip_src)
        if info:
            info.last_seen = ev.ts
            info.mac = ev.eth_src
            info.version = ev.version
        else:
            info = QuerierInfo(ev.ip_src, ev.eth_src, ev.version, ev.ts, ev.ts)
            bucket[ev.ip_src] = info

        # Elected querier (per family) = lowest source IP seen sending general queries.
        cur = self.current_querier.get(fam)
        become_current = False
        if cur is None:
            become_current = True
        else:
            try:
                import ipaddress
                if ipaddress.ip_address(ev.ip_src) <= ipaddress.ip_address(cur.ip):
                    become_current = True
            except ValueError:
                pass
        if become_current:
            self.current_querier[fam] = info
        self.storage.upsert_querier(
            ev.ip_src, ev.eth_src, ev.version, ev.ts,
            is_current=(self.current_querier.get(fam) is info),
        )

    # -- maintenance --------------------------------------------------------
    def prune(self, older_than: float) -> None:
        for group in list(self.memberships):
            gt = self.memberships[group]
            for mac in list(gt):
                if gt[mac].last_seen < older_than:
                    del gt[mac]
            if not gt:
                del self.memberships[group]
        self.storage.prune_memberships(older_than)
