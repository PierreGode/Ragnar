"""The four detection modules.

Every detector exposes ``inspect(ev, state, now) -> list[Alert]`` and is
read-only against shared State. Detector-local state (rate windows, sequence
history) lives inside the detector; segment-wide facts (membership, querier)
live in State.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Tuple

from . import models as M
from .models import IgmpEvent, MsgType, Severity


@dataclass
class Alert:
    rule: str
    severity: Severity
    detail: Dict[str, Any]
    host_mac: str | None = None
    host_ip: str | None = None
    group: str | None = None


class _Window:
    """Sliding-window event counter keyed by an arbitrary hashable."""

    def __init__(self, seconds: float):
        self.seconds = seconds
        self._d: Dict[Any, Deque[float]] = defaultdict(deque)

    def hit(self, key: Any, now: float) -> int:
        dq = self._d[key]
        dq.append(now)
        cutoff = now - self.seconds
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def prune(self, now: float) -> None:
        cutoff = now - self.seconds
        for key in list(self._d):
            dq = self._d[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del self._d[key]


# ---------------------------------------------------------------------------
# 1. Storm / flood
# ---------------------------------------------------------------------------
class FloodDetector:
    def __init__(self, cfg: dict):
        c = cfg["flood"]
        self.c = c
        self.reports = _Window(c["window"])
        self.leaves = _Window(c["window"])
        self.queries = _Window(c["window"])
        self.glob = _Window(c["window"])
        self.flap = _Window(c["window"])            # key=(mac,group) value= J/L stream
        self.flap_state: Dict[Tuple[str, str], str] = {}
        self._fired_glob = -1e9

    def inspect(self, ev: IgmpEvent, state, now: float) -> List[Alert]:
        out: List[Alert] = []
        g = self.glob.hit("all", now)
        if g > self.c["global_rate"] and (now - self._fired_glob) > self.c["window"]:
            self._fired_glob = now
            out.append(Alert(
                "flood.multicast_storm", Severity.HIGH,
                {"igmp_msgs_in_window": g, "window_s": self.c["window"],
                 "threshold": self.c["global_rate"]},
                host_mac=ev.eth_src, host_ip=ev.ip_src,
            ))

        if ev.is_report:
            n = self.reports.hit(ev.eth_src, now)
            if n > self.c["report_rate"]:
                out.append(Alert(
                    "flood.report_storm", Severity.HIGH,
                    {"reports_in_window": n, "threshold": self.c["report_rate"]},
                    host_mac=ev.eth_src, host_ip=ev.ip_src,
                ))
        if ev.msg_type == MsgType.LEAVE or ev.left_groups():
            n = self.leaves.hit(ev.eth_src, now)
            if n > self.c["leave_rate"]:
                out.append(Alert(
                    "flood.leave_storm", Severity.MEDIUM,
                    {"leaves_in_window": n, "threshold": self.c["leave_rate"]},
                    host_mac=ev.eth_src, host_ip=ev.ip_src,
                ))
        if ev.is_query:
            n = self.queries.hit(ev.ip_src, now)
            if n > self.c["query_rate"]:
                out.append(Alert(
                    "flood.query_storm", Severity.HIGH,
                    {"queries_in_window": n, "threshold": self.c["query_rate"]},
                    host_mac=ev.eth_src, host_ip=ev.ip_src,
                ))

        # join/leave flapping per (host, group)
        for group, _ in ev.joined_groups():
            self._flap(out, ev, group, "J", now)
        for group in ev.left_groups():
            self._flap(out, ev, group, "L", now)
        return out

    def _flap(self, out, ev, group, mark, now):
        key = (ev.eth_src, group)
        prev = self.flap_state.get(key)
        self.flap_state[key] = mark
        if prev and prev != mark:
            n = self.flap.hit(key, now)
            if n > self.c["flap_transitions"]:
                out.append(Alert(
                    "flood.join_leave_flap", Severity.MEDIUM,
                    {"transitions_in_window": n, "threshold": self.c["flap_transitions"]},
                    host_mac=ev.eth_src, host_ip=ev.ip_src, group=group,
                ))

    def prune(self, now):
        for w in (self.reports, self.leaves, self.queries, self.glob, self.flap):
            w.prune(now)


# ---------------------------------------------------------------------------
# 2. Anomaly / malformed / downgrade
# ---------------------------------------------------------------------------
class AnomalyDetector:
    def __init__(self, cfg: dict):
        self.c = cfg["anomaly"]

    def inspect(self, ev: IgmpEvent, state, now: float) -> List[Alert]:
        out: List[Alert] = []

        # A non-first fragment carries a message *tail*: there is no IGMP/MLD
        # header in these bytes, so the checksum cannot be computed over them and
        # the message-type/group fields are meaningless. Evaluating content rules
        # here would fire bad_checksum on every fragment tail. The fragmentation
        # itself is still reported (IGMPW-003 in the CVE detector).
        if ev.frag_nonfirst:
            return out

        if not ev.checksum_ok:
            out.append(Alert("anomaly.bad_checksum", Severity.HIGH,
                             {"note": "corrupt or crafted IGMP message"},
                             host_mac=ev.eth_src, host_ip=ev.ip_src, group=ev.group))

        if self.c["require_ttl_1"] and ev.ttl != 1:
            out.append(Alert("anomaly.bad_ttl", Severity.HIGH,
                             {"ttl": ev.ttl, "expected": 1,
                              "note": "off-link injection / spoofed IGMP"},
                             host_mac=ev.eth_src, host_ip=ev.ip_src, group=ev.group))

        # v2/v3 queries must carry the IP Router Alert option
        if self.c["require_router_alert"] and ev.version >= 2 \
                and ev.is_query and not ev.router_alert:
            out.append(Alert("anomaly.no_router_alert", Severity.MEDIUM,
                             {"version": ev.version,
                              "note": "IGMPv2/3 query without IP Router Alert"},
                             host_mac=ev.eth_src, host_ip=ev.ip_src))

        # group-address sanity on reports/leaves
        targets = [g for g, _ in ev.joined_groups()] + ev.left_groups()
        if ev.msg_type in (MsgType.REPORT_V1, MsgType.REPORT_V2, MsgType.LEAVE) and ev.group:
            targets.append(ev.group)
        for grp in set(targets):
            if not M.is_multicast(grp):
                out.append(Alert("anomaly.non_multicast_group", Severity.HIGH,
                                 {"group": grp, "note": "report/leave for non-multicast addr"},
                                 host_mac=ev.eth_src, host_ip=ev.ip_src, group=grp))
            elif grp in M.RESERVED_GROUPS:
                out.append(Alert("anomaly.reserved_group_report", Severity.HIGH,
                                 {"group": grp,
                                  "note": "membership asserted in a non-joinable control group"},
                                 host_mac=ev.eth_src, host_ip=ev.ip_src, group=grp))

        if ev.truncated:
            out.append(Alert("anomaly.truncated_v3", Severity.MEDIUM,
                             {"note": "IGMPv3 numgrp/length mismatch"},
                             host_mac=ev.eth_src, host_ip=ev.ip_src))

        # Non-zero bytes trailing the IGMP message inside the L2 frame. Ordinary
        # frames pad to the 60B minimum with ZEROES, so a non-zero tail (beyond a
        # possible 4-byte FCS, already excluded in decode) is a covert payload
        # smuggled behind a valid advert -- the class of bug that silently drops
        # such bytes instead of surfacing them.
        if self.c.get("flag_trailing_data", True) and ev.trailing_nonzero > 0:
            out.append(Alert("anomaly.trailing_data", Severity.MEDIUM,
                             {"trailing_len": ev.trailing_len,
                              "nonzero_bytes": ev.trailing_nonzero,
                              "note": "non-zero bytes after IGMP message (data smuggled "
                                      "in frame padding)"},
                             host_mac=ev.eth_src, host_ip=ev.ip_src, group=ev.group))

        # version downgrade: v1/v2 query once v3 has been established on-segment
        # (tracked per address family, so IGMP and MLD don't cross-trigger)
        if self.c["flag_downgrade"] and ev.msg_type == MsgType.QUERY_GENERAL \
                and ev.version < 3 and state.segment_version_for(ev.family) >= 3:
            proto = "MLD" if ev.family == 6 else "IGMP"
            out.append(Alert("anomaly.version_downgrade", Severity.HIGH,
                             {"query_version": ev.version,
                              "segment_version": state.segment_version_for(ev.family),
                              "family": ev.family, "protocol": proto,
                              "note": f"possible forced {proto} downgrade (defeats SSM source filtering)"},
                             host_mac=ev.eth_src, host_ip=ev.ip_src))
        return out

    def prune(self, now):  # stateless
        pass


# ---------------------------------------------------------------------------
# 3. Reconnaissance / querier hijack
# ---------------------------------------------------------------------------
class ReconDetector:
    def __init__(self, cfg: dict):
        self.c = cfg["recon"]
        self.scan = _Window(self.c["scan_window"])       # key=src -> distinct groups
        self.scan_groups: Dict[str, Deque] = defaultdict(deque)
        self.query_sources_window = _Window(30)

    def inspect(self, ev: IgmpEvent, state, now: float) -> List[Alert]:
        if not ev.is_query:
            return []
        out: List[Alert] = []

        # querier sourced from the unspecified address -> spoofed / takeover
        if ev.ip_src in ("0.0.0.0", "::"):
            out.append(Alert("recon.spoofed_querier", Severity.HIGH,
                             {"note": "general/group query sourced from the unspecified address",
                              "family": ev.family},
                             host_mac=ev.eth_src, host_ip=ev.ip_src, group=ev.group))

        if ev.msg_type == MsgType.QUERY_GENERAL and not state.learning(now):
            cur = state.current_querier_for(ev.family)
            if cur is None:
                pass
            elif ev.ip_src != cur.ip:
                # New source issuing general queries after baseline.
                sev = Severity.HIGH
                try:
                    import ipaddress
                    lower = ipaddress.ip_address(ev.ip_src) < ipaddress.ip_address(cur.ip)
                except ValueError:
                    lower = False
                rule = "recon.querier_takeover" if lower else "recon.nonquerier_query"
                note = ("lower-IP source would win querier election (hijack)"
                        if lower else "non-querier host issuing general queries (recon)")
                out.append(Alert(rule, sev,
                                 {"observed_querier": cur.ip, "new_source": ev.ip_src,
                                  "note": note},
                                 host_mac=ev.eth_src, host_ip=ev.ip_src))

            # multiple distinct queriers in a short window => contention/spoof
            fam_key = f"{ev.family}:{ev.ip_src}"
            self.query_sources_window.hit(fam_key, now)
            prefix = f"{ev.family}:"
            distinct = len({k for k in self.query_sources_window._d if k.startswith(prefix)})
            if distinct > 1:
                out.append(Alert("recon.querier_contention", Severity.MEDIUM,
                                 {"distinct_query_sources_30s": distinct,
                                  "family": ev.family},
                                 host_mac=ev.eth_src, host_ip=ev.ip_src))

        # group-specific query scanning: one source probing many groups
        if ev.msg_type in (MsgType.QUERY_GROUP, MsgType.QUERY_GROUP_SRC) and ev.group:
            dq = self.scan_groups[ev.ip_src]
            dq.append((ev.group, now))
            cutoff = now - self.c["scan_window"]
            while dq and dq[0][1] < cutoff:
                dq.popleft()
            distinct = len({g for g, _ in dq})
            if distinct >= self.c["scan_distinct_groups"]:
                out.append(Alert("recon.group_scan", Severity.HIGH,
                                 {"distinct_groups": distinct,
                                  "window_s": self.c["scan_window"],
                                  "note": "host enumerating multicast group membership"},
                                 host_mac=ev.eth_src, host_ip=ev.ip_src))
        return out

    def prune(self, now):
        self.scan.prune(now)
        self.query_sources_window.prune(now)
        cutoff = now - self.c["scan_window"]
        for src in list(self.scan_groups):
            dq = self.scan_groups[src]
            while dq and dq[0][1] < cutoff:
                dq.popleft()
            if not dq:
                del self.scan_groups[src]


# ---------------------------------------------------------------------------
# 4. Unauthorized membership / policy
# ---------------------------------------------------------------------------
class PolicyDetector:
    def __init__(self, cfg: dict):
        c = cfg["policy"]
        self.c = c
        self.mode = c["mode"]
        self.allow_link_local = c["allow_link_local"]
        self.benign = set(M.DEFAULT_BENIGN_GROUPS) | set(c.get("benign_groups", []))
        self.sensitive = list(c.get("sensitive_groups", []))
        self.ssm_source_allow = list(c.get("ssm_source_allow", []))
        self.flag_unknown = c.get("flag_unknown_group", True)
        self.rules = c.get("allow", [])

    def _identity_allowed(self, ev: IgmpEvent, group: str) -> bool:
        for rule in self.rules:
            mac = rule.get("mac")
            ip = rule.get("ip")
            if mac and not self._match(ev.eth_src, mac):
                continue
            if ip and not self._match(ev.ip_src, ip):
                continue
            groups = rule.get("groups", [])
            if not groups or M.addr_in_any(group, groups):
                return True
        return False

    @staticmethod
    def _match(value: str, pattern: str) -> bool:
        if pattern.endswith("*"):
            return value.lower().startswith(pattern[:-1].lower())
        return value.lower() == pattern.lower()

    def inspect(self, ev: IgmpEvent, state, now: float) -> List[Alert]:
        out: List[Alert] = []
        for group, sources in ev.joined_groups():
            if self.allow_link_local and M.in_local_control(group):
                continue
            if group in self.benign:
                continue

            first_seen = not state.is_known_group(group)
            explicitly_allowed = self._identity_allowed(ev, group)

            # sensitive groups: any non-allowed join is flagged, even in learn mode
            if M.addr_in_any(group, self.sensitive) and not explicitly_allowed:
                out.append(Alert("policy.sensitive_group_join", Severity.HIGH,
                                 {"group": group, "sources": sources,
                                  "note": "join to a sensitive/restricted group"},
                                 host_mac=ev.eth_src, host_ip=ev.ip_src, group=group))

            # SSM source-list policy (IPv4 232.0.0.0/8, IPv6 ff3x::/32)
            if M.addr_in_any(group, ["232.0.0.0/8", "ff30::/12"]) \
                    and sources and self.ssm_source_allow:
                for s in sources:
                    if not M.addr_in_any(s, self.ssm_source_allow):
                        out.append(Alert("policy.ssm_source_denied", Severity.MEDIUM,
                                         {"group": group, "source": s,
                                          "note": "SSM source outside allowed set"},
                                         host_mac=ev.eth_src, host_ip=ev.ip_src, group=group))

            if self.mode == "enforce":
                if not explicitly_allowed and not state.host_has_group(ev.eth_src, group):
                    out.append(Alert("policy.unauthorized_join", Severity.HIGH,
                                     {"group": group,
                                      "note": "host joined a group not in its allowlist/baseline"},
                                     host_mac=ev.eth_src, host_ip=ev.ip_src, group=group))
            elif first_seen and self.flag_unknown:
                out.append(Alert("policy.new_group", Severity.INFO,
                                 {"group": group, "note": "first observation of this group (baseline)"},
                                 host_mac=ev.eth_src, host_ip=ev.ip_src, group=group))
        return out

    def prune(self, now):
        pass


# ---------------------------------------------------------------------------
# CVE-specific detectors
# ---------------------------------------------------------------------------
# Each rule keys on a wire-observable artifact of the malformation, not on the
# memory-safety outcome. A hit means "a packet matching the documented trigger
# shape crossed this segment" -- it does NOT confirm the target is unpatched or
# that exploitation succeeded. Detection is per-malformation-class and runs on
# BOTH address families regardless of which family the CVE was filed under.

# Valid IGMPv3 / MLDv2 group record types (RFC 3376 §4.2.12, RFC 3810 §5.2.12).
VALID_RECORD_TYPES = {M.GR_IS_IN, M.GR_IS_EX, M.GR_TO_IN,
                      M.GR_TO_EX, M.GR_ALLOW, M.GR_BLOCK}


class CveDetector:
    """Passive detection of documented multicast-membership CVE trigger shapes."""

    def __init__(self, cfg: dict):
        self.c = cfg.get("cve", {})

    def inspect(self, ev: IgmpEvent, state, now: float) -> List[Alert]:
        out: List[Alert] = []
        proto = "MLDv2" if ev.family == 6 else "IGMPv3"

        # -- IGMPW-001 / CVE-2025-50681 --------------------------------------
        # igmpproxy 0.4 < 2b30c36: a membership report carrying an out-of-range
        # group record type reaches inet_fmtsrc() and NULL-derefs. Valid types
        # are 1-6; anything else is the trigger shape. Checked on IGMPv3 and
        # MLDv2 reports alike.
        if self.c.get("flag_invalid_record_type", True) and ev.msg_type == MsgType.REPORT_V3:
            bad = sorted({r.rtype for r in ev.records
                          if r.rtype not in VALID_RECORD_TYPES})
            if bad:
                out.append(Alert(
                    "cve.invalid_record_type", Severity.HIGH,
                    {"code": "IGMPW-001", "cve": "CVE-2025-50681", "cvss": 7.5,
                     "protocol": proto, "family": ev.family,
                     "invalid_rtypes": bad, "valid_range": "1-6",
                     "note": "membership report with out-of-range group record type "
                             "(igmpproxy recv_igmp() NULL-deref trigger shape)"},
                    host_mac=ev.eth_src, host_ip=ev.ip_src, group=ev.group))

        # -- IGMPW-002 / CVE-2026-53275 --------------------------------------
        # Linux ipv6/mcast: a query whose declared source count implies more
        # bytes than the packet carries forces the pskb_may_pull() path that
        # reallocates the skb, after which a stale group-address pointer is
        # dereferenced. The observable is the length/source-count inconsistency.
        # Same check applies to IGMPv3 queries (numsrc * 4).
        if self.c.get("flag_query_source_overrun", True) and ev.is_query \
                and ev.declared_numsrc > 0 \
                and ev.declared_msg_len > ev.actual_msg_len:
            out.append(Alert(
                "cve.query_source_overrun", Severity.HIGH,
                {"code": "IGMPW-002", "cve": "CVE-2026-53275", "cvss": 8.8,
                 "protocol": proto, "family": ev.family,
                 "declared_numsrc": ev.declared_numsrc,
                 "declared_msg_len": ev.declared_msg_len,
                 "actual_msg_len": ev.actual_msg_len,
                 "note": "query declares more sources than the packet carries "
                         "(header-pull/realloc stress; kernel MLD UAF trigger shape)"},
                host_mac=ev.eth_src, host_ip=ev.ip_src, group=ev.group))

        # -- IGMPW-003 / CVE-2019-5608 ---------------------------------------
        # FreeBSD ICMPv6 input mishandles an MLDv2 listener query split across
        # mbufs -> OOB read/write. IGMP and MLD are link-local control traffic
        # with a fixed small footprint; a fragmented membership message is never
        # conformant and is the reassembly-stress trigger shape on both families.
        if self.c.get("flag_fragmented_membership", True) and ev.fragmented:
            out.append(Alert(
                "cve.fragmented_membership", Severity.HIGH,
                {"code": "IGMPW-003", "cve": "CVE-2019-5608", "cvss": 9.8,
                 "protocol": "MLD" if ev.family == 6 else "IGMP",
                 "family": ev.family, "msg_type": ev.msg_type.name,
                 "note": "fragmented multicast membership message; never conformant, "
                         "stresses reassembly/mbuf handling"},
                host_mac=ev.eth_src, host_ip=ev.ip_src, group=ev.group))

        return out

    def prune(self, now: float) -> None:
        return None


class PostureDetector:
    """Protocol-conformance posture, not CVEs. Rules here flag configurations
    and behaviours that are non-conformant and weaken the multicast security
    model, whether the cause is legacy gear or a deliberate downgrade."""

    def __init__(self, cfg: dict):
        self.c = cfg.get("posture", {})

    def inspect(self, ev: IgmpEvent, state, now: float) -> List[Alert]:
        out: List[Alert] = []

        # -- IGMPW-P01: pre-v3 membership in the SSM range (RFC 4604) --------
        # SSM (IPv4 232/8, IPv6 ff3x::/32) requires IGMPv3 / MLDv2, because only
        # those versions carry the source list that makes delivery source-specific
        # (RFC 4604 s2.2.1 / s3). An IGMPv2 or MLDv1 report or leave naming an SSM
        # group asserts ASM-style any-source membership in a range where no source
        # filter can be expressed. A router honouring it delivers traffic from ANY
        # source to that group -- which is the downgrade an attacker wants, and is
        # also what legacy/misconfigured stacks do by accident. Either way the
        # source filtering the operator believes is in force is not in force.
        if self.c.get("flag_ssm_version_mismatch", True) \
                and ev.version < 3 \
                and ev.msg_type in (MsgType.REPORT_V1, MsgType.REPORT_V2, MsgType.LEAVE) \
                and ev.group and M.in_ssm_range(ev.group):
            proto = "MLDv1" if ev.family == 6 else f"IGMPv{ev.version}"
            need = "MLDv2" if ev.family == 6 else "IGMPv3"
            rng = "ff3x::/32" if ev.family == 6 else "232.0.0.0/8"
            out.append(Alert(
                "posture.ssm_version_mismatch", Severity.MEDIUM,
                {"code": "IGMPW-P01", "rfc": "RFC 4604",
                 "observed_version": proto, "required_version": need,
                 "ssm_range": rng, "family": ev.family,
                 "msg_type": ev.msg_type.name,
                 "note": f"{proto} membership in the SSM range {rng}; RFC 4604 "
                         f"requires {need}. No source filter can be expressed, so "
                         f"the group is treated as any-source."},
                host_mac=ev.eth_src, host_ip=ev.ip_src, group=ev.group))

        return out

    def prune(self, now: float) -> None:
        return None
