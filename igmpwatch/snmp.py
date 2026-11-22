"""SNMP poller -- per-interface and per-group multicast data-plane visibility
from the switch, cross-referenced against igmpwatch's own IGMP census.

Why this exists
---------------
The sysfs data-plane sampler (dataplane.py) sees only the mirror port's
aggregate multicast rate -- it cannot attribute a flood to a group or an egress
port. The switch already keeps that per-group / per-interface state; this module
reads it over SNMP and ties it back to the same ``State`` group census the
packet detectors build.

Passive-doctrine note
---------------------
SNMP polling is *out-of-band management-plane* I/O to the switch's management
address. It sends **nothing** on the mirrored segment, transmits no IGMP, joins
no group, and never becomes the reconnaissance signature the packet detectors
look for. It is therefore consistent with the passive doctrine, but it is still
network I/O that needs credentials and a reachable management IP, so it is
**disabled by default** and must be turned on explicitly.

Transport is pluggable. The default client shells out to net-snmp
(``snmpbulkwalk``) so there is no fragile Python SNMP dependency on the Pi; if
the binary or the MIB is absent the poller degrades to a silent no-op. The
evaluation logic is pure (``evaluate()``), so the self-test drives it with
injected snapshots -- no switch, no snmp binary, no root.

Default OIDs
------------
Per-interface multicast (IF-MIB ifXTable, 64-bit high-capacity counters):
  ifName              1.3.6.1.2.1.31.1.1.1.1
  ifHCInMulticastPkts 1.3.6.1.2.1.31.1.1.1.2
  ifHCOutMulticastPkts 1.3.6.1.2.1.31.1.1.1.4
Per-group membership (IGMP-STD-MIB igmpCacheTable, indexed by group+ifIndex):
  igmpCacheLastReporter 1.3.6.1.2.1.85.1.2.1.4   (index = <group-ipv4>.<ifIndex>)

L2-only snooping switches vary in which MIB they populate; every OID here is
config-overridable so the operator can point ``group_table_oid`` at a vendor
table (e.g. a dot1q / CISCO-IGMP-SNOOPING equivalent) that still encodes the
group address in the index.
"""
from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .detectors import Alert
from .models import DEFAULT_BENIGN_GROUPS, Severity, in_local_control

OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_IN_MCAST = "1.3.6.1.2.1.31.1.1.1.2"
OID_IF_OUT_MCAST = "1.3.6.1.2.1.31.1.1.1.4"
OID_IGMP_CACHE = "1.3.6.1.2.1.85.1.2.1.4"   # igmpCacheLastReporter


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------
class NetSnmpClient:
    """Walks OIDs by shelling out to net-snmp's ``snmpbulkwalk``.

    Returns a dict of {index_suffix: value_str} for a walk, or None if the
    query could not be completed (binary missing, timeout, auth failure, MIB
    unsupported). Never raises to the caller.
    """

    def __init__(self, cfg_snmp: dict):
        self.c = cfg_snmp
        self._binary_missing = False

    def _argv(self, oid: str) -> List[str]:
        c = self.c
        prog = "snmpbulkwalk"
        if c.get("snmp_bin_dir"):
            prog = c["snmp_bin_dir"].rstrip("/") + "/" + prog
        argv = [prog, "-Oqn", "-t", str(c.get("timeout", 2)),
                "-r", str(c.get("retries", 1))]
        ver = str(c.get("version", "2c"))
        if ver in ("1", "2c"):
            argv += ["-v", ver, "-c", c.get("community", "public")]
        else:  # v3
            level = c.get("v3_level", "authPriv")
            argv += ["-v", "3", "-l", level, "-u", c.get("v3_user", "")]
            if level in ("authNoPriv", "authPriv"):
                argv += ["-a", c.get("v3_auth_protocol", "SHA"),
                         "-A", c.get("v3_auth_key", "")]
            if level == "authPriv":
                argv += ["-x", c.get("v3_priv_protocol", "AES"),
                         "-X", c.get("v3_priv_key", "")]
        target = f"{c['host']}:{c.get('port', 161)}"
        argv += [target, oid]
        return argv

    def walk(self, oid: str) -> Optional[Dict[str, str]]:
        if self._binary_missing or not self.c.get("host"):
            return None
        try:
            proc = subprocess.run(
                self._argv(oid), capture_output=True, text=True,
                timeout=self.c.get("timeout", 2) * (self.c.get("retries", 1) + 2) + 5,
            )
        except FileNotFoundError:
            if not self._binary_missing:
                sys.stderr.write("[snmp] snmpbulkwalk not found; install net-snmp "
                                 "or disable snmp. SNMP polling off.\n")
            self._binary_missing = True
            return None
        except (subprocess.TimeoutExpired, OSError):
            return None
        if proc.returncode != 0:
            return None
        out: Dict[str, str] = {}
        base = "." + oid if not oid.startswith(".") else oid
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            raw_oid, value = parts[0], parts[1].strip().strip('"')
            if raw_oid.startswith(base + "."):
                suffix = raw_oid[len(base) + 1:]
            elif raw_oid.startswith(oid + "."):
                suffix = raw_oid[len(oid) + 1:]
            else:
                continue
            out[suffix] = value
        return out


# ---------------------------------------------------------------------------
# snapshot model
# ---------------------------------------------------------------------------
@dataclass
class IfaceCounters:
    ifindex: str
    name: str
    in_mcast: int
    out_mcast: int


@dataclass
class SnmpSnapshot:
    ifaces: Dict[str, IfaceCounters] = field(default_factory=dict)
    # group-ip -> {"ifindices": set(str), "reporter": Optional[str]}
    groups: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    group_table_supported: bool = False
    group_walk_skipped: bool = False


def _to_int(s: str) -> Optional[int]:
    try:
        return int(s.strip().split()[0])
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# capability cache -- remember which walks a given switch actually answers
# ---------------------------------------------------------------------------
class CapabilityCache:
    """Per-switch memory of whether the group table is worth walking.

    L2-only platforms often populate ifXTable but return an empty
    igmpCacheTable (no SVI in the VLAN / not the elected querier). Walking it
    every cycle is a wasted SNMP round-trip. This cache records the verdict and
    lets the poller skip that walk -- but never permanently: a ``ttl`` forces a
    periodic re-check so a switch that later gains an SVI or wins the querier
    election is picked back up automatically.

    An empty walk is not trusted on first sight; ``strikes`` consecutive
    reachable-but-empty results are required before a platform is marked
    unsupported. An *unreachable* walk is never a strike -- that's a transport
    problem, not a capability verdict.
    """

    def __init__(self, storage, ttl: float = 3600.0, strikes: int = 3):
        self.storage = storage
        self.ttl = ttl
        self.strikes = strikes

    def group_walk_allowed(self, host: str, now: float) -> bool:
        if self.storage is None or not host:
            return True
        rec = self.storage.get_snmp_capability(host)
        if not rec or rec.get("group_table") is None:
            return True
        if rec["group_table"] == 1:
            return True
        # known-empty: only re-check once the TTL has elapsed
        return (now - (rec.get("checked_at") or 0.0)) >= self.ttl

    def record_group_result(self, host: str, now: float,
                            rows: Optional[int], source: str = "poll") -> None:
        """rows: >0 supported, 0 reachable-but-empty, None unreachable."""
        if self.storage is None or not host or rows is None:
            return
        rec = self.storage.get_snmp_capability(host) or {}
        prev_strikes = rec.get("strikes") or 0
        if rows > 0:
            self.storage.upsert_snmp_capability(host, 1, rows, 0, source, now)
            return
        strikes = prev_strikes + 1
        verdict = 0 if strikes >= self.strikes else None
        self.storage.upsert_snmp_capability(host, verdict, 0, strikes, source, now)

    def verdict(self, host: str) -> Optional[dict]:
        if self.storage is None or not host:
            return None
        return self.storage.get_snmp_capability(host)


def collect_snapshot(client, cfg_snmp: dict, caps: "CapabilityCache | None" = None,
                     now: Optional[float] = None) -> Optional[SnmpSnapshot]:
    """Gather one SNMP snapshot. Returns None if the switch is unreachable."""
    names = client.walk(cfg_snmp.get("if_name_oid", OID_IF_NAME))
    if names is None:
        return None   # unreachable / no transport -> caller no-ops this cycle
    ins = client.walk(cfg_snmp.get("if_in_mcast_oid", OID_IF_IN_MCAST)) or {}
    outs = client.walk(cfg_snmp.get("if_out_mcast_oid", OID_IF_OUT_MCAST)) or {}

    snap = SnmpSnapshot()
    for ifindex, name in names.items():
        i = _to_int(ins.get(ifindex, ""))
        o = _to_int(outs.get(ifindex, ""))
        snap.ifaces[ifindex] = IfaceCounters(
            ifindex=ifindex, name=name,
            in_mcast=i if i is not None else 0,
            out_mcast=o if o is not None else 0,
        )

    host = cfg_snmp.get("host", "")
    now = now if now is not None else time.time()

    # Skip the group walk entirely on platforms already known to answer it
    # empty (re-checked periodically via the cache TTL).
    if caps is not None and not caps.group_walk_allowed(host, now):
        snap.group_walk_skipped = True
        return snap

    grp = client.walk(cfg_snmp.get("group_table_oid", OID_IGMP_CACHE))
    if caps is not None:
        caps.record_group_result(host, now,
                                 None if grp is None else len(grp), "poll")
    if grp is not None:
        snap.group_table_supported = True
        for suffix, reporter in grp.items():
            octs = suffix.split(".")
            if len(octs) < 4:
                continue
            group = ".".join(octs[:4])
            ifidx = octs[4] if len(octs) > 4 else None
            g = snap.groups.setdefault(group, {"ifindices": set(), "reporter": None})
            if ifidx:
                g["ifindices"].add(ifidx)
            if reporter and reporter not in ("0.0.0.0", ""):
                g["reporter"] = reporter
    return snap


# ---------------------------------------------------------------------------
# evaluation (pure)
# ---------------------------------------------------------------------------
@dataclass
class _IfSample:
    in_mcast: int
    out_mcast: int


class SnmpPoller:
    def __init__(self, cfg: dict):
        s = cfg["snmp"]
        self.c = s
        self._last_ts: Optional[float] = None
        self._last_if: Dict[str, _IfSample] = {}
        benign = set(DEFAULT_BENIGN_GROUPS) | set(
            cfg.get("policy", {}).get("benign_groups", []) or [])
        self._benign = benign
        watch = s.get("monitor_ifaces") or []
        self._watch = {str(x) for x in watch}

    def _watched(self, ifc: IfaceCounters) -> bool:
        if not self._watch:
            return True
        return ifc.ifindex in self._watch or ifc.name in self._watch

    def evaluate(self, now: float, snap: Optional[SnmpSnapshot],
                 active_groups: Set[str], known_groups: Set[str],
                 learning: bool) -> List[Alert]:
        if snap is None:
            return []
        out: List[Alert] = []

        # -- per-interface multicast rate ----------------------------------
        prev_ts, self._last_ts = self._last_ts, now
        prev_if, cur_if = self._last_if, {}
        for ifindex, ifc in snap.ifaces.items():
            cur_if[ifindex] = _IfSample(ifc.in_mcast, ifc.out_mcast)
        self._last_if = cur_if

        if prev_ts is not None and now - prev_ts > 0:
            dt = now - prev_ts
            thr = self.c["iface_mcast_pps"]
            for ifindex, ifc in snap.ifaces.items():
                if not self._watched(ifc):
                    continue
                prev = prev_if.get(ifindex)
                if prev is None:
                    continue
                d_in = ifc.in_mcast - prev.in_mcast
                d_out = ifc.out_mcast - prev.out_mcast
                if d_in < 0 or d_out < 0:      # counter reset/wrap -> skip
                    continue
                in_pps = d_in / dt
                out_pps = d_out / dt
                if max(in_pps, out_pps) > thr:
                    out.append(Alert(
                        rule="snmp.iface_mcast_storm",
                        severity=Severity.HIGH,
                        detail={"ifindex": ifindex, "ifname": ifc.name,
                                "in_mcast_pps": round(in_pps, 1),
                                "out_mcast_pps": round(out_pps, 1),
                                "threshold": thr, "window_s": round(dt, 2)},
                    ))

        # -- per-group cross-reference vs igmpwatch census -----------------
        if self.c.get("cross_reference", True) and snap.group_table_supported:
            for group, info in snap.groups.items():
                if in_local_control(group) or group in self._benign:
                    continue
                if (self.c.get("flag_unsubscribed_forwarding", True)
                        and group not in known_groups):
                    out.append(Alert(
                        rule="snmp.unsubscribed_forwarding",
                        severity=Severity.HIGH,
                        detail={"note": "switch forwards a group igmpwatch never "
                                        "saw an IGMP join for",
                                "ifindices": sorted(info.get("ifindices", [])),
                                "last_reporter": info.get("reporter")},
                        group=group, host_ip=info.get("reporter"),
                    ))
            if (self.c.get("flag_census_not_forwarded", False) and not learning):
                switch_groups = set(snap.groups)
                for group in active_groups:
                    if group in self._benign or in_local_control(group):
                        continue
                    if group not in switch_groups:
                        out.append(Alert(
                            rule="snmp.census_not_forwarded",
                            severity=Severity.LOW,
                            detail={"note": "igmpwatch saw a join the switch's "
                                            "group table does not list"},
                            group=group,
                        ))
        return out


# ---------------------------------------------------------------------------
# platform probe -- "which of my target OIDs does this switch answer?"
# ---------------------------------------------------------------------------
def probe(client, cfg_snmp: dict) -> List[Dict[str, Any]]:
    """Walk each target OID once and report responsiveness + a small sample.

    Returns a list of {name, oid, reachable, rows, sample:[(suffix,value)...]}
    so an operator can validate a platform in one shot before relying on the
    cross-reference. Pure w.r.t. formatting; ``client`` does the I/O.
    """
    targets = [
        ("ifName", cfg_snmp.get("if_name_oid", OID_IF_NAME), False),
        ("ifHCInMulticastPkts", cfg_snmp.get("if_in_mcast_oid", OID_IF_IN_MCAST), False),
        ("ifHCOutMulticastPkts", cfg_snmp.get("if_out_mcast_oid", OID_IF_OUT_MCAST), False),
        ("igmpCache (group table)", cfg_snmp.get("group_table_oid", OID_IGMP_CACHE), True),
    ]
    report: List[Dict[str, Any]] = []
    for name, oid, is_group in targets:
        res = client.walk(oid)
        row: Dict[str, Any] = {"name": name, "oid": oid, "is_group": is_group}
        if res is None:
            row.update(reachable=False, rows=0, sample=[])
        else:
            row.update(reachable=True, rows=len(res),
                       sample=list(res.items())[:3])
        report.append(row)
    return report


def _fmt_group_suffix(suffix: str) -> str:
    octs = suffix.split(".")
    if len(octs) >= 4:
        group = ".".join(octs[:4])
        ifidx = octs[4] if len(octs) > 4 else "?"
        return f"{group}@if{ifidx}"
    return suffix


def format_probe(report: List[Dict[str, Any]], cfg_snmp: dict) -> str:
    host = cfg_snmp.get("host", "?")
    ver = cfg_snmp.get("version", "2c")
    lines = [f"igmpwatch SNMP probe -> {host} (v{ver})"]
    any_reach = False
    for r in report:
        tag = " ok " if r["reachable"] else "MISS"
        if r["reachable"]:
            any_reach = True
        sample = ""
        if r["sample"]:
            if r["is_group"]:
                pairs = [f"{_fmt_group_suffix(k)}={v}" for k, v in r["sample"]]
            else:
                pairs = [f"{k}={v}" for k, v in r["sample"]]
            sample = "  e.g. " + ", ".join(pairs)
        lines.append(f"  [{tag}] {r['name']:<24} {r['oid']:<26} "
                     f"{r['rows']:>4} rows{sample}")

    by = {r["name"]: r for r in report}
    grp = next((r for r in report if r["is_group"]), None)
    iface_ok = any(by[n]["reachable"] and by[n]["rows"] > 0
                   for n in ("ifHCInMulticastPkts", "ifHCOutMulticastPkts")
                   if n in by)
    if not any_reach:
        summary = ("Summary: no response. Check host, credentials, version, "
                   "and that the mgmt IP is reachable / SNMP is enabled.")
    elif grp and grp["reachable"] and grp["rows"] > 0:
        summary = ("Summary: per-interface counters + group table both present "
                   "-> full cross-reference available.")
    elif iface_ok:
        summary = ("Summary: per-interface counters present, group table empty "
                   "-> per-port storm detection works; group cross-reference "
                   "unavailable on this platform (try a vendor group_table_oid, "
                   "or rely on the iface + sysfs tiers).")
    else:
        summary = ("Summary: partial response -> verify the OID overrides for "
                   "this platform.")
    lines.append(summary)
    return "\n".join(lines)
