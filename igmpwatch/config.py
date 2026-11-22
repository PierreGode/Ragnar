"""Configuration: sane defaults merged with an optional YAML file."""
from __future__ import annotations

import copy
from typing import Any, Dict

try:
    import yaml  # PyYAML
except ImportError:  # pragma: no cover
    yaml = None

DEFAULTS: Dict[str, Any] = {
    "interface": "eth0",           # SPAN/mirror destination NIC
    "db_path": "/var/lib/igmpwatch/igmpwatch.db",
    "log_path": "/var/log/igmpwatch/events.jsonl",
    "membership_timeout": 300,     # s before an un-refreshed join is aged out
    "learning_period": 180,        # s to baseline querier/membership before enforcing

    "posture": {
        "flag_ssm_version_mismatch": True,   # IGMPW-P01 / RFC 4604
    },

    "cve": {
        "flag_invalid_record_type": True,    # IGMPW-001 / CVE-2025-50681
        "flag_query_source_overrun": True,   # IGMPW-002 / CVE-2026-53275
        "flag_fragmented_membership": True,  # IGMPW-003 / CVE-2019-5608
    },

    "mld": {
        "enable": True,            # also decode IPv6 MLD (ICMPv6) alongside IGMP
    },
    "capture_filter": "",          # optional BPF override; empty = auto (IGMP [+ MLD])

    "flood": {
        "window": 10,              # sliding window seconds
        "report_rate": 40,         # reports per source per window
        "leave_rate": 30,          # leaves per source per window
        "query_rate": 8,           # queries per source per window
        "global_rate": 300,        # total IGMP msgs per window (segment-wide)
        "flap_transitions": 8,     # join<->leave toggles per (host,group) per window
    },

    "anomaly": {
        "require_router_alert": True,   # flag v2/v3 without Router Alert option
        "require_ttl_1": True,          # IGMP must be TTL 1 (link-local)
        "flag_downgrade": True,         # v1/v2 query after v3 established
        "flag_trailing_data": True,     # non-zero bytes smuggled in frame padding
    },

    "recon": {
        "scan_distinct_groups": 6,      # group-specific queries to N groups / window
        "scan_window": 15,
        "alert_nonquerier_query": True, # any general query not from the elected querier
    },

    "policy": {
        "mode": "learn",                # "learn" | "enforce"
        "allow_link_local": True,       # 224.0.0.0/24 joins are normal, don't alert
        "benign_groups": [],            # extra groups to treat as always-allowed
        "sensitive_groups": [],         # any join here alerts unless host is allowed
        "allow": [],                    # list of {mac|ip, groups:[...]} rules
        "flag_unknown_group": True,     # first-seen group on the segment -> INFO
        "ssm_source_allow": [],         # optional allowed SSM source CIDRs
    },

    "alerting": {
        "cooldown": 60,                 # s to suppress duplicate (rule,host,group)
        "min_severity": "LOW",
        "stdout": True,
    },

    "dataplane": {
        "enable": True,           # sample NIC counters and cross-ref against joined groups
        "interval": 5,            # s between /sys counter samples
        "mcast_pps": 2000,        # received multicast pps over this -> storm (HIGH)
        "mcast_pps_floor": 150,   # multicast pps over this WHILE no data groups joined -> flood
        "members_floor": 1,       # "no members" = fewer than this many active data groups
        "rx_drop_pps": 100,       # rx_dropped delta/s over this -> capture loss / storm symptom
        "mcast_ratio": 0.9,       # multicast fraction of rx over this (with ratio_min_pps) -> alert
        "ratio_min_pps": 500,     # only evaluate the ratio above this total rx pps
    },

    "snmp": {
        "enable": False,          # OFF by default: needs switch creds + reachable mgmt IP
        "host": "",               # switch management IP / hostname
        "port": 161,
        "version": "2c",          # "1" | "2c" | "3"
        "community": "public",    # v1/v2c community
        "v3_user": "",            # v3 credentials (used when version == "3")
        "v3_level": "authPriv",   # noAuthNoPriv | authNoPriv | authPriv
        "v3_auth_protocol": "SHA",
        "v3_auth_key": "",
        "v3_priv_protocol": "AES",
        "v3_priv_key": "",
        "timeout": 2,             # per-request seconds
        "retries": 1,
        "interval": 30,           # s between polls (SNMP is heavier than sysfs)
        "snmp_bin_dir": "",       # optional dir holding snmpbulkwalk
        "iface_mcast_pps": 3000,  # per-interface in/out multicast pps -> storm (HIGH)
        "monitor_ifaces": [],     # optional ifName/ifIndex whitelist (empty = all)
        "cross_reference": True,  # compare switch group table vs igmpwatch census
        "cache_capabilities": True,   # remember which walks a switch answers
        "capability_ttl": 3600,       # s before re-checking a "known empty" group table
        "capability_strikes": 3,      # consecutive empty walks before marking unsupported
        "flag_unsubscribed_forwarding": True,   # switch forwards a group we never saw join
        "flag_census_not_forwarded": False,     # noisier: we saw a join the switch doesn't list
        # OID overrides for non-standard platforms (defaults in snmp.py):
        "if_name_oid": "1.3.6.1.2.1.31.1.1.1.1",
        "if_in_mcast_oid": "1.3.6.1.2.1.31.1.1.1.2",
        "if_out_mcast_oid": "1.3.6.1.2.1.31.1.1.1.4",
        "group_table_oid": "1.3.6.1.2.1.85.1.2.1.4",
    },
}


def _deep_merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path: str | None) -> Dict[str, Any]:
    if not path:
        return copy.deepcopy(DEFAULTS)
    if yaml is None:
        raise RuntimeError("PyYAML not installed but a config file was given")
    with open(path, "r") as fh:
        user = yaml.safe_load(fh) or {}
    return _deep_merge(DEFAULTS, user)
