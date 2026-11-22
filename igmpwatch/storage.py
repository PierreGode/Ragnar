"""SQLite persistence. Shares the same DB conventions as the rest of the suite
so events can be correlated with macwatch / arp_guard / dns detections.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any, Dict, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    rule      TEXT NOT NULL,
    severity  INTEGER NOT NULL,
    host_mac  TEXT,
    host_ip   TEXT,
    grp       TEXT,
    detail    TEXT,
    count     INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_rule ON events(rule);

CREATE TABLE IF NOT EXISTS memberships (
    grp        TEXT NOT NULL,
    host_mac   TEXT NOT NULL,
    host_ip    TEXT,
    version    INTEGER,
    sources    TEXT,
    first_seen REAL,
    last_seen  REAL,
    PRIMARY KEY (grp, host_mac)
);

CREATE TABLE IF NOT EXISTS queriers (
    ip         TEXT PRIMARY KEY,
    mac        TEXT,
    version    INTEGER,
    first_seen REAL,
    last_seen  REAL,
    is_current INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hosts (
    host_mac   TEXT PRIMARY KEY,
    host_ip    TEXT,
    first_seen REAL,
    last_seen  REAL,
    groups     TEXT
);

-- Per-switch SNMP capability verdicts, so the poller can skip walks a given
-- platform never answers (e.g. L2-only gear with no igmpCacheTable).
CREATE TABLE IF NOT EXISTS snmp_capabilities (
    host        TEXT PRIMARY KEY,
    group_table INTEGER,      -- 1 supported / 0 known-empty / NULL unknown
    group_rows  INTEGER,      -- rows seen on the last successful walk
    strikes     INTEGER DEFAULT 0,   -- consecutive reachable-but-empty walks
    source      TEXT,         -- 'probe' | 'poll'
    checked_at  REAL,
    first_seen  REAL,
    last_seen   REAL
);
"""


class Storage:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(path), exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.OperationalError:
            pass
        self.db.commit()

    # -- events -------------------------------------------------------------
    def record_event(self, ts: float, rule: str, severity: int,
                      host_mac: Optional[str], host_ip: Optional[str],
                      group: Optional[str], detail: Dict[str, Any],
                      count: int = 1) -> None:
        self.db.execute(
            "INSERT INTO events(ts,rule,severity,host_mac,host_ip,grp,detail,count) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (ts, rule, int(severity), host_mac, host_ip, group,
             json.dumps(detail, separators=(",", ":")), count),
        )
        self.db.commit()

    # -- membership ---------------------------------------------------------
    def upsert_membership(self, group: str, mac: str, ip: Optional[str],
                          version: int, sources, ts: float) -> None:
        self.db.execute(
            "INSERT INTO memberships(grp,host_mac,host_ip,version,sources,first_seen,last_seen) "
            "VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(grp,host_mac) DO UPDATE SET "
            "host_ip=excluded.host_ip, version=excluded.version, "
            "sources=excluded.sources, last_seen=excluded.last_seen",
            (group, mac, ip, version, json.dumps(sources or []), ts, ts),
        )
        self.db.commit()

    def delete_membership(self, group: str, mac: str) -> None:
        self.db.execute("DELETE FROM memberships WHERE grp=? AND host_mac=?", (group, mac))
        self.db.commit()

    def prune_memberships(self, older_than: float) -> int:
        cur = self.db.execute("DELETE FROM memberships WHERE last_seen < ?", (older_than,))
        self.db.commit()
        return cur.rowcount

    # -- querier ------------------------------------------------------------
    def upsert_querier(self, ip: str, mac: Optional[str], version: int,
                       ts: float, is_current: bool) -> None:
        if is_current:
            self.db.execute("UPDATE queriers SET is_current=0")
        self.db.execute(
            "INSERT INTO queriers(ip,mac,version,first_seen,last_seen,is_current) "
            "VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac, version=excluded.version, "
            "last_seen=excluded.last_seen, is_current=excluded.is_current",
            (ip, mac, version, ts, ts, 1 if is_current else 0),
        )
        self.db.commit()

    # -- hosts --------------------------------------------------------------
    def upsert_host(self, mac: str, ip: Optional[str], ts: float, groups) -> None:
        self.db.execute(
            "INSERT INTO hosts(host_mac,host_ip,first_seen,last_seen,groups) "
            "VALUES(?,?,?,?,?) "
            "ON CONFLICT(host_mac) DO UPDATE SET host_ip=excluded.host_ip, "
            "last_seen=excluded.last_seen, groups=excluded.groups",
            (mac, ip, ts, ts, json.dumps(sorted(groups))),
        )
        self.db.commit()

    def load_host_groups(self) -> Dict[str, set]:
        out: Dict[str, set] = {}
        for row in self.db.execute("SELECT host_mac,groups FROM hosts"):
            try:
                out[row["host_mac"]] = set(json.loads(row["groups"] or "[]"))
            except json.JSONDecodeError:
                out[row["host_mac"]] = set()
        return out

    # -- snmp capabilities --------------------------------------------------
    def get_snmp_capability(self, host: str) -> Optional[Dict[str, Any]]:
        row = self.db.execute(
            "SELECT * FROM snmp_capabilities WHERE host=?", (host,)).fetchone()
        return dict(row) if row else None

    def upsert_snmp_capability(self, host: str, group_table: Optional[int],
                               group_rows: int, strikes: int, source: str,
                               ts: float) -> None:
        self.db.execute(
            "INSERT INTO snmp_capabilities("
            "host,group_table,group_rows,strikes,source,checked_at,first_seen,last_seen) "
            "VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(host) DO UPDATE SET group_table=excluded.group_table, "
            "group_rows=excluded.group_rows, strikes=excluded.strikes, "
            "source=excluded.source, checked_at=excluded.checked_at, "
            "last_seen=excluded.last_seen",
            (host, group_table, group_rows, strikes, source, ts, ts, ts),
        )
        self.db.commit()

    def close(self):
        self.db.close()
