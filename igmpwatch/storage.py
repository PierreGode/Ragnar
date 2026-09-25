"""SQLite persistence — events, memberships, queriers, hosts, snmp_capabilities.

Same DB conventions as the rest of the suite so multicast events correlate with
macwatch / arp_guard / DNS detections on a shared timeline.
"""

import json
import sqlite3
import time

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts REAL, module TEXT, rule TEXT, sev TEXT,
  identity TEXT, grp TEXT, signal TEXT, suppressed INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS memberships (
  grp TEXT, host TEXT, version INTEGER, sources TEXT, last_seen REAL,
  PRIMARY KEY (grp, host));
CREATE TABLE IF NOT EXISTS queriers (
  ip TEXT PRIMARY KEY, mac TEXT, first_seen REAL, last_seen REAL, count INTEGER);
CREATE TABLE IF NOT EXISTS hosts (mac TEXT PRIMARY KEY, first_seen REAL, last_seen REAL);
CREATE TABLE IF NOT EXISTS snmp_capabilities (
  host TEXT PRIMARY KEY, supported INTEGER, strikes INTEGER, ts REAL);
"""


class Storage:
    def __init__(self, path=':memory:'):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(_SCHEMA)
        self.db.commit()

    def record_event(self, alert):
        a = alert.to_dict() if hasattr(alert, 'to_dict') else alert
        self.db.execute(
            'INSERT INTO events (ts, module, rule, sev, identity, grp, signal, suppressed)'
            ' VALUES (?,?,?,?,?,?,?,?)',
            (a['ts'], a['module'], a['rule'], a['sev'], a.get('identity'),
             a.get('group'), a['signal'], a.get('suppressed', 0)))
        self.db.commit()

    def event_count(self):
        return self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]

    def persist_state(self, state):
        now = time.time()
        with state.lock:
            for g, members in state.memberships.items():
                for mac, e in members.items():
                    self.db.execute(
                        'INSERT OR REPLACE INTO memberships (grp, host, version, sources, last_seen)'
                        ' VALUES (?,?,?,?,?)',
                        (g, mac, e.get('version'), json.dumps(sorted(e.get('sources') or [])),
                         e.get('last_seen', now)))
            for ip, q in state.queriers.items():
                self.db.execute(
                    'INSERT OR REPLACE INTO queriers (ip, mac, first_seen, last_seen, count)'
                    ' VALUES (?,?,?,?,?)',
                    (ip, q.get('mac'), q.get('first_seen'), q.get('last_seen'), q.get('count')))
            for mac in state.hosts:
                self.db.execute(
                    'INSERT INTO hosts (mac, first_seen, last_seen) VALUES (?,?,?)'
                    ' ON CONFLICT(mac) DO UPDATE SET last_seen=excluded.last_seen',
                    (mac, now, now))
        self.db.commit()

    # -- SNMP capability cache store (CapabilityCache adapter) ----------------
    def get(self, host):
        row = self.db.execute(
            'SELECT supported, strikes, ts FROM snmp_capabilities WHERE host=?',
            (host,)).fetchone()
        if not row:
            return None
        return {'supported': bool(row[0]), 'strikes': row[1], 'ts': row[2]}

    def set(self, host, rec):
        self.db.execute(
            'INSERT OR REPLACE INTO snmp_capabilities (host, supported, strikes, ts)'
            ' VALUES (?,?,?,?)',
            (host, 1 if rec.get('supported') else 0, rec.get('strikes', 0), rec.get('ts', 0)))
        self.db.commit()

    def close(self):
        self.db.close()
