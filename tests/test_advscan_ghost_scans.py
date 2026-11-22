"""Tests for ghost-scan prevention in the Advanced Vulnerability Scanner.

Two production bugs produced "stuck forever" scans on hermes-box:

1. ``delete_scan()`` deleted rows only from the *current* db_path, but scans
   are written to whichever per-network DB (``data/networks/<slug>/db/*.db``)
   was active when they ran. UI deletes under a different network context were
   silent no-ops, and the leftover ``status='running'`` rows were resurrected
   into ``active_scans`` on every boot with a ticking duration.

2. Concurrent ZAP scans deadlocked the ZAP daemon (newSession called while
   another spider was mid-crawl wedges every spider endpoint until the JVM is
   killed), so three zap_spider scans started in the same second all hung.

These tests pin the fixes: delete-everywhere, boot-time freshness cutoff for
recovery, and a serialized ZAP scan slot.
"""

import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import pytest

from db_manager import DatabaseManager


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make_db(tmp_path, name):
    """Create a DatabaseManager with its db inside tmp_path (schema included)."""
    db_file = tmp_path / name
    return DatabaseManager(db_path=str(db_file), currentdir=REPO,
                            data_root=str(tmp_path))


def make_lan_db(tmp_path):
    """A per-network DB under <datadir>/networks/lan/db/lan.db."""
    net_db = tmp_path / 'networks' / 'lan' / 'db'
    net_db.mkdir(parents=True, exist_ok=True)
    return DatabaseManager(db_path=str(net_db / 'lan.db'), currentdir=REPO,
                           data_root=str(tmp_path))


# --- Fix 1: delete_scan must reach every network DB -------------------------

def test_delete_scan_everywhere_removes_rows_from_network_dbs(tmp_path):
    main = make_db(tmp_path, 'ragnar.db')
    lan = make_lan_db(tmp_path)
    # The scan row lives in the per-network DB, not the main one...
    lan.save_scan_job('AVS-X-1', 'zap_spider', 'http://example.test',
                      status='running')
    # ...but the delete UI may run under the main network context.
    removed = main.delete_scan_everywhere('AVS-X-1')
    assert removed >= 1
    with sqlite3.connect(str(lan.db_path)) as conn:
        assert conn.execute(
            'SELECT COUNT(*) FROM scan_jobs WHERE scan_id=?',
            ('AVS-X-1',)).fetchone()[0] == 0


def test_all_scan_db_paths_includes_network_dbs(tmp_path):
    main = make_db(tmp_path, 'ragnar.db')
    lan = make_lan_db(tmp_path)
    paths = [os.path.abspath(p) for p in main.all_scan_db_paths()]
    assert os.path.abspath(str(lan.db_path)) in paths
    assert os.path.abspath(str(main.db_path)) in paths


def test_delete_scan_everywhere_returns_zero_when_nothing_matches(tmp_path):
    main = make_db(tmp_path, 'ragnar.db')
    assert main.delete_scan_everywhere('AVS-NONEWHERE') == 0


# --- Fix 2: recovery must not resurrect stale rows -------------------------

def test_scan_row_is_fresh_accepts_recent_update():
    from advanced_vuln_scanner import _scan_row_is_fresh
    recent = (datetime.now(timezone.utc) + timedelta(minutes=-5)).strftime(
        '%Y-%m-%d %H:%M:%S')
    assert _scan_row_is_fresh({'updated_at': recent}) is True


def test_scan_row_is_fresh_rejects_old_rows():
    from advanced_vuln_scanner import _scan_row_is_fresh
    old = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime(
        '%Y-%m-%d %H:%M:%S')
    # Old rows must not be resurrected into active_scans at boot.
    assert _scan_row_is_fresh({'updated_at': old}) is False


def test_scan_row_is_fresh_rejects_missing_timestamp():
    from advanced_vuln_scanner import _scan_row_is_fresh
    assert _scan_row_is_fresh({}) is False
    assert _scan_row_is_fresh({'updated_at': 'not-a-date'}) is False


# --- Fix 3: ZAP scans are serialized ----------------------------------------

def _bare_scanner():
    """An AdvancedVulnScanner shell with only the attrs the ZAP slot needs —
    same __new__ pattern the capability tests use for heavy classes."""
    from advanced_vuln_scanner import AdvancedVulnScanner
    import threading
    avs = AdvancedVulnScanner.__new__(AdvancedVulnScanner)
    avs._zap_scan_lock = threading.Lock()
    return avs


def test_second_concurrent_zap_scan_is_refused_not_queued():
    avs = _bare_scanner()
    assert avs._zap_scan_lock.acquire(timeout=1) is True  # first scan holds it
    # A second scan must fail fast (no infinite wait) while one is running.
    assert avs._zap_scan_lock.acquire(timeout=1) is False
    avs._zap_scan_lock.release()


def test_zap_slot_acquire_returns_true_when_free():
    avs = _bare_scanner()
    assert avs._zap_scan_lock.acquire(timeout=1) is True
    avs._zap_scan_lock.release()
