"""Tests for AdvancedVulnScanner.start_delegated_scan — the relay that makes a
scan running on a mesh peer appear as a normal local scan."""

import threading
import time

from advanced_vuln_scanner import AdvancedVulnScanner, ScanType


def _scanner():
    s = AdvancedVulnScanner.__new__(AdvancedVulnScanner)
    s._lock = threading.Lock()
    s.active_scans = {}
    s.scan_results = {}
    s.scan_history = []
    s._scan_counter = 0
    s._delegated_scans = {}
    s._db = None
    # No-op the persistence + keep findings as-is.
    s._save_scan_to_db = lambda *a, **k: None
    s._save_finding_to_db = lambda *a, **k: None
    s._dict_to_finding = lambda d: d  # keep the dict; identity for the test
    s.DELEGATE_POLL_INTERVAL = 0.01
    return s


def _peer_io(script, findings):
    state = {"i": 0}

    def start():
        return {"success": True, "scan_id": "AVS-remote-1"}

    def status(rid):
        i = min(state["i"], len(script) - 1)
        state["i"] += 1
        return {"reachable": True, "scan": script[i]}

    def findings_fn(rid):
        return {"findings": findings}

    def cancel(rid):
        return {"success": True}

    return {"start": start, "status": status, "findings": findings_fn, "cancel": cancel}


def _wait(s, scan_id, want, tries=300):
    for _ in range(tries):
        p = s.active_scans.get(scan_id)
        if p and p.status == want:
            return p
        time.sleep(0.01)
    return s.active_scans.get(scan_id)


def test_delegated_scan_relays_and_ingests_findings():
    s = _scanner()
    script = [
        {"status": "running", "progress_percent": 30, "findings_count": 0},
        {"status": "running", "progress_percent": 80, "findings_count": 1},
        {"status": "completed", "progress_percent": 100, "findings_count": 1},
    ]
    io = _peer_io(script, [{"severity": "high", "title": "x", "finding_id": "f1"}])
    scan_id = s.start_delegated_scan("http://t", ScanType.NUCLEI, "harald", io)

    # Appears immediately as a normal running scan.
    assert s.active_scans[scan_id].status == "running"
    assert "harald" in s.active_scans[scan_id].current_check

    p = _wait(s, scan_id, "completed")
    assert p.status == "completed"
    assert p.progress_percent == 100
    # Remote findings were pulled into normal scan_results.
    assert len(s.scan_results[scan_id]) == 1
    # Delegated tracking is cleaned up when done.
    assert scan_id not in s._delegated_scans


def test_delegated_scan_start_refused_marks_failed():
    s = _scanner()
    io = _peer_io([{"status": "running"}], [])
    io["start"] = lambda: {"success": False, "error": "peer OOM guard refused"}
    scan_id = s.start_delegated_scan("http://t", ScanType.ZAP_FULL, "ylva", io)
    p = _wait(s, scan_id, "failed")
    assert p.status == "failed"
    assert "refused" in p.error_message
