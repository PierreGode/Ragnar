"""Tests for mesh scan delegation decision logic and the relay orchestrator."""

import time

from mesh_scan import (
    MeshScanDelegator, build_banner, build_roster, capability,
    pick_delegate, required_tool,
)


# --- scanner -> required heavy tool -----------------------------------------

def test_required_tool_mapping():
    assert required_tool("nuclei") == "nuclei"
    assert required_tool("full") == "nuclei"
    assert required_tool("zap_full") == "zap"
    assert required_tool("zap_spider") == "zap"
    assert required_tool("nikto") is None      # light — never delegated
    assert required_tool("whatweb") is None


# --- delegate selection ------------------------------------------------------

def test_pick_delegate_prefers_both_capable_then_ram():
    ylva = capability("ylva", ram_gb=1.0, nuclei=True, zap=False)
    harald = capability("harald", ram_gb=8.0, nuclei=True, zap=True)
    bjorn = capability("bjorn", ram_gb=4.0, nuclei=True, zap=False)
    roster = build_roster([ylva, harald, bjorn])
    # For nuclei, harald wins (can do both), then bjorn (more RAM), then ylva.
    assert pick_delegate(roster, "nuclei")["viking"] == "harald"
    # For zap, only harald qualifies.
    assert pick_delegate(roster, "zap")["viking"] == "harald"


def test_pick_delegate_none_when_no_capable_peer():
    roster = build_roster([capability("ylva", ram_gb=1.0, nuclei=True)])
    assert pick_delegate(roster, "zap") is None


def test_build_roster_drops_incapable_and_unreachable():
    caps = [
        capability("ylva", nuclei=True),
        capability("tiny", nuclei=False, zap=False),        # can't run anything
        capability("gone", nuclei=True, reachable=False),   # offline
    ]
    names = {c["viking"] for c in build_roster(caps)}
    assert names == {"ylva"}


# --- banner: the operator's exact scenarios ---------------------------------

def test_banner_hidden_when_local_can_run_everything():
    b = build_banner({"nuclei": True, "zap": True}, [])
    assert b["show"] is False


def test_banner_none_found():
    # Pi Zero can't run either, and no peer can either.
    b = build_banner({"nuclei": False, "zap": False}, [])
    assert b["show"] is True and b["kind"] == "none"
    assert "no compatible Ragnar" in b["text"]


def test_banner_one_gb_peer_runs_nuclei_only():
    # Local can't run nuclei; ylva (1GB) can, but can't run zap.
    ylva = capability("ylva", ram_gb=1.0, nuclei=True, zap=False)
    b = build_banner({"nuclei": False, "zap": True}, build_roster([ylva]))
    assert b["show"] and b["kind"] == "delegate"
    assert "ylva" in b["text"] and "Nuclei" in b["text"]
    assert b["recommended"]["viking"] == "ylva"


def test_banner_eight_gb_peer_runs_both():
    harald = capability("harald", ram_gb=8.0, nuclei=True, zap=True)
    b = build_banner({"nuclei": False, "zap": False}, build_roster([harald]))
    assert b["show"] and b["kind"] == "delegate"
    assert "harald" in b["text"]
    assert "Nuclei" in b["text"] and "ZAP" in b["text"]
    assert b["recommended"]["viking"] == "harald"
    assert b["delegates"]["nuclei"]["viking"] == "harald"
    assert b["delegates"]["zap"]["viking"] == "harald"


def test_banner_split_across_units():
    # ylva does nuclei, harald does zap; local can do neither.
    ylva = capability("ylva", ram_gb=1.0, nuclei=True, zap=False)
    harald = capability("harald", ram_gb=8.0, nuclei=False, zap=True)
    b = build_banner({"nuclei": False, "zap": False}, build_roster([ylva, harald]))
    assert b["show"] and b["kind"] == "delegate"
    assert "ylva" in b["text"] and "harald" in b["text"]


# --- delegator relay ---------------------------------------------------------

def _fakes(script):
    """Build injected fns; `script` is a list of status dicts returned in order,
    then the last repeats."""
    state = {"i": 0}

    def start_fn(node, target, scan_type, options):
        return {"success": True, "scan_id": "AVS-1"}

    def status_fn(node, remote_id):
        i = min(state["i"], len(script) - 1)
        state["i"] += 1
        return {"reachable": True, "scan": script[i]}

    def findings_fn(node, remote_id):
        return {"findings": [{"severity": "high", "title": "x"}]}

    def cancel_fn(node, remote_id):
        return {"success": True}

    return start_fn, status_fn, findings_fn, cancel_fn


def test_delegator_relays_progress_and_pulls_findings():
    script = [
        {"status": "running", "progress_percent": 20, "findings_count": 0},
        {"status": "running", "progress_percent": 70, "findings_count": 1},
        {"status": "completed", "progress_percent": 100, "findings_count": 1},
    ]
    d = MeshScanDelegator(*_fakes(script))
    d.POLL_INTERVAL = 0.01
    res = d.start({"ip": "100.0.0.9"}, "harald", "http://t", "nuclei")
    assert res["success"]
    local_id = res["delegated_id"]
    # Wait for the relay thread to reach terminal state.
    for _ in range(200):
        rec = d.get_scan(local_id)
        if rec["status"] == "completed":
            break
        time.sleep(0.01)
    rec = d.get_scan(local_id)
    assert rec["status"] == "completed"
    assert rec["progress_percent"] == 100
    assert rec["findings_count"] == 1
    full = d.list_scans(include_findings=True)[0]
    assert full["findings"] and full["findings"][0]["severity"] == "high"


def test_delegator_start_failure_surfaces_error():
    def start_fn(node, target, scan_type, options):
        return {"success": False, "error": "peer OOM guard refused"}
    d = MeshScanDelegator(start_fn, lambda *a: {}, lambda *a: {}, lambda *a: {})
    res = d.start({"ip": "x"}, "ylva", "http://t", "nuclei")
    assert res["success"] is False and "refused" in res["error"]


def test_delegator_cancel_uses_stored_node_and_hides_it():
    seen = {}

    def start_fn(node, target, scan_type, options):
        return {"success": True, "scan_id": "AVS-9"}

    def status_fn(node, remote_id):
        return {"reachable": True, "scan": {"status": "running", "progress_percent": 5}}

    def cancel_fn(node, remote_id):
        seen["node"] = node
        seen["remote_id"] = remote_id
        return {"success": True}

    d = MeshScanDelegator(start_fn, status_fn, lambda *a: {}, cancel_fn)
    d.POLL_INTERVAL = 5  # don't let the relay reach terminal during the test
    node = {"ip": "100.0.0.9", "id": "nHARALD"}
    local_id = d.start(node, "harald", "http://t", "zap_full")["delegated_id"]

    out = d.cancel(local_id)
    assert out["success"] is True
    # cancel reached the same peer node we started on…
    assert seen["node"] == node and seen["remote_id"] == "AVS-9"
    # …but the node object is never exposed in the serialised job.
    job = d.list_scans(include_findings=True)[0]
    assert "_node" not in job
    assert d.get_scan(local_id) is not None and "_node" not in d.get_scan(local_id)
