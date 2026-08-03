"""Tests for mesh scan delegation decision logic (which peer runs a heavy scanner).

The relay itself lives in AdvancedVulnScanner.start_delegated_scan (see
test_delegated_scan.py); this covers the pure peer-selection logic.
"""

from mesh_scan import build_roster, capability, pick_delegate, required_tool


def test_required_tool_mapping():
    assert required_tool("nuclei") == "nuclei"
    assert required_tool("full") == "nuclei"
    assert required_tool("zap_full") == "zap"
    assert required_tool("zap_spider") == "zap"
    assert required_tool("nikto") is None      # light — never delegated
    assert required_tool("whatweb") is None


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
    # Only a nuclei-capable peer in the mesh -> ZAP has no delegate (stays grey).
    roster = build_roster([capability("ylva", ram_gb=1.0, nuclei=True)])
    assert pick_delegate(roster, "zap") is None
    assert pick_delegate(roster, "nuclei")["viking"] == "ylva"


def test_build_roster_drops_incapable_and_unreachable():
    caps = [
        capability("ylva", nuclei=True),
        capability("tiny", nuclei=False, zap=False),        # can't run anything
        capability("gone", nuclei=True, reachable=False),   # offline
    ]
    names = {c["viking"] for c in build_roster(caps)}
    assert names == {"ylva"}


def test_capability_carries_node_id_for_resolution():
    c = capability("ylva", node_id="nYLVA", ip="100.0.0.9", nuclei=True)
    assert c["node_id"] == "nYLVA" and c["ip"] == "100.0.0.9"
