"""Level / points / rank regression tests.

The overriding requirement: making the system better must NOT break anyone's
existing level. These tests lock in the backward-compatible curve, the level
cap, the Norse ranks, renown, event awards, and the v1->v2 migration that
preserves progress with no retroactive point windfall.
"""
import json
import os
import sys
import threading

os.environ.setdefault("RAGNAR_HEADLESS", "1")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import shared  # noqa: E402


def _obj(gamification_file, total_points=0):
    """A minimal object carrying just the attributes the gamification methods
    touch, with the real methods bound onto it (no heavy SharedData.__init__)."""
    o = shared.SharedData.__new__(shared.SharedData)
    o._stats_lock = threading.Lock()
    o.datadir = os.path.dirname(gamification_file)
    o.gamification_file = gamification_file
    o.points_per_level = 200
    o.max_level = 1000
    o.renown_points_per_star = 10000
    o.points_per_mac = 15
    o.points_per_credential = 25
    o.points_per_data_file = 10
    o.points_per_zombie = 40
    o.points_per_vulnerability = 20
    o.points_per_attack = 30
    o.points_per_port = 2
    o.points_per_scanned_network = 5
    o.points_per_host = 3
    o._NEW_METRIC_KEYS = {"attacksnbr", "portnbr", "scanned_networks_count", "hosts_known"}
    o.event_point_values = {
        "defense_detection_high": 10,
        "mesh_peer": 20,
        "wardrive_network": 4,
    }
    o.rank_ladder = [
        (1, "Thrall"), (10, "Karl"), (25, "Hersir"), (50, "Jarl"),
        (100, "Konungr"), (200, "Berserkr"), (350, "Einherjar"),
        (600, "Jötunn"), (1000, "Ragnar"),
    ]
    o.db = None
    o.crednbr = o.datanbr = o.zombiesnbr = o.vulnnbr = 0
    o.attacksnbr = o.portnbr = o.scanned_networks_count = o.total_targetnbr = 0
    o.coinnbr = total_points
    o.levelnbr = o.calculate_level(total_points)
    o.gamification_data = {
        "version": 2, "total_points": total_points, "level": o.levelnbr,
        "mac_points": {}, "lifetime_counts": {}, "event_counts": {},
    }
    return o


def test_curve_identical_to_old_below_cap():
    o = _obj("/tmp/_g_curve.json")
    old = lambda p: max(1, 1 + p // 200)
    for p in range(0, 199800, 101):
        assert o.calculate_level(p) == old(p), p


def test_level_cap_at_1000():
    o = _obj("/tmp/_g_cap.json")
    assert o.calculate_level(199800) == 1000
    assert o.calculate_level(10_000_000) == 1000


def test_existing_user_level_preserved():
    # The live unit at time of writing: 11415 points must stay level 58.
    o = _obj("/tmp/_g_user.json", total_points=11415)
    assert o.calculate_level(11415) == 58


def test_ranks():
    o = _obj("/tmp/_g_rank.json")
    assert o.get_rank(1)["name"] == "Thrall"
    assert o.get_rank(58)["name"] == "Jarl"
    assert o.get_rank(58)["next_name"] == "Konungr"
    assert o.get_rank(1000)["name"] == "Ragnar"
    assert o.get_rank(1000)["next_name"] is None


def test_renown_beyond_cap():
    o = _obj("/tmp/_g_renown.json")
    assert o.get_renown(199800) == 0        # exactly at cap
    assert o.get_renown(209800) == 1        # +10000
    assert o.get_renown(250000) == 5


def test_award_event_points_persists(tmp_path):
    gf = str(tmp_path / "g.json")
    o = _obj(gf, total_points=100)
    added = o.award_event_points("mesh_peer", count=2)
    assert added == 40
    assert o.coinnbr == 140
    saved = json.load(open(gf))
    assert saved["total_points"] == 140
    assert saved["event_counts"]["mesh_peer"] == {"count": 2, "points": 40}


def test_award_ignores_nonpositive_and_unknown():
    o = _obj("/tmp/_g_guard.json", total_points=100)
    assert o.award_event_points("mesh_peer", count=0) == 0
    assert o.award_event_points("does_not_exist", count=5) == 0
    assert o.coinnbr == 100


def test_migration_preserves_and_no_windfall(tmp_path):
    # Seed a v1 file (pre-upgrade shape) and confirm the load migrates it to v2
    # with identical level/points, then update_stats() baselines the new snapshot
    # sources without awarding anything for pre-existing lifetime totals.
    gf = str(tmp_path / "g.json")
    json.dump({"version": 1, "total_points": 11415, "level": 58,
               "mac_points": {}, "lifetime_counts": {"crednbr": 5}}, open(gf, "w"))

    o = _obj(gf, total_points=0)
    o.gamification_data = {}
    # Pre-existing activity that must NOT be retroactively rewarded:
    o.attacksnbr = 42
    o.portnbr = 888
    o.scanned_networks_count = 300
    o.total_targetnbr = 250

    o.load_gamification_data()
    assert o.gamification_data["version"] == 2
    assert o.coinnbr == 11415 and o.levelnbr == 58   # preserved exactly

    added = o.update_stats()
    assert added == 0                                # no windfall on first pass

    # Now genuinely new activity earns: +5 networks (25) + 10 ports (20) = 45.
    o.scanned_networks_count = 305
    o.portnbr = 898
    assert o.update_stats() == 45
