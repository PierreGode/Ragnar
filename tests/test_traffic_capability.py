"""Tests for the Traffic Analysis hardware gate.

Traffic Analysis used to ride on full server mode (7.5GB RAM), which was the
wrong bar: the engine is a `tcpdump` pipe read line by line in Python. Measured
on a Pi 5 against a live LAN at ~90 packets/sec it costs 0.4% of one core and
18MB RSS, plus 8MB for tcpdump — a Pi Zero workload. It now has its own gate.

What matters here is that the two gates stay separate, that the real
requirement (tcpdump installed) is what the gate actually reports, and that the
genuinely heavy part — the tshark sidecars, ~290MB RSS each — does *not* follow
the core onto small boards.
"""

import threading
from collections import deque
from datetime import datetime, timedelta

import pytest

from server_capabilities import ServerCapabilities, SystemCapabilities
from traffic_analyzer import ConnectionStats, HostTrafficStats, TrafficAnalyzer


def caps_for(ram_gb, cores=4, arch='aarch64', tcpdump=True, tshark=True,
             is_pi_zero=False, is_server_capable=False):
    """A ServerCapabilities describing a made-up board, no hardware detection."""
    sc = ServerCapabilities.__new__(ServerCapabilities)
    sc.shared_data = None
    sc.capabilities = SystemCapabilities(
        architecture=arch,
        total_ram_gb=ram_gb,
        cpu_cores=cores,
        is_pi_zero=is_pi_zero,
        is_server_capable=is_server_capable,
        available_tools={'tcpdump': tcpdump, 'tshark': tshark},
    )
    return sc


@pytest.mark.parametrize("ram_gb,is_pi_zero", [
    (0.42, True),    # Pi Zero 2 W: 512MB board, ~415MB usable
    (0.9, False),    # Pi 4 1GB
    (3.9, False),    # Pi 5 4GB — below server mode's 7.5GB bar
    (7.87, False),   # Pi 5 8GB
])
def test_traffic_analysis_runs_on_any_board_with_tcpdump(ram_gb, is_pi_zero):
    capable, reason = caps_for(ram_gb, is_pi_zero=is_pi_zero)._evaluate_traffic_support()
    assert capable is True
    assert reason == ""


def test_missing_tcpdump_is_the_real_blocker_and_says_so():
    """tcpdump is the one hard requirement, and the reason is shown verbatim in
    the UI — so it has to name the package, not just say 'unavailable'."""
    capable, reason = caps_for(7.87, tcpdump=False)._evaluate_traffic_support()
    assert capable is False
    assert 'tcpdump' in reason


@pytest.mark.parametrize("kwargs", [
    {'ram_gb': 0.0},                      # RAM unreadable — fail closed
    {'ram_gb': 4.0, 'cores': 0},          # no usable core count
    {'ram_gb': 4.0, 'arch': 'mips'},      # unsupported architecture
])
def test_unmeasurable_or_unsupported_boards_are_refused(kwargs):
    capable, reason = caps_for(**kwargs)._evaluate_traffic_support()
    assert capable is False
    assert reason.strip()


def test_gate_is_independent_of_full_server_mode():
    """The whole point of the change: a 4GB Pi 5 is not 'server capable' (that
    bar is 7.5GB for OpenVAS-class work) but it captures traffic fine."""
    sc = caps_for(3.9, is_server_capable=False)
    sc._determine_feature_flags()
    assert sc.capabilities.is_server_capable is False
    assert sc.capabilities.traffic_analysis_enabled is True
    assert sc.get_feature_status()['traffic_analysis'] is True
    # Advanced Vuln stays off here because this made-up board has no nmap
    # (its gate), not because of server mode — see test_advscan_zap_gate.
    assert sc.capabilities.advanced_vuln_enabled is False


def test_flags_land_on_the_capabilities_object():
    """_determine_feature_flags must publish the gate: that is what
    /api/server/capabilities and /api/traffic/status report."""
    sc = caps_for(0.42, tcpdump=False, is_pi_zero=True)
    sc._determine_feature_flags()
    assert sc.capabilities.traffic_capable is False
    assert sc.capabilities.traffic_block_reason
    assert sc.get_feature_status()['traffic_analysis'] is False


@pytest.mark.parametrize("ram_gb,tshark,expected", [
    (0.42, True, False),    # Pi Zero: two tsharks outweigh the whole board
    (1.9, True, False),     # 2GB Pi 4: kiosk-class, still not tshark-class
    (3.9, True, True),      # 4GB Pi 5
    (7.87, False, False),   # big board, but tshark is not installed
])
def test_tshark_sidecars_keep_their_own_higher_bar(ram_gb, tshark, expected):
    sc = caps_for(ram_gb, tshark=tshark)
    sc._determine_feature_flags()
    assert sc.capabilities.traffic_sidecars_enabled is expected
    # The core capture is unaffected either way.
    assert sc.capabilities.traffic_analysis_enabled is True


@pytest.mark.parametrize("feature", ['traffic_analysis'])
def test_tool_install_is_allowed_without_server_mode(feature, monkeypatch):
    """Installing tcpdump is how a small board *gets* Traffic Analysis, so the
    install path must not be the thing that requires server mode."""
    sc = caps_for(0.42, tcpdump=False, is_pi_zero=True, is_server_capable=False)
    monkeypatch.setattr(sc, 'get_missing_tools', lambda f: [])
    ok, message = sc.install_missing_tools(feature)
    assert ok is True
    assert 'Server mode' not in message


def test_advanced_vuln_install_is_allowed_without_server_mode(monkeypatch):
    """The Advanced Vuln CLI scanners (nmap/nuclei/nikto/sqlmap/whatweb) run on
    any board now, so installing them must not require server mode either. ZAP
    is not in this install set — it keeps its own RAM gate — so nothing here is
    server-mode-only anymore."""
    sc = caps_for(3.9, is_server_capable=False)
    monkeypatch.setattr(sc, 'get_missing_tools', lambda f: [])
    ok, message = sc.install_missing_tools('advanced_vuln')
    assert ok is True
    assert 'Server mode' not in message


@pytest.mark.parametrize("ram_gb,expect_low", [
    (0.42, True),    # Pi Zero 2 W
    (0.0, True),     # RAM unreadable — take the conservative caps
    (3.9, False),
    (15.8, False),
])
def test_state_caps_shrink_on_small_boards(ram_gb, expect_low):
    """Tracked hosts/connections/flows are the only unbounded state, so on a
    512MB board they get the divided caps."""
    hosts, conns, flows = TrafficAnalyzer._state_caps(ram_gb)
    d = TrafficAnalyzer.LOW_MEMORY_DIVISOR if expect_low else 1
    assert hosts == TrafficAnalyzer.MAX_TRACKED_HOSTS // d
    assert conns == TrafficAnalyzer.MAX_TRACKED_CONNECTIONS // d
    assert flows == TrafficAnalyzer.MAX_TRACKED_FLOWS // d
    assert hosts > 0 and conns > 0 and flows > 0


def analyzer_with_state(hosts=6, cap=2):
    """A TrafficAnalyzer holding `hosts` peers, capped at `cap`, no capture."""
    a = TrafficAnalyzer.__new__(TrafficAnalyzer)   # no hardware detection
    a._lock = threading.Lock()
    a._max_hosts = a._max_connections = a._max_flows = cap
    now = datetime.now()

    a.host_stats, a.connections, a._flow_history, a._beacon_scored = {}, {}, {}, {}
    a._mac_by_ip, a._listening_ports, a._hostname_by_ip, a._dns_query_times = {}, {}, {}, {}
    for i in range(hosts):
        ip = f'10.0.0.{i}'
        # Higher i == seen more recently, so 0 is always the first evicted.
        seen = now - timedelta(seconds=hosts - i)
        a.host_stats[ip] = HostTrafficStats(ip=ip, last_seen=seen)
        a.connections[f'{ip}:1->10.1.1.1:443'] = ConnectionStats(
            src_ip=ip, dst_ip='10.1.1.1', src_port=1, dst_port=443,
            protocol='tcp', last_seen=seen)
        key = (ip, '10.1.1.1', 443)
        a._flow_history[key] = deque([(seen.timestamp(), 100)])
        a._beacon_scored[key] = {'score': 0.9}
        a._mac_by_ip[ip] = 'aa:bb:cc:dd:ee:ff'
        a._listening_ports[ip] = {443}
        a._hostname_by_ip[ip] = f'host{i}'
        a._dns_query_times[ip] = deque([seen.timestamp()])
    return a


def test_prune_state_evicts_the_least_recently_seen():
    """Without this the analyzer grows an entry per peer forever, which is the
    one thing that would make a long capture unsafe on a 512MB board."""
    a = analyzer_with_state(hosts=6, cap=2)
    a._prune_state()

    assert len(a.host_stats) == 2
    assert len(a.connections) == 2
    assert len(a._flow_history) == 2
    # Survivors are the most recently seen, not an arbitrary two.
    assert set(a.host_stats) == {'10.0.0.4', '10.0.0.5'}
    # Beacon scores follow their flow out, or they leak on their own.
    assert set(a._beacon_scored) == set(a._flow_history)


def test_prune_state_drops_side_tables_for_evicted_hosts():
    a = analyzer_with_state(hosts=6, cap=2)
    a._prune_state()

    live = set(a.host_stats)
    for table in (a._mac_by_ip, a._listening_ports, a._hostname_by_ip, a._dns_query_times):
        assert set(table) == live


def test_prune_state_is_a_no_op_under_the_caps():
    a = analyzer_with_state(hosts=2, cap=10)
    a._prune_state()
    assert len(a.host_stats) == 2
    assert len(a.connections) == 2
    assert len(a._flow_history) == 2
    assert set(a._mac_by_ip) == {'10.0.0.0', '10.0.0.1'}
