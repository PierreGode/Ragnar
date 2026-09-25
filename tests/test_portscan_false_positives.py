"""Regression tests for port-scan detection false positives & evasion.

Covers:
- DNS / DHCP server responses must NOT count as scan targets.
- Flow-direction inference: response traffic doesn't count even without
  the service-port heuristic.
- High-value high ports (Docker, Redis, ES, MongoDB...) bypass the
  response heuristic — closes nmap `-g 53` evasion.
- Default gateway uses softer threshold (5x), not full exemption.
- Horizontal sweep detection: one port across many hosts alerts.
- Real low-port scans still alert (HIGH).
"""

from unittest.mock import patch

import pytest

from traffic_analyzer import (
    AlertCategory,
    TrafficAlertLevel,
    TrafficAnalyzer,
)


@pytest.fixture
def analyzer():
    with patch.object(TrafficAnalyzer, '_detect_interface', return_value='lo'), \
         patch.object(TrafficAnalyzer, '_detect_local_ips',
                      return_value={'127.0.0.1', '192.168.1.10'}), \
         patch.object(TrafficAnalyzer, '_detect_gateway_ips',
                      return_value=set()):
        a = TrafficAnalyzer(shared_data=None, interface='lo')
    a.MAX_ALERTS_PER_MINUTE = 10_000
    a._alert_dedup_window = 0
    return a


def _portscan_alerts(analyzer):
    return [a for a in analyzer.alerts
            if a.category == AlertCategory.PORT_SCAN.value]


# ---------------------------------------------------------------------------
# _looks_like_response
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("my_port,peer_port,expected", [
    (53, 57285, True),     # DNS response
    (67, 68, False),       # DHCP server->client (port 68 < 1024, not "ephemeral")
    (80, 49152, True),     # HTTP response
    (443, 51000, True),    # HTTPS response
    (54321, 53, False),    # DNS query (client initiating)
    (49152, 443, False),   # HTTPS request
    (22, 50000, False),    # 22 not in SERVICE_SOURCE_PORTS
    (8080, 60000, True),   # HTTP-alt response
    (0, 0, False),         # ARP / ICMP — no port info
    (53, 6379, False),     # `nmap -g 53` against Redis — high-value bypass
    (53, 27017, False),    # `nmap -g 53` against MongoDB — high-value bypass
    (53, 9200, False),     # `nmap -g 53` against Elasticsearch — bypass
])
def test_looks_like_response(analyzer, my_port, peer_port, expected):
    assert analyzer._looks_like_response(my_port, peer_port) is expected


# ---------------------------------------------------------------------------
# DNS responses must not pollute ports_targeted
# ---------------------------------------------------------------------------

def test_dns_responses_do_not_pollute_ports_targeted(analyzer):
    """Router answers 60 DNS queries from a client. No port-scan alert."""
    router = '192.168.1.1'
    client = '192.168.1.195'
    base_ts = '2026-05-28 00:46:45.000000'

    # 60 DNS replies on different ephemeral client ports.
    for i in range(60):
        eph = 32768 + i
        line = (f'{base_ts} IP {router}.53 > {client}.{eph}: '
                f'UDP, length 44')
        analyzer._parse_and_record_packet(line)

    # Router should NOT have those ephemeral ports as "targeted".
    router_stats = analyzer.host_stats[router]
    assert len(router_stats.ports_targeted) == 0, (
        f"Router shouldn't target ephemeral ports from DNS responses, "
        f"got: {router_stats.ports_targeted}"
    )
    # And no port-scan alert.
    assert _portscan_alerts(analyzer) == []


def test_dhcp_server_responses_do_not_trigger_scan(analyzer):
    """DHCP server (port 67) responding to clients shouldn't look like scan."""
    server = '192.168.1.1'
    base_ts = '2026-05-28 00:46:45.000000'

    for i in range(60):
        client = f'192.168.1.{100 + (i % 50)}'
        eph = 32768 + i
        line = (f'{base_ts} IP {server}.67 > {client}.{eph}: '
                f'UDP, length 300')
        analyzer._parse_and_record_packet(line)

    assert len(analyzer.host_stats[server].ports_targeted) == 0
    assert _portscan_alerts(analyzer) == []


def test_dns_client_querying_one_resolver_is_not_a_scan(analyzer):
    """Client makes 60 DNS queries to 8.8.8.8 — only port 53 is 'targeted'."""
    client = '192.168.1.195'
    resolver = '8.8.8.8'
    base_ts = '2026-05-28 00:46:45.000000'

    for i in range(60):
        eph = 32768 + i
        line = (f'{base_ts} IP {client}.{eph} > {resolver}.53: '
                f'UDP, length 64')
        analyzer._parse_and_record_packet(line)

    # Client only targets one port (53).
    assert analyzer.host_stats[client].ports_targeted == {53}
    assert _portscan_alerts(analyzer) == []


# ---------------------------------------------------------------------------
# Real port scans still alert
# ---------------------------------------------------------------------------

def test_real_low_port_scan_alerts_high(analyzer):
    """Attacker probes 25 well-known ports — HIGH severity port-scan alert."""
    attacker = '203.0.113.10'
    target = '192.168.1.50'
    base_ts = '2026-05-28 01:00:00.000000'

    for port in range(1, 26):  # ports 1..25 — all <1024
        eph = 40000 + port
        line = (f'{base_ts} IP {attacker}.{eph} > {target}.{port}: '
                f'tcp 0')
        analyzer._parse_and_record_packet(line)

    alerts = _portscan_alerts(analyzer)
    assert len(alerts) >= 1
    assert alerts[0].level == TrafficAlertLevel.HIGH
    assert alerts[0].src_ip == attacker
    assert alerts[0].details['low_ports_count'] >= 20


def test_heavy_ephemeral_targeting_alerts_medium(analyzer):
    """Host initiates to 200 unique high ports — MEDIUM alert."""
    src = '203.0.113.10'
    target = '192.168.1.50'
    base_ts = '2026-05-28 01:00:00.000000'

    for i in range(200):
        port = 30000 + i
        eph = 40000 + i
        line = (f'{base_ts} IP {src}.{eph} > {target}.{port}: '
                f'tcp 0')
        analyzer._parse_and_record_packet(line)

    alerts = _portscan_alerts(analyzer)
    assert len(alerts) >= 1
    # 200 high ports with 0 low ports — MEDIUM, not HIGH.
    assert alerts[0].level == TrafficAlertLevel.MEDIUM


# ---------------------------------------------------------------------------
# Gateway whitelist
# ---------------------------------------------------------------------------

def test_default_gateway_uses_softer_threshold(analyzer):
    """Gateway gets 5x threshold — 30 low ports no longer alerts."""
    gateway = '192.168.1.1'
    analyzer._gateway_ips = {gateway}
    target = '192.168.1.50'
    base_ts = '2026-05-28 01:00:00.000000'

    # 30 low ports: would alert HIGH for non-gateway, but gateway needs 100.
    for port in range(1, 31):
        eph = 40000 + port
        line = (f'{base_ts} IP {gateway}.{eph} > {target}.{port}: tcp 0')
        analyzer._parse_and_record_packet(line)

    assert _portscan_alerts(analyzer) == []


def test_compromised_gateway_with_heavy_scan_still_alerts(analyzer):
    """Gateway with 100+ low-port targets crosses the softer threshold."""
    gateway = '192.168.1.1'
    analyzer._gateway_ips = {gateway}
    target = '192.168.1.50'
    base_ts = '2026-05-28 01:00:00.000000'

    # 110 low ports — exceeds 20*5 = 100.
    for port in range(1, 111):
        eph = 40000 + port
        line = (f'{base_ts} IP {gateway}.{eph} > {target}.{port}: tcp 0')
        analyzer._parse_and_record_packet(line)

    alerts = _portscan_alerts(analyzer)
    assert len(alerts) >= 1
    assert alerts[0].level == TrafficAlertLevel.HIGH
    assert alerts[0].details['is_gateway'] is True


# ---------------------------------------------------------------------------
# High-value high ports (nmap -g 53 evasion)
# ---------------------------------------------------------------------------

def test_source_port_53_against_high_value_ports_still_counts(analyzer):
    """`nmap -g 53` against Redis/Mongo/ES/Docker must NOT evade detection."""
    attacker = '203.0.113.10'
    target = '192.168.1.50'
    base_ts = '2026-05-28 01:00:00.000000'

    high_value_targets = [6379, 27017, 9200, 5432, 3306, 2375, 5984,
                          8080, 8443, 11211, 1433, 5601, 9000, 9090,
                          5985, 5986, 2379, 5672, 5900, 8086]

    for port in high_value_targets:
        line = (f'{base_ts} IP {attacker}.53 > {target}.{port}: tcp 0')
        analyzer._parse_and_record_packet(line)

    # All 20 high-value ports should appear in ports_targeted despite src=53.
    targeted = analyzer.host_stats[attacker].ports_targeted
    for port in high_value_targets:
        assert port in targeted, (
            f"port {port} (high-value) should be counted as targeted "
            f"even with src_port=53; got {sorted(targeted)}"
        )

    # And the scan alert fires (weighted score >= threshold).
    alerts = _portscan_alerts(analyzer)
    assert len(alerts) >= 1
    assert alerts[0].level == TrafficAlertLevel.HIGH
    assert alerts[0].details['high_value_ports_count'] >= 20


def test_dns_response_to_random_ephemeral_still_filtered(analyzer):
    """Random ephemeral (not high-value) — DNS response heuristic still works."""
    router = '192.168.1.1'
    client = '192.168.1.195'
    base_ts = '2026-05-28 00:46:45.000000'

    # 50 DNS replies — none of these ports are in HIGH_VALUE_HIGH_PORTS.
    for i in range(50):
        eph = 32768 + i
        line = (f'{base_ts} IP {router}.53 > {client}.{eph}: UDP, length 44')
        analyzer._parse_and_record_packet(line)

    assert len(analyzer.host_stats[router].ports_targeted) == 0


# ---------------------------------------------------------------------------
# Flow-direction inference
# ---------------------------------------------------------------------------

def test_response_packet_does_not_count_as_initiation(analyzer):
    """If we see the request first, the response shouldn't be counted."""
    client = '192.168.1.195'
    server = '203.0.113.10'
    base_ts = '2026-05-28 01:00:00.000000'

    # Client initiates to an UNCOMMON port that's neither service nor
    # high-value, so neither heuristic applies — only flow-direction does.
    line_request = f'{base_ts} IP {client}.50000 > {server}.31415: tcp 64'
    analyzer._parse_and_record_packet(line_request)
    # Server responds — direction reverses.
    line_response = f'{base_ts} IP {server}.31415 > {client}.50000: tcp 64'
    analyzer._parse_and_record_packet(line_response)

    # Client targeted port 31415. ✓
    assert 31415 in analyzer.host_stats[client].ports_targeted
    # Server did NOT "target" port 50000 — it was responding.
    assert 50000 not in analyzer.host_stats[server].ports_targeted


# ---------------------------------------------------------------------------
# Horizontal sweep
# ---------------------------------------------------------------------------

def test_horizontal_sweep_one_port_many_hosts_alerts(analyzer):
    """Scanner hits port 445 across 12 hosts — sweep alert fires."""
    attacker = '203.0.113.10'
    base_ts = '2026-05-28 01:00:00.000000'

    for i in range(12):
        target = f'192.168.1.{50 + i}'
        line = (f'{base_ts} IP {attacker}.40000 > {target}.445: tcp 0')
        analyzer._parse_and_record_packet(line)

    sweep_alerts = [a for a in _portscan_alerts(analyzer)
                    if 'sweep' in a.message.lower()]
    assert len(sweep_alerts) >= 1
    assert sweep_alerts[0].details['sweep_port'] == 445
    assert sweep_alerts[0].details['hosts_targeted'] >= 10


def test_sweep_only_counts_relevant_ports(analyzer):
    """Random high port across many hosts should NOT trigger sweep."""
    attacker = '203.0.113.10'
    base_ts = '2026-05-28 01:00:00.000000'

    # Port 31415 is neither <1024 nor in HIGH_VALUE_HIGH_PORTS — irrelevant.
    for i in range(20):
        target = f'192.168.1.{50 + i}'
        line = (f'{base_ts} IP {attacker}.40000 > {target}.31415: tcp 0')
        analyzer._parse_and_record_packet(line)

    sweep_alerts = [a for a in _portscan_alerts(analyzer)
                    if 'sweep' in a.message.lower()]
    assert sweep_alerts == []


def test_sweep_dedup_per_src_port_pair(analyzer):
    """Repeated sweep observations should not spam alerts."""
    analyzer._alert_dedup_window = 300  # restore real dedup
    attacker = '203.0.113.10'
    base_ts = '2026-05-28 01:00:00.000000'

    # First wave: 12 hosts on port 22.
    for i in range(12):
        target = f'192.168.1.{50 + i}'
        line = (f'{base_ts} IP {attacker}.40000 > {target}.22: tcp 0')
        analyzer._parse_and_record_packet(line)

    sweep_alerts_first = [a for a in _portscan_alerts(analyzer)
                          if a.details.get('sweep_port') == 22]
    assert len(sweep_alerts_first) == 1

    # Second wave: more hosts on port 22 — should NOT fire again.
    for i in range(12, 25):
        target = f'192.168.1.{50 + i}'
        line = (f'{base_ts} IP {attacker}.40000 > {target}.22: tcp 0')
        analyzer._parse_and_record_packet(line)

    sweep_alerts_total = [a for a in _portscan_alerts(analyzer)
                          if a.details.get('sweep_port') == 22]
    assert len(sweep_alerts_total) == 1


# ---------------------------------------------------------------------------
# ports_contacted UI semantics unchanged for non-zero ports
# ---------------------------------------------------------------------------

def test_ports_contacted_still_tracks_all_peer_ports(analyzer):
    """UI view of `ports_contacted` should include both directions' ports."""
    router = '192.168.1.1'
    client = '192.168.1.195'
    base_ts = '2026-05-28 00:46:45.000000'

    line = f'{base_ts} IP {router}.53 > {client}.57285: UDP, length 44'
    analyzer._parse_and_record_packet(line)

    # Router's ports_contacted contains the client's ephemeral port (UI shows
    # "ports involved with this host"). It just isn't counted as a scan target.
    assert 57285 in analyzer.host_stats[router].ports_contacted
    assert 57285 not in analyzer.host_stats[router].ports_targeted
    # And the client's stats show port 53 as both contacted and targeted.
    assert 53 in analyzer.host_stats[client].ports_contacted
