"""Regression tests for broadcast/multicast and protocol-aware filtering.

Covers the 192.168.1.105 -> 255.255.255.255:6667 false positive:
- UDP broadcast on port 6667 must NOT trigger an "IRC C2" alert.
- Broadcast destinations must NOT be sampled for beacon scoring.
- A real TCP unicast to port 6667 must still alert.
"""

from unittest.mock import patch

import pytest

from traffic_analyzer import AlertCategory, TrafficAnalyzer


@pytest.fixture
def analyzer():
    with patch.object(TrafficAnalyzer, '_detect_interface', return_value='lo'), \
         patch.object(TrafficAnalyzer, '_detect_local_ips',
                      return_value={'127.0.0.1', '192.168.1.10'}):
        a = TrafficAnalyzer(shared_data=None, interface='lo')
    a.MAX_ALERTS_PER_MINUTE = 10_000
    a._alert_dedup_window = 0
    return a


# ---------------------------------------------------------------------------
# _is_broadcast_or_multicast
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip,expected", [
    ('255.255.255.255', True),
    ('0.0.0.0', True),
    ('192.168.1.255', True),
    ('10.0.0.255', True),
    ('224.0.0.1', True),       # multicast
    ('239.255.255.250', True),  # SSDP
    ('192.168.1.105', False),
    ('8.8.8.8', False),
    ('240.0.0.1', False),       # reserved, not multicast
    ('', False),
])
def test_is_broadcast_or_multicast(ip, expected):
    assert TrafficAnalyzer._is_broadcast_or_multicast(ip) is expected


# ---------------------------------------------------------------------------
# Suppression: UDP broadcast on port 6667 must not alert
# ---------------------------------------------------------------------------

def test_udp_broadcast_on_irc_port_does_not_alert(analyzer):
    analyzer._check_suspicious_patterns(
        src_ip='192.168.1.105', dst_ip='255.255.255.255',
        src_port=54321, dst_port=6667, protocol='udp',
    )
    suspicious = [a for a in analyzer.alerts
                  if a.category == AlertCategory.SUSPICIOUS_PORT.value]
    assert suspicious == []


def test_subnet_directed_broadcast_on_irc_port_does_not_alert(analyzer):
    analyzer._check_suspicious_patterns(
        src_ip='192.168.1.105', dst_ip='192.168.1.255',
        src_port=54321, dst_port=6667, protocol='udp',
    )
    assert not any(
        a.category == AlertCategory.SUSPICIOUS_PORT.value
        for a in analyzer.alerts
    )


def test_udp_unicast_on_irc_port_does_not_alert(analyzer):
    # UDP unicast on 6667 is still not IRC — same suppression rule.
    analyzer._check_suspicious_patterns(
        src_ip='192.168.1.105', dst_ip='203.0.113.10',
        src_port=54321, dst_port=6667, protocol='udp',
    )
    assert not any(
        a.category == AlertCategory.SUSPICIOUS_PORT.value
        for a in analyzer.alerts
    )


def test_tcp_unicast_on_irc_port_still_alerts(analyzer):
    analyzer._check_suspicious_patterns(
        src_ip='192.168.1.73', dst_ip='203.0.113.10',
        src_port=54321, dst_port=6667, protocol='tcp',
    )
    suspicious = [a for a in analyzer.alerts
                  if a.category == AlertCategory.SUSPICIOUS_PORT.value]
    assert len(suspicious) == 1
    assert suspicious[0].details['protocol'] == 'tcp'
    assert suspicious[0].details['broadcast'] is False


def test_non_tcp_only_port_is_unaffected_by_proto(analyzer):
    # Port 4444 is in TCP_UNICAST_ONLY_PORTS so should be suppressed on UDP.
    # Pick a non-tcp-only port (8080) to confirm the gate doesn't over-apply.
    analyzer._check_suspicious_patterns(
        src_ip='192.168.1.50', dst_ip='203.0.113.5',
        src_port=12345, dst_port=8080, protocol='udp',
    )
    suspicious = [a for a in analyzer.alerts
                  if a.category == AlertCategory.SUSPICIOUS_PORT.value]
    assert len(suspicious) == 1


# ---------------------------------------------------------------------------
# Beacon sampling: broadcast destinations are skipped
# ---------------------------------------------------------------------------

def test_parser_does_not_sample_broadcast_for_beacon(analyzer):
    # tcpdump-style line: 192.168.1.105 sends UDP to 255.255.255.255:6667
    line = ('2026-05-28 00:29:13.000000 IP 192.168.1.105.54321 '
            '> 255.255.255.255.6667: udp 64')
    for _ in range(10):
        analyzer._parse_and_record_packet(line)
    assert ('192.168.1.105', '255.255.255.255', 6667) not in analyzer._flow_history


def test_parser_does_not_sample_multicast_for_beacon(analyzer):
    line = ('2026-05-28 00:29:13.000000 IP 192.168.1.105.54321 '
            '> 239.255.255.250.1900: udp 100')
    for _ in range(10):
        analyzer._parse_and_record_packet(line)
    assert ('192.168.1.105', '239.255.255.250', 1900) not in analyzer._flow_history


def test_parser_still_samples_external_unicast_for_beacon(analyzer):
    line = ('2026-05-28 00:29:13.000000 IP 192.168.1.73.54321 '
            '> 203.0.113.10.443: tcp 128')
    for _ in range(8):
        analyzer._parse_and_record_packet(line)
    assert ('192.168.1.73', '203.0.113.10', 443) in analyzer._flow_history
