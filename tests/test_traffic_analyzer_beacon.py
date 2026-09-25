"""Tests for the C2 beacon detector in traffic_analyzer.TrafficAnalyzer."""

import time
from unittest.mock import patch

import pytest

from traffic_analyzer import (
    AlertCategory,
    TrafficAlertLevel,
    TrafficAnalyzer,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def analyzer():
    """A TrafficAnalyzer with side-effecting init paths stubbed out.

    We don't want the constructor probing real network interfaces or running
    `ip`/tcpdump during unit tests.
    """
    with patch.object(TrafficAnalyzer, '_detect_interface', return_value='lo'), \
         patch.object(TrafficAnalyzer, '_detect_local_ips',
                      return_value={'127.0.0.1', '192.168.1.10'}):
        a = TrafficAnalyzer(shared_data=None, interface='lo')
    # Make alert rate-limiting essentially unlimited for tests.
    a.MAX_ALERTS_PER_MINUTE = 10_000
    a._alert_dedup_window = 0
    return a


def _seed_periodic_flow(analyzer, src, dst, port, *,
                        count=8, interval=30.0, size=128,
                        jitter=0.0, size_jitter=0):
    """Push `count` evenly-spaced samples into the flow history."""
    base = 1_700_000_000.0
    for i in range(count):
        ts = base + i * interval + (jitter if i % 2 else 0.0)
        sz = size + (size_jitter if i % 2 else 0)
        analyzer._record_flow_sample(src, dst, port, ts, sz)


# ---------------------------------------------------------------------------
# _is_internal
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip,expected", [
    ('10.0.0.5', True),
    ('192.168.1.1', True),
    ('172.16.0.1', True),
    ('172.31.255.254', True),
    ('172.15.0.1', False),
    ('172.32.0.1', False),
    ('127.0.0.1', True),
    ('169.254.1.1', True),
    ('8.8.8.8', False),
    ('1.1.1.1', False),
    ('', False),
    ('not-an-ip', False),
])
def test_is_internal(ip, expected):
    assert TrafficAnalyzer._is_internal(ip) is expected


# ---------------------------------------------------------------------------
# _score_flow
# ---------------------------------------------------------------------------

def test_score_flow_rejects_too_few_samples(analyzer):
    samples = [(0.0, 100), (30.0, 100)]
    assert analyzer._score_flow(samples) is None


def test_score_flow_rejects_jittery_intervals(analyzer):
    # Wildly varying intervals = not a beacon.
    samples = [
        (0.0, 100), (1.0, 100), (30.0, 100), (31.5, 100),
        (200.0, 100), (203.0, 100), (500.0, 100),
    ]
    assert analyzer._score_flow(samples) is None


def test_score_flow_rejects_sub_minimum_interval(analyzer):
    # 1s interval - below BEACON_MIN_INTERVAL (5s).
    samples = [(i * 1.0, 100) for i in range(10)]
    assert analyzer._score_flow(samples) is None


def test_score_flow_accepts_regular_beacon(analyzer):
    samples = [(i * 30.0, 128) for i in range(8)]
    result = analyzer._score_flow(samples)
    assert result is not None
    # Perfect regularity should produce near-max score.
    assert result['score'] > 0.95
    assert result['interval_cv'] == pytest.approx(0.0)
    assert result['mean_interval_s'] == pytest.approx(30.0)
    assert result['samples'] == 8


def test_score_flow_size_jitter_lowers_score(analyzer):
    regular = [(i * 30.0, 128) for i in range(8)]
    noisy = [(i * 30.0, 128 + (50 if i % 2 else 0)) for i in range(8)]
    s_regular = analyzer._score_flow(regular)['score']
    s_noisy = analyzer._score_flow(noisy)['score']
    assert s_noisy < s_regular


# ---------------------------------------------------------------------------
# _sweep_beacons
# ---------------------------------------------------------------------------

def test_sweep_fires_alert_for_clean_beacon(analyzer):
    _seed_periodic_flow(analyzer, '192.168.1.73', '203.0.113.10', 6667,
                        count=8, interval=30.0, size=128)
    fired = analyzer._sweep_beacons(force=True)

    assert len(fired) == 1
    key, metrics = fired[0]
    assert key == ('192.168.1.73', '203.0.113.10', 6667)
    assert metrics['score'] >= TrafficAnalyzer.BEACON_SCORE_CRITICAL

    # Alert should be recorded and classified correctly.
    assert len(analyzer.alerts) == 1
    alert = analyzer.alerts[0]
    assert alert.category == AlertCategory.C2_BEACON.value
    assert alert.level == TrafficAlertLevel.HIGH
    assert alert.src_ip == '192.168.1.73'
    assert alert.dst_ip == '203.0.113.10'
    assert alert.details['dst_port'] == 6667
    assert 'mitre' in alert.details


def test_sweep_does_not_realert_on_same_score(analyzer):
    _seed_periodic_flow(analyzer, '192.168.1.73', '203.0.113.10', 6667,
                        count=8, interval=30.0, size=128)
    analyzer._sweep_beacons(force=True)
    initial_alert_count = len(analyzer.alerts)

    # Re-sweeping with the same buffer must not produce a duplicate alert.
    analyzer._sweep_beacons(force=True)
    assert len(analyzer.alerts) == initial_alert_count


def test_sweep_realerts_when_score_climbs_significantly(analyzer):
    # Start with a noisy flow that scores above the alert threshold but well
    # below critical.
    base = 1_700_000_000.0
    for i in range(8):
        # Intervals oscillate between 25s and 35s -> CV ~= 0.17, score ~0.32
        # for intervals; combined with perfect size yields a passing but
        # imperfect total score.
        offset = 25.0 if i % 2 else 35.0
        analyzer._record_flow_sample(
            '192.168.1.73', '203.0.113.10', 6667,
            base + sum(25.0 if j % 2 else 35.0 for j in range(i)),
            128,
        )
    analyzer._sweep_beacons(force=True)
    first_count = len(analyzer.alerts)

    # Now feed perfectly periodic samples that push the score to ~1.0.
    analyzer._flow_history[('192.168.1.73', '203.0.113.10', 6667)].clear()
    for i in range(10):
        analyzer._record_flow_sample(
            '192.168.1.73', '203.0.113.10', 6667,
            base + 10_000 + i * 30.0, 128,
        )
    analyzer._sweep_beacons(force=True)
    assert len(analyzer.alerts) > first_count


def test_sweep_respects_throttle_interval(analyzer):
    _seed_periodic_flow(analyzer, '192.168.1.73', '203.0.113.10', 6667)
    # First call (not forced) runs immediately because _last_beacon_sweep
    # starts at construction time, which may or may not have elapsed. Force
    # to set a known baseline.
    analyzer._sweep_beacons(force=True)
    analyzer.alerts.clear()
    analyzer._beacon_scored.clear()

    # A non-forced call within the throttle window should be a no-op.
    fired = analyzer._sweep_beacons(force=False)
    assert fired == []


def test_sweep_skips_denylisted_ports_via_parser(analyzer):
    # Direct flow recording does not enforce the denylist; the parser does.
    # Verify the parser path skips DNS (port 53) sampling.
    line = '2026-01-15 10:30:45.123456 IP 192.168.1.73.54321 > 8.8.8.8.53: udp 64'
    for _ in range(10):
        analyzer._parse_and_record_packet(line)
    # No (src, 8.8.8.8, 53) flow should be tracked.
    assert ('192.168.1.73', '8.8.8.8', 53) not in analyzer._flow_history


def test_parser_records_external_outbound_flow(analyzer):
    # 192.168.1.10 is in the analyzer's _local_ips and should be skipped
    # (treated as Ragnar itself). 192.168.1.73 is internal-but-not-Ragnar
    # and should be recorded.
    line = ('2026-01-15 10:30:45.123456 IP 192.168.1.73.54321 '
            '> 203.0.113.10.6667: tcp 128')
    for _ in range(8):
        analyzer._parse_and_record_packet(line)
    assert ('192.168.1.73', '203.0.113.10', 6667) in analyzer._flow_history
    assert len(analyzer._flow_history[('192.168.1.73', '203.0.113.10', 6667)]) == 8


def test_get_beacons_returns_sorted_candidates(analyzer):
    # Perfect beacon -> highest score
    _seed_periodic_flow(analyzer, '192.168.1.73', '203.0.113.10', 6667,
                        count=8, interval=30.0, size=128)
    # Slightly noisier beacon -> lower score
    base = 1_700_000_000.0
    for i in range(8):
        offset = 60.0 + (2.0 if i % 2 else 0.0)
        analyzer._record_flow_sample(
            '192.168.1.50', '198.51.100.5', 443,
            base + i * offset, 256 + (10 if i % 2 else 0),
        )
    analyzer._sweep_beacons(force=True)

    beacons = analyzer.get_beacons()
    assert len(beacons) >= 1
    # Sorted descending by score.
    scores = [b['score'] for b in beacons]
    assert scores == sorted(scores, reverse=True)


def test_clear_stats_resets_beacon_state(analyzer):
    _seed_periodic_flow(analyzer, '192.168.1.73', '203.0.113.10', 6667)
    analyzer._sweep_beacons(force=True)
    assert analyzer._flow_history
    assert analyzer._beacon_scored

    analyzer.clear_stats()
    assert not analyzer._flow_history
    assert not analyzer._beacon_scored
