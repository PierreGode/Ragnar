"""Tests for the Dashboard Targets card numbers.

The card read "54 targets, 54 total, 0 offline, 0 new, 0 lost" no matter what
was on the network: active came from a stored status that never records a
failure, and New/Lost held only the difference between two 15 second syncs.

Covers the single counting rule now shared by every code path:
- active / offline follow the live presence verdict
- hosts without a verdict fall back to the stored status
- New is "first seen in the last 24 hours", in both timestamp formats
- Lost is "was answering, went Offline in the last 24 hours, still Offline",
  and never includes a host that was simply never seen
"""

import time
from datetime import datetime, timedelta

import pytest


@pytest.fixture(scope='module')
def counts():
    try:
        import webapp_modern as module
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"webapp_modern unimportable here: {exc}")
    return module._live_target_counts


NOW = datetime(2026, 11, 10, 12, 0, 0)
OLD = (NOW - timedelta(days=30)).isoformat()


def host(ip, status='alive', first_seen=OLD, mac='aa:bb:cc:dd:ee:01'):
    return {'ip': ip, 'mac': mac, 'status': status, 'first_seen': first_seen}


def up():
    return {'status': 'up', 'seen_ago': 1.0, 'since': time.time() - 3600}


def down(hours_ago=1.0, ever_seen=True):
    return {'status': 'down', 'seen_ago': 5.0 if ever_seen else None,
            'since': time.time() - hours_ago * 3600}


def test_active_and_offline_follow_presence_not_the_stored_status(counts):
    hosts = [host('192.168.1.1'), host('192.168.1.2'), host('192.168.1.3')]
    presence = {'192.168.1.1': up(), '192.168.1.2': down(), '192.168.1.3': down()}
    result = counts(hosts, presence, now=NOW)
    assert (result['active'], result['inactive'], result['total']) == (1, 2, 3)


def test_presence_can_also_revive_a_host_the_database_calls_degraded(counts):
    result = counts([host('192.168.1.1', status='degraded')], {'192.168.1.1': up()}, now=NOW)
    assert result['active'] == 1 and result['inactive'] == 0


def test_hosts_without_a_verdict_use_the_stored_status(counts):
    hosts = [host('192.168.1.195'), host('192.168.1.9', status='degraded')]
    result = counts(hosts, {}, now=NOW)
    assert (result['active'], result['inactive']) == (1, 1)
    assert result['lost_ips'] == []


def test_counts_always_add_up(counts):
    hosts = [host(f'192.168.1.{i}') for i in range(1, 21)]
    presence = {f'192.168.1.{i}': (up() if i % 3 else down()) for i in range(1, 15)}
    result = counts(hosts, presence, now=NOW)
    assert result['active'] + result['inactive'] == result['total'] == 20


def test_placeholder_rows_are_not_targets(counts):
    hosts = [host(''), host('STANDALONE'), host('192.168.1.5', mac='STANDALONE'), host('192.168.1.6')]
    assert counts(hosts, {}, now=NOW)['total'] == 1


@pytest.mark.parametrize('stamp,expected', [
    ((NOW - timedelta(hours=2)).isoformat(), True),
    ((NOW - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S'), True),
    ((NOW - timedelta(hours=23, minutes=59)).isoformat(), True),
    ((NOW - timedelta(hours=25)).isoformat(), False),
    ((NOW + timedelta(hours=3)).isoformat(), False),     # clock skew, not "new"
    ('', False), (None, False), ('not a date', False),
])
def test_new_means_first_seen_in_the_last_24_hours(counts, stamp, expected):
    result = counts([host('192.168.1.7', first_seen=stamp)], {}, now=NOW)
    assert (result['new_ips'] == ['192.168.1.7']) is expected


def test_lost_means_recently_gone_after_having_answered(counts):
    hosts = [host(f'192.168.1.{i}') for i in (1, 2, 3, 4)]
    presence = {
        '192.168.1.1': up(),
        '192.168.1.2': down(hours_ago=1),                      # lost
        '192.168.1.3': down(hours_ago=1, ever_seen=False),     # never answered
        '192.168.1.4': down(hours_ago=30),                     # gone too long ago
    }
    assert counts(hosts, presence, now=NOW)['lost_ips'] == ['192.168.1.2']


def test_lists_are_sorted_numerically(counts):
    recent = (NOW - timedelta(hours=1)).isoformat()
    hosts = [host(ip, first_seen=recent) for ip in ('192.168.1.100', '192.168.1.20', '192.168.1.3')]
    assert counts(hosts, {}, now=NOW)['new_ips'] == ['192.168.1.3', '192.168.1.20', '192.168.1.100']
