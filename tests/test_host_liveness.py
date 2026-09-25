"""Tests for host liveness discovery (the Online/Offline flapping fix).

Liveness used to be decided by a single ``arp-scan --localnet`` broadcast
sweep. That sweep misses most live hosts on Wi-Fi and returns nothing at all
on a wired-only box (it was always run on the Wi-Fi interface), so every
target cycled Offline/Degraded between scans and back again on the next one.

Covers:
- the kernel neighbour table as a second liveness source, and which
  neighbour states count as "alive"
- arp-scan results and neighbour entries being merged, with arp-scan winning
  on conflicts because it carries the vendor string
- a sweep that found zero hosts being treated as a broken sensor rather than
  as the whole LAN going down
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from actions.scanning import NetworkScanner


NEIGH_OUTPUT = """\
192.168.1.1 dev eth0 lladdr b0:6e:bf:28:00:a0 REACHABLE
192.168.1.11 dev eth0 lladdr 94:ba:06:6c:ab:dd STALE
192.168.1.12 dev eth0 lladdr 14:c1:4e:3c:3e:f6 DELAY
192.168.1.13 dev eth0 lladdr 14:c1:4e:3c:3e:f7 PROBE
192.168.1.14 dev eth0 lladdr 14:c1:4e:3c:3e:f8 PERMANENT
192.168.1.99 dev eth0 FAILED
192.168.1.98 dev eth0 INCOMPLETE
192.168.1.97 dev eth0 lladdr 00:11:22:33:44:55 FAILED
not-an-ip dev eth0 lladdr 00:11:22:33:44:66 REACHABLE
192.168.1.96 dev eth0 lladdr zz:zz:zz:zz:zz:zz REACHABLE
"""


@pytest.fixture
def scanner():
    """A NetworkScanner stand-in carrying only what the methods under test use."""
    s = MagicMock()
    s.arp_scan_interface = 'eth0'
    s.logger = MagicMock()
    s._is_valid_ip = NetworkScanner._is_valid_ip
    s._is_valid_mac = NetworkScanner._is_valid_mac
    s.NEIGH_ALIVE_STATES = NetworkScanner.NEIGH_ALIVE_STATES
    return s


def _run_neigh(scanner):
    return NetworkScanner._read_neighbour_table(scanner)


# ---------------------------------------------------------------------------
# neighbour table parsing
# ---------------------------------------------------------------------------

def test_neighbour_table_keeps_only_resolved_alive_states(scanner):
    completed = subprocess.CompletedProcess([], 0, stdout=NEIGH_OUTPUT, stderr='')
    with patch('actions.scanning.subprocess.run', return_value=completed):
        hosts = _run_neigh(scanner)

    assert set(hosts) == {'192.168.1.1', '192.168.1.11', '192.168.1.12',
                          '192.168.1.13', '192.168.1.14'}
    assert hosts['192.168.1.1']['mac'] == 'b0:6e:bf:28:00:a0'


def test_neighbour_table_drops_failed_and_incomplete(scanner):
    """FAILED/INCOMPLETE are evidence a host is *not* reachable."""
    completed = subprocess.CompletedProcess([], 0, stdout=NEIGH_OUTPUT, stderr='')
    with patch('actions.scanning.subprocess.run', return_value=completed):
        hosts = _run_neigh(scanner)

    for ip in ('192.168.1.99', '192.168.1.98', '192.168.1.97'):
        assert ip not in hosts


def test_neighbour_table_scoped_to_the_lan_interface(scanner):
    completed = subprocess.CompletedProcess([], 0, stdout='', stderr='')
    with patch('actions.scanning.subprocess.run', return_value=completed) as run:
        _run_neigh(scanner)

    assert run.call_args[0][0] == ['ip', '-4', 'neigh', 'show', 'dev', 'eth0']


def test_neighbour_table_survives_missing_ip_command(scanner):
    with patch('actions.scanning.subprocess.run', side_effect=FileNotFoundError):
        assert _run_neigh(scanner) == {}


def test_neighbour_table_survives_nonzero_exit(scanner):
    completed = subprocess.CompletedProcess([], 1, stdout=NEIGH_OUTPUT, stderr='boom')
    with patch('actions.scanning.subprocess.run', return_value=completed):
        assert _run_neigh(scanner) == {}


# ---------------------------------------------------------------------------
# merge semantics: arp-scan sweep + neighbour table
# ---------------------------------------------------------------------------

def _merge(arp_hosts, neigh_hosts):
    """The merge run_arp_scan() performs, isolated from the subprocess work."""
    merged = dict(arp_hosts)
    for ip, data in neigh_hosts.items():
        merged.setdefault(ip, data)
    return merged


def test_neighbours_fill_the_gaps_left_by_one_broadcast_sweep():
    arp = {'192.168.1.1': {'mac': 'b0:6e:bf:28:00:a0', 'vendor': 'ASUSTek'}}
    neigh = {
        '192.168.1.11': {'mac': '94:ba:06:6c:ab:dd', 'vendor': ''},
        '192.168.1.12': {'mac': '14:c1:4e:3c:3e:f6', 'vendor': ''},
    }

    merged = _merge(arp, neigh)

    assert set(merged) == {'192.168.1.1', '192.168.1.11', '192.168.1.12'}


def test_arp_scan_wins_on_conflict_because_it_carries_the_vendor():
    arp = {'192.168.1.1': {'mac': 'b0:6e:bf:28:00:a0', 'vendor': 'ASUSTek'}}
    neigh = {'192.168.1.1': {'mac': 'b0:6e:bf:28:00:a0', 'vendor': ''}}

    assert _merge(arp, neigh)['192.168.1.1']['vendor'] == 'ASUSTek'


# ---------------------------------------------------------------------------
# failed-ping accounting: an empty result is a broken sensor, not a dead LAN
# ---------------------------------------------------------------------------

def _account(netkb_entries, alive_macs, max_failed_pings):
    """The failed-ping accounting from ScanPorts.update_netkb()."""
    for mac in netkb_entries:
        if alive_macs and mac not in alive_macs:
            netkb_entries[mac]['Failed_Pings'] = netkb_entries[mac].get('Failed_Pings', 0) + 1
            netkb_entries[mac]['Alive'] = (
                '0' if netkb_entries[mac]['Failed_Pings'] >= max_failed_pings else '1')
    return netkb_entries


def test_empty_scan_does_not_charge_a_failed_ping_to_anyone():
    entries = {'aa:bb:cc:dd:ee:ff': {'Alive': '1', 'Failed_Pings': 14}}

    _account(entries, alive_macs=set(), max_failed_pings=15)

    assert entries['aa:bb:cc:dd:ee:ff']['Failed_Pings'] == 14
    assert entries['aa:bb:cc:dd:ee:ff']['Alive'] == '1'


def test_a_real_scan_still_ages_out_a_genuinely_absent_host():
    entries = {'aa:bb:cc:dd:ee:ff': {'Alive': '1', 'Failed_Pings': 14}}

    _account(entries, alive_macs={'11:22:33:44:55:66'}, max_failed_pings=15)

    assert entries['aa:bb:cc:dd:ee:ff']['Failed_Pings'] == 15
    assert entries['aa:bb:cc:dd:ee:ff']['Alive'] == '0'


def test_a_host_below_the_threshold_stays_alive():
    entries = {'aa:bb:cc:dd:ee:ff': {'Alive': '1', 'Failed_Pings': 3}}

    _account(entries, alive_macs={'11:22:33:44:55:66'}, max_failed_pings=15)

    assert entries['aa:bb:cc:dd:ee:ff']['Alive'] == '1'
