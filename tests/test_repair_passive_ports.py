"""Tests for the phantom-port repair heuristic.

The repair clears a host's whole port list, so the cost of a false positive is
one scan cycle — but it still must not fire on a genuinely busy server. These
tests pin both directions: the recorded sweep is caught, a real multi-service
box is left alone.
"""

import importlib.util
import os

import pytest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      'scripts', 'repair_passive_ports.py')
_spec = importlib.util.spec_from_file_location('repair_passive_ports', SCRIPT)
repair = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(repair)


# The scanner's shipped portlist — what the sweep wrote into every host.
PORTLIST = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137,
    138, 139, 143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 520, 554, 587,
    631, 636, 993, 995, 1024, 1025, 1080, 1194, 1433, 1434, 1521, 1723, 1812,
    1813, 1883, 1900, 2049, 5000, 5432, 5900, 5985, 5986, 6379, 7000, 8080,
    8086, 8443, 8888, 9000, 9090, 9200,
}

# A real row from the reported incident: 53 ports, no 22 (the capture filter
# hid it), everything else straight out of the sweep.
SWEPT = {
    20, 21, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137, 138,
    139, 143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 520, 554, 587, 631,
    636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080,
    8086, 8443, 8888, 9000, 9090, 9200,
}


def poisoned(ports, min_ports=repair.DEFAULT_MIN_PORTS):
    return repair.is_poisoned(set(ports), PORTLIST, min_ports)


def test_recorded_sweep_is_caught():
    assert poisoned(SWEPT) is True


def test_sweep_merged_over_an_earlier_real_scan_is_caught():
    """Passive discovery merged into whatever a scan had already found, so a
    swept row can carry a couple of genuine ports too."""
    assert poisoned(SWEPT | {5000, 7000}) is True


def test_real_windows_server_is_left_alone():
    """Lots of privileged ports from the portlist, but none of the junk ones
    and SSH-free is not enough on its own."""
    dc = {53, 88, 135, 139, 389, 443, 445, 464, 636, 3268, 3269, 5985, 9389, 3389}
    assert poisoned(dc) is False


def test_busy_linux_server_answering_ssh_is_left_alone():
    """22 present means the capture filter cannot explain the row."""
    assert poisoned(SWEPT | {22}) is False


def test_small_port_list_is_left_alone():
    assert poisoned({22, 80, 443, 3306}) is False


def test_row_needs_the_implausible_services():
    """A large privileged-port set without ftp-data/tftp/nntp/bgp-style junk is
    a real host, not a sweep."""
    plausible = {25, 53, 80, 110, 143, 389, 443, 445, 465, 587, 636, 993, 995,
                 3306, 5432, 8080, 8443}
    assert len(plausible) >= repair.DEFAULT_MIN_PORTS
    assert poisoned(plausible) is False


def test_ports_outside_the_scanner_portlist_disqualify_when_dominant():
    """A row mostly made of ports the sweep never touches is a scan result."""
    exotic = {20, 69, 119, 179, 515} | set(range(30000, 30040))
    assert poisoned(exotic) is False


def test_parse_ports_ignores_junk():
    assert repair.parse_ports('80, 443,,x,8080') == {80, 443, 8080}
    assert repair.parse_ports('') == set()
    assert repair.parse_ports(None) == set()


@pytest.mark.parametrize("min_ports,expected", [(15, True), (60, False)])
def test_min_ports_threshold_is_honoured(min_ports, expected):
    assert poisoned(SWEPT, min_ports=min_ports) is expected
