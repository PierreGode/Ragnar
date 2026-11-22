"""Tests for the IP range host-discovery sweep (Hosts tab "IP Range Scan").

The sweep expands a user range (CIDR or start-end), runs ``nmap -sn`` and
parses the XML into a live-host list. These tests cover the pure parsing /
range-expansion logic, which is where the sharp edges live:

- range expansion for CIDR, explicit start-end (full and short forms), a single
  IP and the unicode dashes a phone keyboard inserts
- the guard rails: a reversed range, an over-large range and malformed input all
  raise a user-facing ``ValueError``
- discovery XML parsing keeps only up-hosts and reads IP / hostname / MAC /
  vendor / response time
- nbstat XML parsing maps IP -> NetBIOS name and ignores ``<unknown>``
"""

import xml.etree.ElementTree as ET
from unittest.mock import MagicMock

import pytest

from actions.scanning import NetworkScanner


@pytest.fixture
def scanner():
    """A NetworkScanner stand-in carrying only what the methods under test use."""
    s = MagicMock()
    s.logger = MagicMock()
    s.MAX_RANGE_HOSTS = NetworkScanner.MAX_RANGE_HOSTS
    return s


def _expand(scanner, target):
    return NetworkScanner._expand_scan_range(scanner, target)


# ---------------------------------------------------------------------------
# range expansion
# ---------------------------------------------------------------------------

def test_expand_cidr_passes_through_as_single_target(scanner):
    targets, count = _expand(scanner, '192.168.1.0/24')
    assert targets == ['192.168.1.0/24']      # handed to nmap verbatim
    assert count == 254                         # usable hosts in a /24


def test_expand_cidr_slash30_and_slash32(scanner):
    assert _expand(scanner, '192.168.1.0/30')[1] == 2
    assert _expand(scanner, '192.168.1.5/32')[1] == 1


def test_expand_start_end_full_form(scanner):
    targets, count = _expand(scanner, '192.168.1.1-192.168.1.254')
    assert count == 254
    assert len(targets) == 254
    assert targets[0] == '192.168.1.1'
    assert targets[-1] == '192.168.1.254'


def test_expand_start_end_short_form_reuses_octets(scanner):
    targets, count = _expand(scanner, '192.168.1.10-20')
    assert count == 11
    assert targets[0] == '192.168.1.10'
    assert targets[-1] == '192.168.1.20'


def test_expand_normalises_unicode_dashes(scanner):
    # en-dash, em-dash and minus sign all count as a range separator
    for dash in ('–', '—', '−'):
        _, count = _expand(scanner, f'192.168.1.1{dash}192.168.1.5')
        assert count == 5


def test_expand_single_ip(scanner):
    targets, count = _expand(scanner, '10.0.0.5')
    assert targets == ['10.0.0.5']
    assert count == 1


def test_expand_rejects_reversed_range(scanner):
    with pytest.raises(ValueError, match='before its start'):
        _expand(scanner, '192.168.1.254-192.168.1.1')


def test_expand_rejects_oversized_range(scanner):
    with pytest.raises(ValueError, match='too large'):
        _expand(scanner, '10.0.0.0/16')


def test_expand_rejects_malformed_cidr(scanner):
    with pytest.raises(ValueError, match='Invalid CIDR'):
        _expand(scanner, '192.168.1.0/99')


def test_expand_rejects_empty(scanner):
    with pytest.raises(ValueError):
        _expand(scanner, '')


# ---------------------------------------------------------------------------
# discovery XML parsing
# ---------------------------------------------------------------------------

DISCOVERY_XML = """\
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme Corp"/>
    <hostnames><hostname name="box.local" type="PTR"/></hostnames>
    <times srtt="12450" rttvar="100" to="200000"/>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.11" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.12" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_discovery_keeps_only_up_hosts(scanner):
    hosts = NetworkScanner._parse_discovery_xml(scanner, ET.fromstring(DISCOVERY_XML))
    assert {h['ip'] for h in hosts} == {'192.168.1.10', '192.168.1.12'}


def test_discovery_reads_mac_vendor_hostname_and_rtt(scanner):
    hosts = NetworkScanner._parse_discovery_xml(scanner, ET.fromstring(DISCOVERY_XML))
    by_ip = {h['ip']: h for h in hosts}
    rich = by_ip['192.168.1.10']
    assert rich['mac'] == 'aa:bb:cc:dd:ee:ff'
    assert rich['vendor'] == 'Acme Corp'
    assert rich['hostname'] == 'box.local'
    assert rich['response_ms'] == 12.4          # srtt microseconds -> ms
    assert rich['status'] == 'up'


def test_discovery_bare_host_has_empty_fields(scanner):
    hosts = NetworkScanner._parse_discovery_xml(scanner, ET.fromstring(DISCOVERY_XML))
    bare = {h['ip']: h for h in hosts}['192.168.1.12']
    assert bare['mac'] == ''
    assert bare['vendor'] == ''
    assert bare['hostname'] == ''
    assert bare['response_ms'] is None


# ---------------------------------------------------------------------------
# nbstat XML parsing
# ---------------------------------------------------------------------------

NBSTAT_XML = """\
<nmaprun>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostscript>
      <script id="nbstat" output="NetBIOS name: WORKSTATION1, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: aa:bb:cc:dd:ee:ff"/>
    </hostscript>
  </host>
  <host>
    <address addr="192.168.1.11" addrtype="ipv4"/>
    <hostscript>
      <script id="nbstat" output="NetBIOS name: &lt;unknown&gt;, NetBIOS user: &lt;unknown&gt;"/>
    </hostscript>
  </host>
  <host>
    <address addr="192.168.1.12" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_nbstat_maps_ip_to_name_and_skips_unknown(scanner):
    names = NetworkScanner._parse_nbstat_xml(scanner, ET.fromstring(NBSTAT_XML))
    assert names == {'192.168.1.10': 'WORKSTATION1'}
