"""Tests for the Ragnar Mesh layer.

The mesh has no controller: every unit publishes its own report and reads its
peers', so a bug here does not degrade one node's view — it degrades all of
them identically. Two properties carry the weight:

* **Peer authentication fails closed.** `caller_is_mesh_peer` is what lets a
  request skip the login, so every path that cannot positively prove a tagged
  tailnet identity must return False. A permissive failure mode would expose
  Ragnar's endpoints to anything that can reach the port.

* **Cross-site correlation fuses on actors, not on coincidence.** Mesh units sit
  on different LANs that reuse the same address space. Correlating a private
  192.168.1.1 in Jersey with a private 192.168.1.1 in Stockholm would invent
  incidents; failing to correlate a public scanner hitting both would miss the
  one thing a mesh is for.
"""

import ipaddress

import pytest

import mesh_manager
from incident_engine import IncidentEngine, extract_entities


# ---------------------------------------------------------------------------
# The module's own self-test covers node normalization, key-expiry
# classification, URL building and auth-key validation. Run it here so a
# regression fails the suite rather than only a manual invocation.
# ---------------------------------------------------------------------------

def test_module_self_test_passes():
    assert mesh_manager._self_test() == 0


# ---------------------------------------------------------------------------
# Peer authentication
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('addr', [
    '',                       # no address at all
    '192.168.1.50',           # ordinary LAN host
    '10.0.0.5',               # RFC1918
    '8.8.8.8',                # public internet
    '127.0.0.1',              # loopback — a proxied request, origin unknowable
    '100.63.255.255',         # just below the tailnet range
    '100.128.0.0',            # just above the tailnet range
    'fe80::1',                # link-local IPv6
    'not-an-ip',              # garbage
])
def test_non_tailnet_addresses_are_never_peers(addr):
    """Anything outside Tailscale's range is refused without a lookup."""
    assert mesh_manager.caller_is_mesh_peer(addr) is False


def test_tailnet_range_boundaries():
    """100.64.0.0/10 exactly — the CGNAT block Tailscale allocates from."""
    assert mesh_manager.is_tailnet_addr('100.64.0.0') is True
    assert mesh_manager.is_tailnet_addr('100.127.255.255') is True
    assert mesh_manager.is_tailnet_addr('100.63.255.255') is False
    assert mesh_manager.is_tailnet_addr('100.128.0.0') is False


def test_tailnet_address_without_the_tag_is_refused(monkeypatch):
    """Tailnet membership alone must not grant access.

    This is the case that matters most: the operator's own laptop is a genuine,
    fully-authenticated tailnet node. It is not a Ragnar unit, and it must not
    be able to reach unit-to-unit endpoints without logging in.
    """
    monkeypatch.setattr(mesh_manager, 'installed', lambda: True)
    monkeypatch.setattr(mesh_manager, 'whois', lambda ip, ttl=None: {
        'node': 'laptop', 'dns_name': 'laptop.tailnet.ts.net',
        'tags': [], 'login': 'someone@example.com', 'display_name': 'Someone',
    })
    assert mesh_manager.caller_is_mesh_peer('100.78.0.3') is False


def test_tailnet_address_with_a_different_tag_is_refused(monkeypatch):
    monkeypatch.setattr(mesh_manager, 'installed', lambda: True)
    monkeypatch.setattr(mesh_manager, 'whois', lambda ip, ttl=None: {
        'node': 'ci-runner', 'tags': ['tag:ci'], 'login': '', 'display_name': '',
    })
    assert mesh_manager.caller_is_mesh_peer('100.78.0.4') is False


def test_tagged_peer_is_accepted(monkeypatch):
    monkeypatch.setattr(mesh_manager, 'installed', lambda: True)
    monkeypatch.setattr(mesh_manager, 'whois', lambda ip, ttl=None: {
        'node': 'ragnar-jersey', 'tags': ['tag:ragnar-mesh'],
        'login': 'tagged-devices', 'display_name': '',
    })
    assert mesh_manager.caller_is_mesh_peer('100.78.0.9') is True


def test_custom_tag_is_honoured(monkeypatch):
    """An operator inside a larger tailnet can scope the mesh to their own tag."""
    monkeypatch.setattr(mesh_manager, 'installed', lambda: True)
    monkeypatch.setattr(mesh_manager, 'whois', lambda ip, ttl=None: {
        'node': 'unit', 'tags': ['tag:acme-sensors'], 'login': '', 'display_name': '',
    })
    assert mesh_manager.caller_is_mesh_peer('100.78.0.9', 'tag:acme-sensors') is True
    assert mesh_manager.caller_is_mesh_peer('100.78.0.9', 'tag:ragnar-mesh') is False


def test_unresolvable_peer_is_refused(monkeypatch):
    """tailscaled silent (stopped, permissions, socket moved) means no access."""
    monkeypatch.setattr(mesh_manager, 'installed', lambda: True)
    monkeypatch.setattr(mesh_manager, 'whois', lambda ip, ttl=None: None)
    assert mesh_manager.caller_is_mesh_peer('100.78.0.9') is False


def test_missing_tailscale_refuses_everything(monkeypatch):
    monkeypatch.setattr(mesh_manager, 'installed', lambda: False)
    assert mesh_manager.caller_is_mesh_peer('100.78.0.9') is False


# ---------------------------------------------------------------------------
# Degraded transport
# ---------------------------------------------------------------------------

def test_status_without_tailscale_is_structured_not_raised(monkeypatch):
    """Ragnar must keep working on a box that never joins a tailnet."""
    monkeypatch.setattr(mesh_manager, 'binary_path', lambda: '')
    state = mesh_manager.status()
    assert state['available'] is False
    assert state['installed'] is False
    assert state['peers'] == []
    assert state['reason']


def test_status_with_daemon_down_reports_why(monkeypatch):
    monkeypatch.setattr(mesh_manager, 'binary_path', lambda: '/usr/bin/tailscale')
    monkeypatch.setattr(mesh_manager, 'raw_status', lambda force=False: None)
    state = mesh_manager.status()
    assert state['installed'] is True
    assert state['available'] is False
    assert 'not responding' in state['reason']


def test_needs_login_surfaces_the_auth_url(monkeypatch):
    monkeypatch.setattr(mesh_manager, 'binary_path', lambda: '/usr/bin/tailscale')
    monkeypatch.setattr(mesh_manager, 'raw_status', lambda force=False: {
        'BackendState': 'NeedsLogin', 'AuthURL': 'https://login.tailscale.com/a/abc',
        'Self': {}, 'Peer': {},
    })
    state = mesh_manager.status()
    assert state['available'] is False
    assert 'login.tailscale.com' in state['reason']


def test_join_rejects_a_bad_auth_key(monkeypatch):
    """Validated before shelling out, so a typo never reaches the CLI."""
    monkeypatch.setattr(mesh_manager, 'installed', lambda: True)
    called = []
    monkeypatch.setattr(mesh_manager, '_run', lambda *a, **k: called.append(a) or (0, '', ''))
    ok, message = mesh_manager.join('hunter2')
    assert ok is False
    assert 'tskey-' in message
    assert called == []


# ---------------------------------------------------------------------------
# Cross-site correlation scoping
# ---------------------------------------------------------------------------

def alert(src, target=None, source='arp_guard', codes=('gw_mac_change',)):
    return {'source': source, 'module': source, 'codes': list(codes),
            'ts': 1000.0, 'severity': 'high', 'src': src, 'target': target,
            'title': 'test', 'raw': {}}


def test_private_ips_are_scoped_per_site():
    """The same RFC1918 address at two sites is two different machines."""
    jersey = extract_entities(alert('192.168.1.1'), scope='Unit 01')
    stockholm = extract_entities(alert('192.168.1.1'), scope='Unit 02')
    assert jersey and stockholm
    assert not (jersey & stockholm)


def test_public_ips_still_fuse_across_sites():
    """One scanner hitting two sites is one campaign — the point of a mesh."""
    jersey = extract_entities(alert('45.33.32.156'), scope='Unit 01')
    stockholm = extract_entities(alert('45.33.32.156'), scope='Unit 02')
    assert jersey & stockholm


def test_non_routable_documentation_ranges_are_scoped():
    """TEST-NET / benchmarking / reserved space is not a routable actor.

    Python's `is_private` covers the whole IANA special-purpose registry, not
    just RFC1918 — 203.0.113.0/24, 198.18.0.0/15, 240.0.0.0/4 and friends. None
    of those can identify a host that reached two sites, so scoping them is
    correct rather than incidental.
    """
    for addr in ('203.0.113.9', '198.18.0.1', '192.0.2.5'):
        a = extract_entities(alert(addr), scope='Unit 01')
        b = extract_entities(alert(addr), scope='Unit 02')
        assert not (a & b), f'{addr} should be site-scoped'


def test_macs_fuse_across_sites():
    """A NIC seen at two sites is the same NIC, wherever it turns up."""
    jersey = extract_entities(alert('aa:bb:cc:dd:ee:ff'), scope='Unit 01')
    stockholm = extract_entities(alert('aa:bb:cc:dd:ee:ff'), scope='Unit 02')
    assert jersey & stockholm


def test_link_local_is_scoped():
    jersey = extract_entities(alert('169.254.1.5'), scope='Unit 01')
    stockholm = extract_entities(alert('169.254.1.5'), scope='Unit 02')
    assert not (jersey & stockholm)


def test_ssids_are_scoped_per_site():
    """'Guest WiFi' exists at every site and is a different network at each."""
    a = alert('aa:bb:cc:dd:ee:01', source='wifiwatch', codes=('evil_twin',))
    a['raw'] = {'ssid': 'Guest WiFi'}
    b = alert('aa:bb:cc:dd:ee:02', source='wifiwatch', codes=('evil_twin',))
    b['raw'] = {'ssid': 'Guest WiFi'}
    ents_a = {e for e in extract_entities(a, scope='Unit 01') if e[0] == 'ssid'}
    ents_b = {e for e in extract_entities(b, scope='Unit 02') if e[0] == 'ssid'}
    assert ents_a and ents_b
    assert not (ents_a & ents_b)


def test_unscoped_extraction_is_unchanged():
    """Local alerts pass no scope and must behave exactly as before."""
    assert extract_entities(alert('192.168.1.1')) == {('ip', '192.168.1.1')}


def test_engine_does_not_fuse_two_sites_on_a_private_collision():
    engine = IncidentEngine(window_s=600)
    engine.ingest(alert('192.168.1.1', source='arp_guard'), scope='Unit 01')
    engine.ingest(alert('192.168.1.1', source='ndpwatch',
                        codes=('ra_spoof',)), scope='Unit 02')
    assert len(engine.incidents()) == 2


def test_engine_fuses_two_sites_on_a_shared_public_actor():
    engine = IncidentEngine(window_s=600)
    engine.ingest(alert('45.33.32.156', source='certwatch',
                        codes=('cert_mismatch',)), scope='Unit 01')
    engine.ingest(alert('45.33.32.156', source='snmpwatch',
                        codes=('snmp_bruteforce',)), scope='Unit 02')
    incidents = engine.incidents()
    assert len(incidents) == 1
    # Both units' detectors land in the same incident, which is what makes the
    # cross-site campaign visible at all.
    assert len(incidents[0]['sources']) == 2


def test_scoped_private_addresses_are_still_valid_entities():
    """Scoping must namespace the value, not discard the entity."""
    ents = extract_entities(alert('192.168.1.1'), scope='Unit 07')
    assert ents == {('ip', 'Unit 07/192.168.1.1')}
