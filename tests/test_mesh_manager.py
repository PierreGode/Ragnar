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
# Tag membership — "on the tailnet" vs "in the mesh"
# ---------------------------------------------------------------------------
# The single most common first-run confusion: a unit is fully connected to
# Tailscale (BackendState Running) yet carries no mesh tag, so it shares no
# data. The status route decides mesh membership purely from the normalized
# node's `tags`, so that field must survive normalization faithfully — an
# untagged node must come out untagged, and only the exact tag counts.

def _node(tags):
    return mesh_manager.normalize_node(
        {'ID': 'n1', 'HostName': 'pi', 'DNSName': 'pi.ts.net.', 'OS': 'linux',
         'TailscaleIPs': ['100.78.0.5'], 'Online': True, 'Tags': tags},
        magic_dns_suffix='ts.net')


def test_untagged_node_is_not_in_the_mesh():
    """A Running-but-untagged node is the tester's exact state: on the tailnet,
    invisible to the mesh."""
    node = _node(None)
    assert node['tags'] == []
    assert 'tag:ragnar-mesh' not in node['tags']


def test_tagged_node_is_in_the_mesh():
    node = _node(['tag:ragnar-mesh'])
    assert 'tag:ragnar-mesh' in node['tags']


def test_a_different_tag_does_not_grant_membership():
    """Only the configured mesh tag counts — a node tagged for something else is
    still not a mesh unit."""
    node = _node(['tag:server', 'tag:prod'])
    assert 'tag:ragnar-mesh' not in node['tags']


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
# Raspberry Pi Connect status parsing
# ---------------------------------------------------------------------------
# Connect is a per-user service, and Ragnar runs as root — so a signed-in box
# looks signed-out unless queried in the login user's session. The parser must
# also read the real `rpi-connect status` text, where "Signed in: no" contains
# the substring "signed in" and trapped the first implementation.

def test_pi_connect_parse_off():
    p = mesh_manager._parse_pi_connect(
        '✗ Raspberry Pi Connect is not running, run rpi-connect on')
    assert p['running'] is False and p['signed_in'] is False


def test_pi_connect_parse_running_but_signed_out():
    """The exact string that made a signed-out box read as signed in."""
    p = mesh_manager._parse_pi_connect('Signed in: no\nTo sign in, run rpi-connect signin')
    assert p['running'] is True
    assert p['signed_in'] is False


def test_pi_connect_parse_signed_in():
    p = mesh_manager._parse_pi_connect(
        'Signed in: yes\nScreen sharing: allowed\nRemote shell: allowed')
    assert p['running'] is True
    assert p['signed_in'] is True


def test_pi_connect_parse_legacy_signed_in_as():
    p = mesh_manager._parse_pi_connect('Signed in as: someone@example.com')
    assert p['signed_in'] is True


def test_pi_connect_parse_empty():
    p = mesh_manager._parse_pi_connect('')
    assert p['running'] is False and p['signed_in'] is False


def test_pi_connect_login_uids_are_human(monkeypatch):
    """Only real login UIDs (>=1000) with a runtime dir are probed, never root."""
    monkeypatch.setattr(mesh_manager.os, 'listdir',
                        lambda p: ['0', '1000', '1001', 'not-a-uid'])
    assert mesh_manager._pi_connect_login_uids() == [1000, 1001]


def test_pi_connect_status_is_structured():
    s = mesh_manager.pi_connect_status()
    assert set(s) == {'installed', 'running', 'signed_in', 'user', 'detail'}
    assert isinstance(s['installed'], bool)


# ---------------------------------------------------------------------------
# diagnose_peer — turning "Ragnar's API did not answer" into the real cause
# ---------------------------------------------------------------------------
# A red "did not answer" card spans four causes with four different fixes.
# diagnose_peer must classify each so the operator gets the fix, not a guess.
# Each is one urlopen outcome, mocked here — no real network.

import urllib.error


class _FakeResp:
    def __init__(self, status, body):
        self.status = status
        self._body = body
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, *a): return self._body
    def getcode(self): return self.status


def _patch_urlopen(monkeypatch, behaviour):
    import urllib.request
    monkeypatch.setattr(urllib.request, 'urlopen', behaviour)


def test_diagnose_no_address():
    r = mesh_manager.diagnose_peer('')
    assert r['category'] == 'address'
    assert r['reachable'] is False


def test_diagnose_healthy_peer(monkeypatch):
    _patch_urlopen(monkeypatch,
                   lambda *a, **k: _FakeResp(200, b'{"success": true, "unit_id": 2}'))
    r = mesh_manager.diagnose_peer('100.78.0.9', port=8000)
    assert r['category'] == 'ok'
    assert r['reachable'] is True


def test_diagnose_something_else_on_the_port(monkeypatch):
    """200 but not Ragnar JSON — a different service is on that port."""
    _patch_urlopen(monkeypatch, lambda *a, **k: _FakeResp(200, b'<html>nginx</html>'))
    r = mesh_manager.diagnose_peer('100.78.0.9', port=8000)
    assert r['category'] == 'badbody'
    assert r['reachable'] is False


def test_diagnose_connection_refused(monkeypatch):
    """Nothing listening — the peer's Ragnar is down or on another port."""
    def refuse(*a, **k):
        raise urllib.error.URLError(ConnectionRefusedError('Connection refused'))
    _patch_urlopen(monkeypatch, refuse)
    r = mesh_manager.diagnose_peer('100.78.0.9', port=8000)
    assert r['category'] == 'refused'
    assert 'systemctl' in r['hint']


def test_diagnose_timeout_is_a_firewall_or_acl(monkeypatch):
    """Filtered, not closed — the ACL or a host firewall blocks the port."""
    def slow(*a, **k):
        raise urllib.error.URLError(TimeoutError('timed out'))
    _patch_urlopen(monkeypatch, slow)
    r = mesh_manager.diagnose_peer('100.78.0.9', port=8000)
    assert r['category'] == 'timeout'
    assert 'ACL' in r['hint'] or 'firewall' in r['hint']


def test_diagnose_bare_timeout_error(monkeypatch):
    """Some stacks raise TimeoutError directly rather than wrapping it."""
    def slow(*a, **k):
        raise TimeoutError('timed out')
    _patch_urlopen(monkeypatch, slow)
    r = mesh_manager.diagnose_peer('100.78.0.9', port=8000)
    assert r['category'] == 'timeout'


def test_diagnose_401_is_an_identity_problem(monkeypatch):
    """The peer answered but rejected this unit — a tag/auth issue, not a port."""
    def unauth(*a, **k):
        raise urllib.error.HTTPError('http://x', 401, 'Unauthorized', {}, None)
    _patch_urlopen(monkeypatch, unauth)
    r = mesh_manager.diagnose_peer('100.78.0.9', port=8000, mesh_tag='tag:ragnar-mesh')
    assert r['category'] == 'auth'
    assert 'tag:ragnar-mesh' in r['hint']


def test_diagnose_other_http_code(monkeypatch):
    def teapot(*a, **k):
        raise urllib.error.HTTPError('http://x', 418, "I'm a teapot", {}, None)
    _patch_urlopen(monkeypatch, teapot)
    r = mesh_manager.diagnose_peer('100.78.0.9', port=8000)
    assert r['category'] == 'http'
    assert '418' in r['error']


# ---------------------------------------------------------------------------
# `tailscale serve`
# ---------------------------------------------------------------------------
# With the tailnet's HTTPS Certificates feature disabled, `tailscale serve
# --https` does not return an error — it blocks indefinitely waiting for a
# certificate that can never be issued (confirmed against a live tailnet; it
# hangs even with stdin closed, so it is not an unanswered prompt). The only
# symptom is an unexplained timeout, so the precondition must be checked before
# the command is ever invoked.

def test_https_serve_refuses_when_certs_are_unavailable(monkeypatch):
    monkeypatch.setattr(mesh_manager, 'installed', lambda: True)
    monkeypatch.setattr(mesh_manager, 'https_available', lambda: False)
    ran = []
    monkeypatch.setattr(mesh_manager, '_run',
                        lambda *a, **k: ran.append(a) or (0, '', ''))

    ok, message = mesh_manager.serve_web(enable=True, use_https=True)
    assert ok is False
    # The command must never be reached — reaching it *is* the hang.
    assert ran == []
    assert 'not enabled' in message.lower()
    assert 'login.tailscale.com' in message


def test_http_serve_works_without_certs(monkeypatch):
    """Plain HTTP needs no certificate, so it stays available as the fallback."""
    monkeypatch.setattr(mesh_manager, 'installed', lambda: True)
    monkeypatch.setattr(mesh_manager, 'https_available', lambda: False)
    monkeypatch.setattr(mesh_manager, 'magic_dns_name', lambda: 'unit.tailnet.ts.net')
    captured = {}

    def fake_run(args, timeout=None):
        captured['args'] = list(args)
        return 0, 'Serve started', ''

    monkeypatch.setattr(mesh_manager, '_run', fake_run)
    ok, message = mesh_manager.serve_web(port=8000, enable=True, use_https=False)
    assert ok is True
    assert '--http' in captured['args'] and '80' in captured['args']
    assert '--https' not in captured['args']
    assert 'unit.tailnet.ts.net' in message


def test_publish_defaults_to_http(monkeypatch):
    """HTTP is the default path — no use_https means plain HTTP, no cert check."""
    monkeypatch.setattr(mesh_manager, 'installed', lambda: True)
    # If the default were HTTPS this would be consulted and, being False, refuse.
    monkeypatch.setattr(mesh_manager, 'https_available', lambda: False)
    monkeypatch.setattr(mesh_manager, 'magic_dns_name', lambda: 'unit.tailnet.ts.net')
    captured = {}
    monkeypatch.setattr(mesh_manager, '_run',
                        lambda args, timeout=None: captured.update(args=list(args)) or (0, '', ''))
    ok, _ = mesh_manager.serve_web(port=8000, enable=True)   # no use_https
    assert ok is True
    assert '--http' in captured['args'] and '--https' not in captured['args']


def test_stopping_serve_clears_both_schemes(monkeypatch):
    """Stop must fully unpublish regardless of which scheme was live, and must
    never depend on the cert feature being available."""
    monkeypatch.setattr(mesh_manager, 'installed', lambda: True)
    monkeypatch.setattr(mesh_manager, 'https_available', lambda: False)
    calls = []
    monkeypatch.setattr(mesh_manager, '_run',
                        lambda args, timeout=None: calls.append(list(args)) or (0, '', ''))
    ok, message = mesh_manager.serve_web(enable=False, use_https=True)
    assert ok is True
    assert 'stopped' in message.lower()
    # Both an https-off and an http-off were issued.
    assert any('--https' in c and 'off' in c for c in calls)
    assert any('--http' in c and 'off' in c for c in calls)


def test_https_serve_proceeds_when_certs_are_available(monkeypatch):
    monkeypatch.setattr(mesh_manager, 'installed', lambda: True)
    monkeypatch.setattr(mesh_manager, 'https_available', lambda: True)
    monkeypatch.setattr(mesh_manager, 'magic_dns_name', lambda: 'unit.tailnet.ts.net')
    captured = {}

    def fake_run(args, timeout=None):
        captured['args'] = list(args)
        captured['timeout'] = timeout
        return 0, '', ''

    monkeypatch.setattr(mesh_manager, '_run', fake_run)
    ok, _ = mesh_manager.serve_web(port=8000, enable=True, use_https=True)
    assert ok is True
    assert '--https' in captured['args']
    # Real certificate issuance goes out to Let's Encrypt and is slow; a short
    # timeout here would fail a request that was going to succeed.
    assert captured['timeout'] >= 60


def test_https_available_reads_cert_domains(monkeypatch):
    monkeypatch.setattr(mesh_manager, 'raw_status',
                        lambda force=False: {'CertDomains': ['unit.tailnet.ts.net']})
    assert mesh_manager.https_available() is True
    monkeypatch.setattr(mesh_manager, 'raw_status', lambda force=False: {'CertDomains': None})
    assert mesh_manager.https_available() is False
    monkeypatch.setattr(mesh_manager, 'raw_status', lambda force=False: {})
    assert mesh_manager.https_available() is False
    monkeypatch.setattr(mesh_manager, 'raw_status', lambda force=False: None)
    assert mesh_manager.https_available() is False


def test_permission_failure_is_explained(monkeypatch):
    """Ragnar runs as root, but a hand-run instance may not — say so plainly."""
    monkeypatch.setattr(mesh_manager, 'installed', lambda: True)
    monkeypatch.setattr(mesh_manager, 'https_available', lambda: True)
    monkeypatch.setattr(mesh_manager, '_run', lambda *a, **k:
                        (1, '', 'Access denied: serve config denied'))
    ok, message = mesh_manager.serve_web(enable=True, use_https=True)
    assert ok is False
    assert 'root' in message.lower()


def test_subprocess_never_inherits_stdin():
    """A prompt-on-stdin would hang until the timeout and explain nothing."""
    import inspect
    source = inspect.getsource(mesh_manager._run)
    assert 'stdin=subprocess.DEVNULL' in source


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


# ── poll_mesh: the idle-peer fix ────────────────────────────────────────────
# Tailscale's Online flag lags real reachability; skipping "offline" peers is
# what silently stopped data sharing once units went idle. include_offline lets
# the mesh poll them anyway (the poll is the keepalive).

def _nodes():
    return [
        {'id': 'a', 'ip': '100.0.0.1', 'online': True, 'is_self': False},
        {'id': 'b', 'ip': '100.0.0.2', 'online': False, 'is_self': False},
        {'id': 's', 'ip': '100.0.0.9', 'online': True, 'is_self': True},
    ]


def test_poll_mesh_skips_offline_by_default(monkeypatch):
    polled = []
    monkeypatch.setattr(mesh_manager, 'poll_peer',
                        lambda n, *a, **k: (polled.append(n['id']) or {'reachable': True}))
    mesh_manager.poll_mesh(_nodes(), timeout=1)
    assert polled == ['a']            # offline 'b' and self 's' excluded


def test_poll_mesh_includes_offline_when_asked(monkeypatch):
    polled = []
    monkeypatch.setattr(mesh_manager, 'poll_peer',
                        lambda n, *a, **k: (polled.append(n['id']) or {'reachable': True}))
    mesh_manager.poll_mesh(_nodes(), timeout=1, include_offline=True)
    assert sorted(polled) == ['a', 'b']   # offline 'b' now polled; self still excluded


# ── command_peer: the mesh write path ───────────────────────────────────────

def test_command_peer_no_address():
    r = mesh_manager.command_peer({'id': 'x'}, 'traffic', 'start')
    assert r['reachable'] is False and r['success'] is False


def test_command_peer_success(monkeypatch):
    _patch_urlopen(monkeypatch,
                   lambda *a, **k: _FakeResp(200, b'{"success": true, "running": true}'))
    r = mesh_manager.command_peer({'id': 'a', 'ip': '100.0.0.1'}, 'traffic', 'start')
    assert r['reachable'] is True and r['success'] is True and r['running'] is True


def test_command_peer_rejected_by_tag(monkeypatch):
    def unauth(*a, **k):
        raise urllib.error.HTTPError('u', 401, 'Unauthorized', {}, None)
    _patch_urlopen(monkeypatch, unauth)
    r = mesh_manager.command_peer({'id': 'a', 'ip': '100.0.0.1'}, 'traffic', 'start')
    assert r['reachable'] is False and 'mesh tag' in r['error']
