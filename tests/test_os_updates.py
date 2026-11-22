"""Tests for os_updates.py - OS package (apt) updates from the web UI.

The runner is driven end to end against fake `apt-get` / `dpkg` executables on
PATH, so the real subprocess, streaming, progress and failure-classification
code runs without root and without touching the system's packages.
"""
import json
import os
import stat
import textwrap
import time

import pytest

import os_updates


APT_LIST_SAMPLE = textwrap.dedent("""\
    Listing...
    agnostics/stable 1.7 arm64 [upgradable from: 1.6]
    curl/stable-security,stable-security 8.14.1-2+deb13u7 arm64 [upgradable from: 8.14.1-2+deb13u4]
    tailscale/unknown 1.104.5 arm64 [upgradable from: 1.104.4]
    bind9-host/stable-security 1:9.20.30-1~deb13u1 arm64 [upgradable from: 1:9.20.26-1~deb13u1]
    cloudflared/unknown 2026.10.7 arm64 [upgradable from: 2026.7.3]
    tailscale/unknown 1.104.5 arm64 [upgradable from: 1.104.4]
    libc6/jammy-security 2.35-0ubuntu3.9 amd64 [upgradable from: 2.35-0ubuntu3.8]
    """)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def test_parse_upgradable_rows_security_first_and_deduped():
    pkgs = os_updates.parse_upgradable(APT_LIST_SAMPLE)
    names = [p['name'] for p in pkgs]
    assert names == ['bind9-host', 'curl', 'libc6', 'agnostics', 'cloudflared', 'tailscale']
    ts = os_updates.find_package(pkgs, 'tailscale')
    assert ts == {'name': 'tailscale', 'current': '1.104.4', 'candidate': '1.104.5',
                  'arch': 'arm64', 'suites': 'unknown', 'security': False}
    bind = os_updates.find_package(pkgs, 'bind9-host')
    assert bind['current'] == '1:9.20.26-1~deb13u1' and bind['security'] is True
    assert os_updates.find_package(pkgs, 'libc6')['security'] is True   # Ubuntu pocket


def test_parse_upgradable_ignores_noise():
    text = ('WARNING: apt does not have a stable CLI interface.\n\nListing... Done\n'
            'N: There is 1 additional version.\n')
    assert os_updates.parse_upgradable(text) == []


# ---------------------------------------------------------------------------
# Kernel / reboot
# ---------------------------------------------------------------------------

def _modules(tmp_path, names):
    d = tmp_path / 'modules'
    for n in names:
        (d / n).mkdir(parents=True)
    return str(d)


def test_kernel_newer_same_flavour_needs_reboot(tmp_path):
    d = _modules(tmp_path, ['6.18.39+rpt-rpi-2712', '6.18.50+rpt-rpi-2712',
                            '6.18.60+rpt-rpi-v8', '6.18.33-v8+'])
    k = os_updates.kernel_status('6.18.39+rpt-rpi-2712', d)
    assert k['newest'] == '6.18.50+rpt-rpi-2712' and k['reboot_pending'] is True


def test_kernel_other_flavours_and_older_are_ignored(tmp_path):
    d = _modules(tmp_path, ['6.18.39+rpt-rpi-2712', '6.12.62+rpt-rpi-2712',
                            '6.18.60+rpt-rpi-v8', '6.18.99-v8+'])
    k = os_updates.kernel_status('6.18.39+rpt-rpi-2712', d)
    assert k['reboot_pending'] is False


def test_kernel_debian_style_version(tmp_path):
    d = _modules(tmp_path, ['6.1.0-28-amd64', '6.1.0-31-amd64', '6.1.0-40-cloud-amd64'])
    k = os_updates.kernel_status('6.1.0-28-amd64', d)
    assert k['newest'] == '6.1.0-31-amd64' and k['reboot_pending'] is True


def test_needs_reboot_for():
    assert os_updates.needs_reboot_for(['curl', 'linux-image-6.18.50+rpt-rpi-2712'])
    assert os_updates.needs_reboot_for(['libc6'])
    assert not os_updates.needs_reboot_for(['tailscale', 'curl', 'agnostics'])


# ---------------------------------------------------------------------------
# Status file
# ---------------------------------------------------------------------------

def _status(tmp_path, data):
    p = tmp_path / 'os_update.json'
    p.write_text(json.dumps(data))
    return str(p)


def test_running_with_dead_pid_reads_as_interrupted(tmp_path):
    p = _status(tmp_path, {'state': 'running', 'pid': 999999999, 'boot_id': os_updates.boot_id()})
    s = os_updates.read_status(p)
    assert s['state'] == 'finished' and s['outcome'] == 'interrupted'


def test_running_after_reboot_reads_as_interrupted(tmp_path):
    # Our own PID is alive, but the boot id says it belongs to an earlier boot.
    p = _status(tmp_path, {'state': 'running', 'pid': os.getpid(), 'boot_id': 'old-boot'})
    assert os_updates.read_status(p)['outcome'] == 'interrupted'


def test_running_with_live_pid_stays_running(tmp_path):
    p = _status(tmp_path, {'state': 'running', 'pid': os.getpid(), 'boot_id': os_updates.boot_id()})
    assert os_updates.read_status(p)['state'] == 'running'


def test_just_launched_without_pid_is_running_then_expires(tmp_path, monkeypatch):
    monkeypatch.setattr(os_updates, '_unit_active', lambda: False)
    p = _status(tmp_path, {'state': 'running', 'pid': None, 'started': time.time()})
    assert os_updates.read_status(p)['state'] == 'running'
    p = _status(tmp_path, {'state': 'running', 'pid': None, 'started': time.time() - 3600})
    assert os_updates.read_status(p)['outcome'] == 'interrupted'


# ---------------------------------------------------------------------------
# Validation / launch
# ---------------------------------------------------------------------------

AVAILABLE = os_updates.parse_upgradable(APT_LIST_SAMPLE)


def test_validate_packages():
    assert os_updates.validate_packages(None, AVAILABLE) == ([], '')
    assert os_updates.validate_packages(['tailscale', 'Tailscale'], AVAILABLE) == (['tailscale'], '')
    clean, err = os_updates.validate_packages('tailscale', AVAILABLE)
    assert clean is None and 'list' in err
    clean, err = os_updates.validate_packages(['tailscale;reboot'], AVAILABLE)
    assert clean is None and 'not a valid' in err
    clean, err = os_updates.validate_packages(['-oAPT::Foo=1'], AVAILABLE)
    assert clean is None
    clean, err = os_updates.validate_packages(['htop'], AVAILABLE)   # not upgradable
    assert clean is None and 'no update' in err
    clean, err = os_updates.validate_packages(['a'] * 100, AVAILABLE)
    assert clean is None


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Point the module's state files at tmp and stub the system probes."""
    monkeypatch.setattr(os_updates, 'STATUS_PATH', str(tmp_path / 'logs' / 'os_update.json'))
    monkeypatch.setattr(os_updates, 'LOG_PATH', str(tmp_path / 'logs' / 'os_update.log'))
    monkeypatch.setattr(os_updates, 'PREV_LOG_PATH', str(tmp_path / 'logs' / 'os_update.prev.log'))
    monkeypatch.setattr(os_updates, 'supported', lambda: (True, ''))
    monkeypatch.setattr(os_updates, '_unit_active', lambda: False)
    monkeypatch.setattr(os_updates, 'list_upgradable', lambda force=False: {
        'ok': True, 'packages': AVAILABLE, 'count': len(AVAILABLE), 'security_count': 3})
    monkeypatch.setattr(os_updates, 'reboot_required', lambda flags=None: (False, ''))
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    monkeypatch.setenv('PATH', f'{bindir}:{os.environ.get("PATH", "")}')
    monkeypatch.setenv('FAKE_CALLS', str(tmp_path / 'calls.log'))
    # Never let a test reach the real sudo / systemd-run: a dev box has
    # passwordless sudo, and sudo's secure_path ignores the fake PATH above, so
    # a launch() test once started a REAL upgrade. Pretend to be root (no sudo
    # launcher at all) and shadow sudo with a fake that refuses, so even a
    # missed patch fails safe.
    monkeypatch.setattr(os_updates.os, 'geteuid', lambda: 0)
    _fake(bindir, 'sudo', 'exit 1\n')
    return tmp_path


def _fake(bindir, name, body):
    path = bindir / name
    path.write_text('#!/bin/bash\necho "$(basename "$0") $*" >> "$FAKE_CALLS"\n' + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _calls(sandbox):
    try:
        return (sandbox / 'calls.log').read_text().splitlines()
    except OSError:
        return []


def test_launch_refuses_unsupported(monkeypatch, sandbox):
    monkeypatch.setattr(os_updates, 'supported', lambda: (False, 'container'))
    assert os_updates.launch('check') == (False, 'unsupported', 'container')


def test_launch_refuses_bad_action_and_packages(sandbox):
    assert os_updates.launch('dist-upgrade')[1] == 'invalid'
    assert os_updates.launch('upgrade', ['htop'])[1] == 'invalid'
    assert not os.path.exists(os_updates.STATUS_PATH)  # nothing was started


def test_launch_refuses_when_nothing_to_upgrade(monkeypatch, sandbox):
    monkeypatch.setattr(os_updates, 'list_upgradable', lambda force=False: {
        'ok': True, 'packages': [], 'count': 0, 'security_count': 0})
    assert os_updates.launch('upgrade')[1] == 'invalid'


def test_launch_refuses_while_running(sandbox):
    os.makedirs(os.path.dirname(os_updates.STATUS_PATH))
    with open(os_updates.STATUS_PATH, 'w') as fh:
        json.dump({'state': 'running', 'pid': os.getpid(), 'boot_id': os_updates.boot_id()}, fh)
    assert os_updates.launch('check')[1] == 'busy'


def test_launch_uses_transient_unit(sandbox):
    _fake(sandbox / 'bin', 'systemd-run', 'exit 0\n')
    ok, code, _ = os_updates.launch('upgrade', ['tailscale'])
    assert ok and code == ''
    call = [c for c in _calls(sandbox) if c.startswith('systemd-run')][-1]
    assert '--unit=ragnar-os-update' in call and '--collect' in call
    assert call.endswith('os_updates.py run upgrade tailscale')
    status = json.load(open(os_updates.STATUS_PATH))
    assert status['state'] == 'running' and status['packages'] == ['tailscale']


def test_launch_non_root_goes_through_sudo(sandbox, monkeypatch):
    monkeypatch.setattr(os_updates.os, 'geteuid', lambda: 1000)
    _fake(sandbox / 'bin', 'systemd-run', 'exit 0\n')
    _fake(sandbox / 'bin', 'sudo', 'exit 0\n')      # fake sudo "succeeds" without running anything
    ok, code, _ = os_updates.launch('check')
    assert ok
    calls = _calls(sandbox)
    assert calls[0].startswith('sudo -n ') and '--unit=ragnar-os-update' in calls[0]
    # systemd-run is passed by absolute path, so sudo's secure_path cannot swap it
    assert calls[0].split()[2] == str(sandbox / 'bin' / 'systemd-run')
    assert not any(c.startswith('systemd-run') for c in calls)


def test_launch_unit_exists_is_busy(sandbox):
    _fake(sandbox / 'bin', 'systemd-run',
          'echo "Failed to start transient service unit: Unit ragnar-os-update.service already exists." >&2\nexit 1\n')
    assert os_updates.launch('check')[1] == 'busy'


# ---------------------------------------------------------------------------
# Runner, end to end against fake apt-get / dpkg
# ---------------------------------------------------------------------------

FAKE_APT = r'''
if [[ " $* " == *" -s "* ]]; then
  # Simulations: canned solver output, never touches anything.
  if [[ " $* " == *" upgrade "* ]]; then
    printf '%b\n' "${FAKE_SIM_UPGRADE:-0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.}"
  else
    printf '%b\n' "${FAKE_SIM_INSTALL:-}"
  fi
  exit ${FAKE_SIM_RC:-0}
fi
case " $* " in
  *" update "*)
    if [ -n "$FAKE_UPDATE_FAIL" ]; then echo "$FAKE_UPDATE_FAIL"; exit 100; fi
    echo "Hit:1 http://deb.debian.org/debian trixie InRelease"
    echo "Get:2 https://pkgs.tailscale.com/stable/debian trixie InRelease"
    exit 0 ;;
  *" clean "*) exit 0 ;;
esac
if [[ " $* " == *" -d "* ]]; then
  echo "Reading package lists..."
  echo "${FAKE_SUMMARY:-3 upgraded, 1 newly installed, 0 to remove and 2 not upgraded.}"
  echo "Need to get 41.5 MB of archives."
  echo "${FAKE_SPACE:-After this operation, 12.0 MB of additional disk space will be used.}"
  echo "Download complete and in download only mode"
  exit 0
fi
for p in ${FAKE_PKGS:-curl tailscale linux-image-6.18.50+rpt-rpi-2712 agnostics}; do
  echo "Preparing to unpack .../${p}.deb ..."
  echo "Unpacking ${p}:arm64 (9.9) over (9.8) ..."
done
for p in ${FAKE_PKGS:-curl tailscale linux-image-6.18.50+rpt-rpi-2712 agnostics}; do
  echo "Setting up ${p}:arm64 (9.9) ..."
done
exit ${FAKE_INSTALL_RC:-0}
'''


def _runner(sandbox, action, packages=(), allow_remove=()):
    _fake(sandbox / 'bin', 'apt-get', FAKE_APT)
    _fake(sandbox / 'bin', 'dpkg', 'exit 0\n')
    _fake(sandbox / 'bin', 'apt-mark', 'printf "%b" "${FAKE_HOLDS:-}"\n')
    return os_updates.Runner(action, list(packages),
                             status_path=os_updates.STATUS_PATH, log_path=os_updates.LOG_PATH,
                             disk_path=str(sandbox), allow_remove=list(allow_remove))


def _real(calls):
    """apt-get calls that could change something (everything but -s simulations)."""
    return [c for c in calls if c.startswith('apt-get') and ' -s ' not in c]


def _final(sandbox):
    return json.load(open(os_updates.STATUS_PATH))


def test_runner_check(sandbox):
    rc = _runner(sandbox, 'check').execute()
    st = _final(sandbox)
    assert rc == 0 and st['state'] == 'finished' and st['outcome'] == 'ok'
    assert st['last_check'] > 0 and st['pid'] is None
    calls = _calls(sandbox)
    assert any(' update' in c for c in calls)
    assert not any(' upgrade' in c or ' install' in c for c in _real(calls))
    assert any(' -s ' in c and 'upgrade --with-new-pkgs' in c for c in calls)  # held-back analysis
    assert st['held_back'] == []


def test_runner_upgrade_all(sandbox, monkeypatch):
    rc = _runner(sandbox, 'upgrade').execute()
    st = _final(sandbox)
    assert rc == 0 and st['outcome'] == 'ok', st
    assert st['upgraded'] == sorted(['agnostics', 'curl', 'linux-image-6.18.50+rpt-rpi-2712',
                                     'tailscale'])
    assert st['upgraded_count'] == 4
    assert st['tailscale_upgraded'] is True
    assert st['reboot_recommended'] is True          # linux-image in the set
    assert st['kept_back'] == 2 and st['download_mb'] == 41.5
    assert st['progress'] == {'done': 4, 'total': 4, 'current': 'agnostics'}
    calls = _calls(sandbox)
    upgrade_calls = [c for c in _real(calls) if 'upgrade --with-new-pkgs' in c]
    assert len(upgrade_calls) == 2 and ' -d ' in upgrade_calls[0] and ' -d ' not in upgrade_calls[1]
    assert all('--no-remove' in c for c in upgrade_calls)
    assert not any('full-upgrade' in c or 'dist-upgrade' in c or 'autoremove' in c for c in calls)
    assert any(c.startswith('dpkg --configure -a') for c in calls)
    # Non-interactive and keep-local-config on every apt call
    assert all('--force-confold' in c for c in calls if c.startswith('apt-get -y'))
    log = open(os_updates.LOG_PATH).read()
    assert 'Setting up tailscale:arm64' in log and '==> Finished: ok' in log


def test_runner_targeted_upgrade(sandbox, monkeypatch):
    monkeypatch.setenv('FAKE_PKGS', 'tailscale')
    monkeypatch.setenv('FAKE_SUMMARY', '1 upgraded, 0 newly installed, 0 to remove and 329 not upgraded.')
    rc = _runner(sandbox, 'upgrade', ['tailscale']).execute()
    st = _final(sandbox)
    assert rc == 0 and st['upgraded'] == ['tailscale'] and st['reboot_recommended'] is False
    calls = [c for c in _real(_calls(sandbox)) if 'install --only-upgrade tailscale' in c]
    assert len(calls) == 2
    assert all('--no-remove' in c for c in calls)   # a targeted upgrade never removes on its own


def test_runner_nothing_to_install(sandbox, monkeypatch):
    monkeypatch.setenv('FAKE_SUMMARY', '0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.')
    rc = _runner(sandbox, 'upgrade').execute()
    assert rc == 0 and _final(sandbox)['upgraded_count'] == 0
    assert len([c for c in _real(_calls(sandbox)) if 'upgrade --with-new-pkgs' in c]) == 1  # download only


def test_runner_disk_full_installs_nothing(sandbox, monkeypatch):
    monkeypatch.setenv('FAKE_SPACE', 'After this operation, 9,999,999 MB of additional disk space will be used.')
    rc = _runner(sandbox, 'upgrade').execute()
    st = _final(sandbox)
    assert rc == 1 and st['code'] == 'disk_full' and 'Not enough free space' in st['error']
    upgrade_calls = [c for c in _real(_calls(sandbox)) if 'upgrade --with-new-pkgs' in c]
    assert len(upgrade_calls) == 1 and ' -d ' in upgrade_calls[0]   # never reached install


@pytest.mark.parametrize('failure,code', [
    ('Err:1 http://deb.debian.org trixie InRelease\n  Temporary failure resolving deb.debian.org', 'offline'),
    ('W: GPG error: https://pkgs.tailscale.com/stable/debian trixie InRelease: NO_PUBKEY 458CA832957F5868', 'repo_key'),
    ('E: Could not get lock /var/lib/apt/lists/lock. It is held by process 42', 'locked'),
    ('E: something else entirely', 'apt_error'),
])
def test_runner_update_failures_stop_before_install(sandbox, monkeypatch, failure, code):
    monkeypatch.setenv('FAKE_UPDATE_FAIL', failure)
    rc = _runner(sandbox, 'upgrade').execute()
    st = _final(sandbox)
    assert rc == 1 and st['code'] == code, st
    assert not any('upgrade' in c for c in _calls(sandbox))
    if code == 'repo_key':
        assert 'pkgs.tailscale.com' in st['error']


def test_runner_install_failure(sandbox, monkeypatch):
    monkeypatch.setenv('FAKE_INSTALL_RC', '100')
    rc = _runner(sandbox, 'upgrade').execute()
    st = _final(sandbox)
    assert rc == 1 and st['code'] == 'dpkg_error' and st['state'] == 'finished'
    assert 'dpkg --configure -a' in st['hint']


def test_runner_never_left_running_on_crash(sandbox, monkeypatch):
    runner = _runner(sandbox, 'upgrade')
    monkeypatch.setattr(runner, 'refresh_lists', lambda: 1 / 0)
    assert runner.execute() == 1
    st = _final(sandbox)
    assert st['state'] == 'finished' and 'ZeroDivisionError' in st['error']


def test_overview_unsupported(monkeypatch):
    monkeypatch.setattr(os_updates, 'supported', lambda: (False, 'no apt'))
    ov = os_updates.overview()
    assert ov['supported'] is False and ov['reason'] == 'no apt'
    assert ov['available']['count'] == 0 and ov['tailscale'] is None


# ---------------------------------------------------------------------------
# Held-back packages (rpd-common needing pcmanfm replaced, on Raspberry Pi OS)
# ---------------------------------------------------------------------------

SIM_UPGRADE_KEPT = """Reading package lists...
Calculating upgrade...
The following packages have been kept back:
  rpd-common pinned-thing
  stuck-pkg
The following upgrades have been deferred due to phasing:
  ubuntu-phased
0 upgraded, 0 newly installed, 0 to remove and 4 not upgraded."""

SIM_INSTALL_RPD = """The following packages will be REMOVED:
  pcmanfm
Remv pcmanfm [1.4.0-1+rpt9] []
Inst rpd-common [1.18] (1.35 Raspberry Pi Foundation:stable [arm64]) []
Inst pcmanfm-pi (1.11 Raspberry Pi Foundation:stable [arm64]) []
Inst qt6gtk2 (0.3-1+rpt1 Raspberry Pi Foundation:stable [arm64]) []
Conf rpd-common (1.35 Raspberry Pi Foundation:stable [arm64])"""


def _fake_sim(outputs):
    """simulate() stand-in: picks canned output by the package being simulated."""
    def simulate(args):
        if args[0] == 'upgrade':
            return 0, SIM_UPGRADE_KEPT.splitlines()
        name = args[-1]
        rc, text = outputs[name]
        return rc, text.splitlines()
    return simulate


def test_apt_block_parses_multi_line_lists():
    lines = SIM_UPGRADE_KEPT.splitlines()
    assert os_updates.apt_block(lines, os_updates.KEPT_BACK_HEADER) == ['rpd-common', 'pinned-thing', 'stuck-pkg']
    assert os_updates.apt_block(lines, os_updates.PHASED_HEADER) == ['ubuntu-phased']
    assert os_updates.apt_block(['The following packages have been kept back:', '  a:arm64 b*'],
                                os_updates.KEPT_BACK_HEADER) == ['a', 'b']


def test_analyze_held_back_reasons():
    sim = _fake_sim({
        'rpd-common': (0, SIM_INSTALL_RPD),
        'stuck-pkg': (100, 'E: Unable to correct problems, you have held broken packages.'),
    })
    held = {h['name']: h for h in os_updates.analyze_held_back(sim, holds={'pinned-thing'})}
    rpd = held['rpd-common']
    assert rpd['reason'] == 'needs_removal' and rpd['removes'] == ['pcmanfm']
    assert rpd['new'] == ['pcmanfm-pi', 'qt6gtk2'] and rpd['candidate'] == '1.35'
    assert held['pinned-thing']['reason'] == 'hold'
    assert held['stuck-pkg']['reason'] == 'unresolvable' and 'held broken' in held['stuck-pkg']['detail']
    assert held['ubuntu-phased']['reason'] == 'phased'


def test_analyze_held_back_solver_only_and_failed_simulation():
    sim = _fake_sim({'rpd-common': (0, 'Inst rpd-common [1.18] (1.35 x [arm64])'),
                     'stuck-pkg': (0, ''), 'pinned-thing': (0, '')})
    held = {h['name']: h for h in os_updates.analyze_held_back(sim, holds=set())}
    assert held['rpd-common']['reason'] == 'solver' and held['rpd-common']['removes'] == []
    assert os_updates.analyze_held_back(lambda a: (None, ['boom']), holds=set()) is None


def test_annotate_held_counts_and_version_match():
    available = {'ok': True, 'count': 3, 'security_count': 1, 'packages': [
        {'name': 'rpd-common', 'current': '1.18', 'candidate': '1.35', 'security': False},
        {'name': 'curl', 'current': '1', 'candidate': '2', 'security': True},
        {'name': 'stale', 'current': '1', 'candidate': '3', 'security': False}]}
    held = [{'name': 'rpd-common', 'candidate': '1.35', 'reason': 'needs_removal', 'removes': ['pcmanfm'], 'new': []},
            {'name': 'stale', 'candidate': '2', 'reason': 'needs_removal', 'removes': ['x'], 'new': []}]
    out = os_updates.annotate_held(available, held)
    by = {p['name']: p for p in out['packages']}
    assert by['rpd-common']['held']['can_force'] is True and by['rpd-common']['held']['removes'] == ['pcmanfm']
    assert 'held' not in by['stale']          # newer candidate than the one analysed
    assert 'held' not in by['curl']
    assert out['held_count'] == 1 and out['upgradable_now'] == 2 and out['security_now'] == 1
    assert 'held' not in available['packages'][0]     # the cached list is not mutated


def test_upgrade_all_refused_when_only_held_back_remains(sandbox, monkeypatch):
    monkeypatch.setattr(os_updates, 'list_upgradable', lambda force=False: {
        'ok': True, 'count': 1, 'security_count': 0, 'packages': [
            {'name': 'rpd-common', 'current': '1.18', 'candidate': '1.35', 'security': False}]})
    os.makedirs(os.path.dirname(os_updates.STATUS_PATH))
    with open(os_updates.STATUS_PATH, 'w') as fh:
        json.dump({'state': 'finished', 'held_back': [
            {'name': 'rpd-common', 'candidate': '1.35', 'reason': 'needs_removal', 'removes': ['pcmanfm']}]}, fh)
    ok, code, msg = os_updates.launch('upgrade')
    assert not ok and code == 'invalid' and 'held back' in msg


def test_launch_passes_approved_removals(sandbox):
    _fake(sandbox / 'bin', 'systemd-run', 'exit 0\n')
    assert os_updates.launch('upgrade', ['tailscale'], ['pcmanfm'])[0]
    call = [c for c in _calls(sandbox) if c.startswith('systemd-run')][-1]
    assert call.endswith('os_updates.py run upgrade --allow-remove=pcmanfm tailscale')
    assert json.load(open(os_updates.STATUS_PATH))['allow_remove'] == ['pcmanfm']


def test_validate_removals():
    assert os_updates.validate_removals(None, ['a']) == ([], '')
    assert os_updates.validate_removals(['pcmanfm'], [])[0] is None        # removals need named packages
    assert os_updates.validate_removals('pcmanfm', ['a'])[0] is None
    assert os_updates.validate_removals(['x; rm -rf'], ['a'])[0] is None
    assert os_updates.validate_removals(['PCManFM', 'pcmanfm'], ['a']) == (['pcmanfm'], '')


def test_main_parses_allow_remove(monkeypatch):
    seen = {}

    class FakeRunner:
        def __init__(self, action, packages, allow_remove=None):
            seen.update(action=action, packages=packages, allow_remove=allow_remove)

        def execute(self):
            return 0
    monkeypatch.setattr(os_updates, 'Runner', FakeRunner)
    monkeypatch.setattr(os_updates, '_install_signal_handlers', lambda r: None)
    assert os_updates.main(['run', 'upgrade', '--allow-remove=pcmanfm,bad;x', 'rpd-common']) == 0
    assert seen == {'action': 'upgrade', 'packages': ['rpd-common'], 'allow_remove': ['pcmanfm']}


def test_runner_upgrade_anyway_with_approved_removal(sandbox, monkeypatch):
    monkeypatch.setenv('FAKE_SIM_INSTALL', SIM_INSTALL_RPD.replace('\n', '\\n'))
    monkeypatch.setenv('FAKE_PKGS', 'rpd-common pcmanfm-pi')
    monkeypatch.setenv('FAKE_SUMMARY', '1 upgraded, 1 newly installed, 1 to remove and 0 not upgraded.')
    rc = _runner(sandbox, 'upgrade', ['rpd-common'], ['pcmanfm']).execute()
    st = _final(sandbox)
    assert rc == 0 and st['outcome'] == 'ok', st
    assert st['planned_removals'] == ['pcmanfm']
    real = [c for c in _real(_calls(sandbox)) if 'install --only-upgrade rpd-common' in c]
    assert len(real) == 2 and not any('--no-remove' in c for c in real)


def test_runner_refuses_unapproved_removal(sandbox, monkeypatch):
    sim = SIM_INSTALL_RPD.replace('Remv pcmanfm', 'Remv lxterminal [1] []\nRemv pcmanfm')
    monkeypatch.setenv('FAKE_SIM_INSTALL', sim.replace('\n', '\\n'))
    rc = _runner(sandbox, 'upgrade', ['rpd-common'], ['pcmanfm']).execute()
    st = _final(sandbox)
    assert rc == 1 and st['code'] == 'removal_changed' and 'lxterminal' in st['error']
    assert not any('install' in c for c in _real(_calls(sandbox)))   # nothing downloaded or installed


def test_runner_targeted_needing_removal_fails_clearly(sandbox, monkeypatch):
    _runner(sandbox, 'upgrade', ['rpd-common'])   # writes the fakes
    _fake(sandbox / 'bin', 'apt-get', FAKE_APT.replace(
        'if [[ " $* " == *" -d "* ]]; then',
        'if [[ " $* " == *" --no-remove "* && " $* " == *" -d "* ]]; then\n'
        '  echo "E: Packages need to be removed but remove is disabled."; exit 100\nfi\n'
        'if [[ " $* " == *" -d "* ]]; then'))
    runner = os_updates.Runner('upgrade', ['rpd-common'], status_path=os_updates.STATUS_PATH,
                               log_path=os_updates.LOG_PATH, disk_path=str(sandbox))
    assert runner.execute() == 1
    st = _final(sandbox)
    assert st['code'] == 'needs_removal' and 'rpd-common' in st['error']


def test_runner_upgrade_all_records_held_back(sandbox, monkeypatch):
    monkeypatch.setenv('FAKE_SIM_UPGRADE', 'The following packages have been kept back:\\n  rpd-common\\n'
                                           '0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.')
    monkeypatch.setenv('FAKE_SIM_INSTALL', SIM_INSTALL_RPD.replace('\n', '\\n'))
    monkeypatch.setenv('FAKE_SUMMARY', '0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.')
    rc = _runner(sandbox, 'upgrade').execute()
    st = _final(sandbox)
    assert rc == 0 and st['held_count'] == 1
    assert st['held_back'][0]['name'] == 'rpd-common' and st['held_back'][0]['removes'] == ['pcmanfm']


def test_failed_run_keeps_previous_held_back(sandbox, monkeypatch):
    os.makedirs(os.path.dirname(os_updates.STATUS_PATH))
    with open(os_updates.STATUS_PATH, 'w') as fh:
        json.dump({'state': 'finished', 'held_back': [{'name': 'rpd-common'}]}, fh)
    monkeypatch.setenv('FAKE_UPDATE_FAIL', 'Temporary failure resolving deb.debian.org')
    _runner(sandbox, 'check').execute()
    assert _final(sandbox)['held_back'] == [{'name': 'rpd-common'}]


def test_launch_keeps_previous_log(sandbox):
    _fake(sandbox / 'bin', 'systemd-run', 'exit 0\n')
    os.makedirs(os.path.dirname(os_updates.LOG_PATH))
    with open(os_updates.LOG_PATH, 'w') as fh:
        fh.write('328 upgraded\n')
    monkeypatch_prev = os_updates.PREV_LOG_PATH
    assert os_updates.launch('check')[0]
    assert open(os_updates.LOG_PATH).read() == ''
    assert open(monkeypatch_prev).read() == '328 upgraded\n'
    assert os_updates.read_log(previous=True) == '328 upgraded\n'
