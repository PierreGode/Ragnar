#!/usr/bin/env python3
"""os_updates.py - operating-system package updates (apt) from the web UI.

Ragnar's own updater (git_updater.py) only moves Ragnar's code. Everything else
on the box comes from apt: the kernel, OpenSSL/curl/bind security fixes, and
the third-party repositories the installer adds - Tailscale
(pkgs.tailscale.com) above all, which is what the mesh runs on. Before this
module nothing in the UI touched any of that, so a unit only received OS fixes
when someone SSH'd in and ran apt by hand.

The module has two halves.

Library side (imported by webapp_modern.py). Cheap reads only: the upgradable
list (`apt list --upgradable`, cached against the apt/dpkg state it was computed
from, because every open dashboard tab polls), the status of the current or last
run, and launching a run. Nothing on this side talks to the network or takes the
dpkg lock.

Runner side (`python3 os_updates.py run check|upgrade [pkg ...]`). The slow work.
It is started in a transient systemd unit (ragnar-os-update) because an upgrade
can restart the very things the browser is talking through: tailscaled (which
drops a tailnet browser for a few seconds), NetworkManager / wpa_supplicant, or
ragnar.service itself. A run inside ragnar.service's cgroup dies with that
restart, part-way through dpkg, and leaves a half-configured system. A transient
unit does not.

Safety choices:
  * `apt-get upgrade --with-new-pkgs`, never `full-upgrade`: it may install new
    dependencies (new kernels need them) but it never removes a package, so an
    upgrade cannot uninstall a tool Ragnar depends on. Targeted upgrades run with
    `--no-remove` for the same reason.
  * A package that can only be upgraded by removing another one is "held back".
    After every run the runner works out why (what it would remove, what it
    would add, or that it is on hold / in a phased rollout) so the card can say
    so instead of listing it as upgradable forever. Upgrading it anyway takes an
    explicit list of removals the operator approved, and the run stops if apt
    wants to remove anything beyond that list.
  * Download first, install second. A dropped connection during the download
    leaves the system untouched; the free-space check runs between the two,
    using apt's own estimate of how much the install will add.
  * Non-interactive throughout (debconf, conffile prompts, apt-listchanges,
    needrestart), keeping the local version of any changed config file.
"""

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(REPO_ROOT, 'data', 'logs')
STATUS_PATH = os.path.join(LOG_DIR, 'os_update.json')
LOG_PATH = os.path.join(LOG_DIR, 'os_update.log')
PREV_LOG_PATH = os.path.join(LOG_DIR, 'os_update.prev.log')

UNIT_NAME = 'ragnar-os-update'
APT_LISTS_DIR = '/var/lib/apt/lists'
DPKG_STATUS = '/var/lib/dpkg/status'
REBOOT_FLAGS = ('/run/reboot-required', '/var/run/reboot-required')

# apt's own "After this operation, N MB will be used" estimate is what the
# install needs; this is the headroom kept on top of it so dpkg never fills the
# card mid-unpack (a full root filesystem halfway through dpkg is the one way an
# upgrade really breaks a box).
FREE_SPACE_MARGIN_MB = 300

# How long apt waits for another package manager (apt-daily, an SSH session)
# to let go of the lock before giving up.
LOCK_WAIT_SECONDS = 600

# A run that was just launched has no PID in the status file yet. Until this
# long has passed it counts as starting, not as a crashed run.
LAUNCH_GRACE_SECONDS = 90

LIST_TIMEOUT = 180          # `apt list` on a Pi Zero with Kali-size lists
UPDATE_TIMEOUT = 20 * 60    # `apt-get update` over a slow uplink

MAX_PACKAGES = 64
MAX_HELD = 20              # held-back packages analysed per run (one simulation each)
SIM_TIMEOUT = 10 * 60      # the upgrade solver on a Pi Zero with hundreds of packages
_PKG_NAME = re.compile(r'^[a-z0-9][a-z0-9+.\-]{0,127}$')

# Packages whose upgrade only takes effect after a reboot. Matched by prefix.
_REBOOT_PREFIXES = (
    'linux-image', 'linux-firmware', 'raspi-firmware', 'raspberrypi-kernel',
    'raspberrypi-bootloader', 'rpi-eeprom', 'firmware-', 'libc6', 'systemd',
    'dbus', 'udev', 'libssl', 'openssl',
)

_APT_ENV = {
    'LC_ALL': 'C',
    'LANG': 'C',
    'DEBIAN_FRONTEND': 'noninteractive',
    'DEBCONF_NONINTERACTIVE_SEEN': 'true',
    'APT_LISTCHANGES_FRONTEND': 'none',
    'NEEDRESTART_MODE': 'l',        # list only: never restart services on its own
    'UCF_FORCE_CONFFOLD': '1',
}

_APT_OPTS = [
    '-q',
    '-o', f'DPkg::Lock::Timeout={LOCK_WAIT_SECONDS}',
    '-o', 'Dpkg::Options::=--force-confdef',
    '-o', 'Dpkg::Options::=--force-confold',
    '-o', 'Dpkg::Use-Pty=0',
    '-o', 'APT::Color=0',
]


def _env():
    env = dict(os.environ)
    env.update(_APT_ENV)
    path = env.get('PATH', '')
    for extra in ('/usr/sbin', '/sbin', '/usr/bin', '/bin'):
        if extra not in path.split(':'):
            path = f'{path}:{extra}' if path else extra
    env['PATH'] = path
    return env


# ---------------------------------------------------------------------------
# Capability
# ---------------------------------------------------------------------------

def in_container():
    """True inside Docker/Podman, where OS packages come with the image."""
    if os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv'):
        return True
    try:
        with open('/proc/1/cgroup', 'r') as fh:
            text = fh.read()
        return any(tag in text for tag in ('docker', 'containerd', 'kubepods', 'libpod'))
    except OSError:
        return False


def supported():
    """(ok, reason). `reason` is one sentence the UI can show as-is."""
    if in_container():
        return False, ('Ragnar is running in a container: its OS packages come with the '
                       'image. Pull or rebuild the image to update them.')
    if not shutil.which('apt-get') or not shutil.which('dpkg'):
        return False, ('This system does not use apt. Update its packages with your '
                       "distribution's package manager.")
    return True, ''


# ---------------------------------------------------------------------------
# Upgradable list
# ---------------------------------------------------------------------------

# tailscale/unknown 1.104.5 arm64 [upgradable from: 1.104.4]
# curl/stable-security,stable-security 8.14.1-2+deb13u7 arm64 [upgradable from: 8.14.1-2+deb13u4]
_UPGRADABLE_LINE = re.compile(
    r'^(?P<name>[a-z0-9][a-z0-9+.\-]*)/(?P<suites>\S+)\s+(?P<candidate>\S+)\s+'
    r'(?P<arch>\S+)\s+\[upgradable from:\s*(?P<current>[^\]]+)\]')


def is_security_suite(suites):
    """True when any suite the candidate comes from is a security pocket."""
    return any('security' in s.lower() for s in (suites or '').split(','))


def parse_upgradable(text):
    """Parse `apt list --upgradable` output into package dicts.

    Security fixes sort first, then by name. Lines that are not package rows
    ("Listing...", the unstable-CLI warning) are skipped.
    """
    packages = []
    seen = set()
    for line in (text or '').splitlines():
        m = _UPGRADABLE_LINE.match(line.strip())
        if not m:
            continue
        name = m.group('name')
        if name in seen:
            continue
        seen.add(name)
        suites = m.group('suites')
        packages.append({
            'name': name,
            'current': m.group('current').strip(),
            'candidate': m.group('candidate'),
            'arch': m.group('arch'),
            'suites': suites,
            'security': is_security_suite(suites),
        })
    packages.sort(key=lambda p: (not p['security'], p['name']))
    return packages


def _mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def _state_key():
    """Changes whenever apt's lists or the installed set change."""
    return (_mtime(APT_LISTS_DIR), _mtime(os.path.join(APT_LISTS_DIR, 'partial')),
            _mtime(DPKG_STATUS))


_list_lock = threading.Lock()
_list_cache = {'key': None, 'result': None}


def list_upgradable(force=False):
    """The upgradable packages, recomputed only when apt's state changed.

    Never runs while a package run is active: dpkg rewrites its status file
    continuously during an install, so recomputing then would run `apt list`
    on every poll and read a half-written state.
    """
    with _list_lock:
        cached = _list_cache['result']
        if cached is not None and not force:
            if is_running() or _list_cache['key'] == _state_key():
                return cached
        key = _state_key()
        result = _compute_upgradable()
        _list_cache['key'] = key
        _list_cache['result'] = result
        return result


def _compute_upgradable():
    ok, reason = supported()
    if not ok:
        return {'ok': False, 'error': reason, 'packages': [], 'count': 0,
                'security_count': 0, 'computed_at': time.time()}
    try:
        proc = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True,
                              text=True, timeout=LIST_TIMEOUT, env=_env(),
                              stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': f'apt list timed out after {LIST_TIMEOUT}s.',
                'packages': [], 'count': 0, 'security_count': 0,
                'computed_at': time.time()}
    except OSError as exc:
        return {'ok': False, 'error': f'Could not run apt: {exc}', 'packages': [],
                'count': 0, 'security_count': 0, 'computed_at': time.time()}
    packages = parse_upgradable(proc.stdout)
    result = {
        'ok': proc.returncode == 0,
        'error': '' if proc.returncode == 0 else (proc.stderr.strip().splitlines() or
                                                  ['apt list failed'])[-1],
        'packages': packages,
        'count': len(packages),
        'security_count': sum(1 for p in packages if p['security']),
        'computed_at': time.time(),
    }
    return result


def find_package(packages, name):
    for pkg in packages or []:
        if pkg.get('name') == name:
            return pkg
    return None


# ---------------------------------------------------------------------------
# Held-back packages
# ---------------------------------------------------------------------------
# `apt list --upgradable` lists every package with a newer candidate, including
# ones `upgrade --with-new-pkgs` will never install. Without this the card
# offered "Upgrade All (1)" for a package that each run then quietly skipped
# (rpd-common 1.35 on Raspberry Pi OS, which needs pcmanfm replaced by
# pcmanfm-pi), so the box looked stuck.

KEPT_BACK_HEADER = 'The following packages have been kept back:'
PHASED_HEADER = 'The following upgrades have been deferred due to phasing:'

_SIM_INST = re.compile(r'^Inst (?P<name>[a-z0-9][a-z0-9+.\-]*)(?::\S+)? '
                       r'(?:\[(?P<old>[^\]]*)\] )?\((?P<new>\S+)')
_SIM_REMV = re.compile(r'^Remv (?P<name>[a-z0-9][a-z0-9+.\-]*)(?::\S+)?(?: |$)')

HELD_REASONS = {
    'needs_removal': 'Upgrading it means removing another package.',
    'solver': 'Upgrade All leaves it alone, but it can be upgraded on its own.',
    'hold': 'It is on hold (apt-mark hold), so apt will not upgrade it.',
    'phased': ('Phased rollout: the distribution is releasing it gradually. It installs '
               'by itself once this box is included.'),
    'unresolvable': 'apt cannot upgrade it without breaking another package.',
}


def apt_block(lines, header):
    """Package names listed under an apt header line ("... kept back:")."""
    names = []
    inside = False
    for line in lines or []:
        if inside:
            if line.startswith(' '):
                for token in line.split():
                    token = token.rstrip('*').split(':', 1)[0]
                    if _PKG_NAME.match(token) and token not in names:
                        names.append(token)
                continue
            inside = False
        if line.strip().startswith(header):
            inside = True
    return names


def _simulate(args, timeout=SIM_TIMEOUT):
    """apt-get -s: never needs the lock and never changes anything."""
    cmd = ['apt-get', '-s', '-o', 'Debug::NoLocking=1', '-o', 'APT::Color=0'] + list(args)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              env=_env(), stdin=subprocess.DEVNULL, errors='replace')
    except (subprocess.TimeoutExpired, OSError) as exc:
        return None, [str(exc)]
    return proc.returncode, (proc.stdout + '\n' + proc.stderr).splitlines()


def apt_holds():
    try:
        proc = subprocess.run(['apt-mark', 'showhold'], capture_output=True, text=True,
                              timeout=60, env=_env(), stdin=subprocess.DEVNULL)
    except (subprocess.TimeoutExpired, OSError):
        return set()
    return {l.strip().split(':', 1)[0] for l in proc.stdout.splitlines() if l.strip()}


def simulate_install(packages, simulate=_simulate):
    """What `install --only-upgrade <packages>` would do: (rc, removes, new, versions, errors)."""
    rc, lines = simulate(['install', '--only-upgrade'] + list(packages))
    removes, new, versions = [], [], {}
    for line in lines:
        m = _SIM_REMV.match(line)
        if m:
            removes.append(m.group('name'))
            continue
        m = _SIM_INST.match(line)
        if m:
            versions[m.group('name')] = m.group('new')
            if m.group('old') is None and m.group('name') not in packages:
                new.append(m.group('name'))
    errors = [l.strip() for l in lines if l.startswith('E:')][:3]
    return rc, removes, new, versions, errors


def analyze_held_back(simulate=_simulate, holds=None, limit=MAX_HELD):
    """Which upgradable packages Upgrade All will skip, and why.

    Returns a list of {name, candidate, reason, removes, new, detail}, or None
    when the simulation itself failed (callers then keep what they knew).
    """
    rc, lines = simulate(['upgrade', '--with-new-pkgs'])
    if rc is None or rc != 0:
        return None
    holds = apt_holds() if holds is None else set(holds)
    held = []
    for name in apt_block(lines, KEPT_BACK_HEADER)[:limit]:
        entry = {'name': name, 'candidate': '', 'removes': [], 'new': [], 'detail': ''}
        if name in holds:
            entry['reason'] = 'hold'
            held.append(entry)
            continue
        rc2, removes, new, versions, errors = simulate_install([name], simulate)
        entry.update(candidate=versions.get(name, ''), removes=removes, new=new)
        if rc2 == 0 and removes:
            entry['reason'] = 'needs_removal'
        elif rc2 == 0:
            entry['reason'] = 'solver'
        else:
            entry['reason'] = 'unresolvable'
            entry['detail'] = ' '.join(errors)
        held.append(entry)
    for name in apt_block(lines, PHASED_HEADER)[:limit]:
        held.append({'name': name, 'candidate': '', 'reason': 'phased', 'removes': [],
                     'new': [], 'detail': ''})
    return held


def annotate_held(available, held):
    """Copy of `available` with each held-back package marked.

    A held entry only applies while the candidate is the version that was
    analysed: once a newer one appears it has to be looked at again, so it is
    shown as an ordinary upgrade until the next run says otherwise.
    """
    by_name = {h.get('name'): h for h in held or [] if h.get('name')}
    packages = []
    held_count = held_security = 0
    for pkg in available.get('packages') or []:
        pkg = dict(pkg)
        info = by_name.get(pkg['name'])
        if info and (not info.get('candidate') or info.get('candidate') == pkg['candidate']):
            pkg['held'] = {
                'reason': info.get('reason', 'solver'),
                'explanation': HELD_REASONS.get(info.get('reason'), ''),
                'removes': list(info.get('removes') or []),
                'new': list(info.get('new') or []),
                'detail': info.get('detail', ''),
                'can_force': info.get('reason') in ('needs_removal', 'solver'),
            }
            held_count += 1
            held_security += 1 if pkg.get('security') else 0
        packages.append(pkg)
    out = dict(available)
    out['packages'] = packages
    out['held_count'] = held_count
    out['upgradable_now'] = max(0, len(packages) - held_count)
    out['security_now'] = max(0, int(available.get('security_count') or 0) - held_security)
    return out


# ---------------------------------------------------------------------------
# Reboot state
# ---------------------------------------------------------------------------

_KVER = re.compile(r'^(\d+(?:\.\d+)*(?:-\d+)?)(.*)$')


def _version_tuple(ver):
    return tuple(int(x) for x in re.findall(r'\d+', ver or ''))


def kernel_status(running=None, modules_dir='/lib/modules'):
    """Running kernel vs the newest installed one of the same flavour.

    On a Pi the flavour is the part after the version ("+rpt-rpi-2712"), and
    both the 2712 and v8 images are installed side by side, so only the
    running flavour is compared.
    """
    if running is None:
        running = os.uname().release
    m = _KVER.match(running)
    if not m:
        return {'running': running, 'newest': running, 'reboot_pending': False}
    run_ver, flavour = m.group(1), m.group(2)
    newest_ver, newest = run_ver, running
    try:
        entries = os.listdir(modules_dir)
    except OSError:
        entries = []
    for entry in entries:
        em = _KVER.match(entry)
        if not em or em.group(2) != flavour:
            continue
        if not os.path.isdir(os.path.join(modules_dir, entry)):
            continue
        if _version_tuple(em.group(1)) > _version_tuple(newest_ver):
            newest_ver, newest = em.group(1), entry
    return {'running': running, 'newest': newest, 'reboot_pending': newest != running}


def reboot_required(flags=REBOOT_FLAGS):
    """(required, why). Debian's flag file, or a newer kernel waiting."""
    for flag in flags:
        if os.path.exists(flag):
            return True, 'A package asked for a reboot to finish its update.'
    kernel = kernel_status()
    if kernel['reboot_pending']:
        return True, (f"Kernel {kernel['newest']} is installed but {kernel['running']} "
                      'is still running.')
    return False, ''


def needs_reboot_for(names):
    return any(str(n).startswith(_REBOOT_PREFIXES) for n in names or [])


# ---------------------------------------------------------------------------
# Run status
# ---------------------------------------------------------------------------

def _write_json_atomic(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f'{path}.tmp.{os.getpid()}'
    with open(tmp, 'w') as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def _read_json(path):
    try:
        with open(path, 'r') as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def boot_id():
    try:
        with open('/proc/sys/kernel/random/boot_id', 'r') as fh:
            return fh.read().strip()
    except OSError:
        return ''


def _pid_alive(pid):
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _unit_active():
    if not shutil.which('systemctl'):
        return False
    try:
        proc = subprocess.run(['systemctl', 'is-active', '--quiet', UNIT_NAME],
                              capture_output=True, timeout=5)
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def read_status(path=None):
    """The current or last run, with a crashed run reported as interrupted.

    A run killed mid-way (power cut, unit stopped) leaves state=running in the
    file forever. Left as-is that would pin the card on "Installing..." and
    refuse every later run as busy, so a running state whose process is gone
    is turned into an interrupted one.
    """
    status = _read_json(path or STATUS_PATH)
    if status.get('state') != 'running':
        return status
    pid = status.get('pid')
    if status.get('boot_id') and status.get('boot_id') != boot_id():
        alive = False           # the box rebooted mid-run; the PID is someone else's now
    elif pid:
        alive = _pid_alive(pid)
    else:
        started = float(status.get('started') or 0)
        alive = (time.time() - started) < LAUNCH_GRACE_SECONDS or _unit_active()
    if alive:
        return status
    status = dict(status)
    status.update({
        'state': 'finished',
        'outcome': 'interrupted',
        'error': 'The previous package run stopped before it finished.',
        'hint': ('If it was installing, run "sudo dpkg --configure -a" or start an '
                 'upgrade again - Ragnar runs that repair step first.'),
    })
    return status


def is_running():
    return read_status().get('state') == 'running'


def last_checked():
    """When the package lists were last refreshed, by Ragnar or anyone else."""
    status = _read_json(STATUS_PATH)
    stamps = [_mtime(APT_LISTS_DIR), _mtime(os.path.join(APT_LISTS_DIR, 'partial')),
              float(status.get('last_check') or 0)]
    best = max(stamps)
    return best or None


def read_log(max_chars=12000, previous=False):
    try:
        with open(PREV_LOG_PATH if previous else LOG_PATH, 'r', errors='replace') as fh:
            text = fh.read()
    except OSError:
        return ''
    return text[-max_chars:]


def overview():
    """Everything the Settings card and the Mesh tab need, in one cheap call."""
    ok, reason = supported()
    status = read_status()
    payload = {
        'supported': ok,
        'reason': reason,
        'running': status.get('state') == 'running',
        'status': status,
        'last_checked': last_checked() if ok else None,
    }
    if not ok:
        payload.update({'available': {'ok': False, 'packages': [], 'count': 0,
                                      'security_count': 0, 'held_count': 0,
                                      'upgradable_now': 0, 'security_now': 0},
                        'tailscale': None, 'reboot_required': False, 'reboot_reason': ''})
        return payload
    available = annotate_held(list_upgradable(), status.get('held_back'))
    payload['available'] = available
    ts = find_package(available.get('packages'), 'tailscale')
    payload['tailscale'] = ({'current': ts['current'], 'candidate': ts['candidate']}
                            if ts else None)
    required, why = reboot_required()
    payload['reboot_required'] = required
    payload['reboot_reason'] = why
    payload['has_previous_log'] = os.path.exists(PREV_LOG_PATH)
    return payload


# ---------------------------------------------------------------------------
# Launching a run
# ---------------------------------------------------------------------------

def validate_packages(packages, available_packages):
    """(clean_list, error). Only names that are currently upgradable pass.

    `apt-get install --only-upgrade` would not install a new package anyway,
    but the endpoint is not a generic package installer and should not look
    like one: anything not on the upgradable list is refused.
    """
    if packages is None:
        return [], ''
    if not isinstance(packages, (list, tuple)):
        return None, 'packages must be a list of package names.'
    if len(packages) > MAX_PACKAGES:
        return None, f'At most {MAX_PACKAGES} packages per run.'
    names = {p.get('name') for p in available_packages or []}
    clean = []
    for raw in packages:
        name = str(raw).strip().lower()
        if not _PKG_NAME.match(name):
            return None, f'"{raw}" is not a valid package name.'
        if name not in names:
            return None, f'{name} has no update available - run "Check for updates" first.'
        if name not in clean:
            clean.append(name)
    return clean, ''


def validate_removals(allow_remove, packages):
    """(clean_list, error) for the removals an operator approved.

    Approval is a ceiling, not a command: the runner never asks apt to remove
    anything, it only lets apt go ahead when every removal it plans is on this
    list. It only makes sense together with named packages.
    """
    if not allow_remove:
        return [], ''
    if not isinstance(allow_remove, (list, tuple)):
        return None, 'allow_remove must be a list of package names.'
    if not packages:
        return None, 'Approving removals needs the packages to upgrade named as well.'
    if len(allow_remove) > 32:
        return None, 'Too many removals in one run.'
    clean = []
    for raw in allow_remove:
        name = str(raw).strip().lower()
        if not _PKG_NAME.match(name):
            return None, f'"{raw}" is not a valid package name.'
        if name not in clean:
            clean.append(name)
    return clean, ''


def launch(action, packages=None, allow_remove=None):
    """Start a run. Returns (ok, code, message).

    code: '' on success, else unsupported / invalid / busy / launch_failed.
    """
    ok, reason = supported()
    if not ok:
        return False, 'unsupported', reason
    if action not in ('check', 'upgrade'):
        return False, 'invalid', 'Unknown action.'
    clean = []
    removals = []
    previous = _read_json(STATUS_PATH)
    if action == 'upgrade':
        available = annotate_held(list_upgradable(), previous.get('held_back'))
        clean, error = validate_packages(packages, available.get('packages'))
        if clean is None:
            return False, 'invalid', error
        removals, error = validate_removals(allow_remove, clean)
        if removals is None:
            return False, 'invalid', error
        if not clean and not available.get('count'):
            return False, 'invalid', 'Nothing to upgrade - the system is up to date.'
        if not clean and not available.get('upgradable_now'):
            return False, 'invalid', ('Nothing to upgrade automatically: the remaining '
                                      'packages are held back. Each one says why on the card.')
    if is_running() or _unit_active():
        return False, 'busy', 'A package run is already in progress.'

    _write_json_atomic(STATUS_PATH, {
        'state': 'running', 'action': action, 'packages': clean, 'allow_remove': removals,
        'step': 'Starting', 'started': time.time(), 'pid': None, 'boot_id': boot_id(),
        'last_check': float(previous.get('last_check') or 0),
        'held_back': previous.get('held_back'),
    })
    # Keep the previous run's output: a quick follow-up run (a check right after
    # a big upgrade) used to overwrite the only record of how the upgrade went.
    try:
        if os.path.getsize(LOG_PATH) > 0:
            os.replace(LOG_PATH, PREV_LOG_PATH)
    except OSError:
        pass
    try:
        open(LOG_PATH, 'w').close()
    except OSError:
        pass

    args = [sys.executable or '/usr/bin/python3', os.path.abspath(__file__), 'run', action]
    if removals:
        args.append('--allow-remove=' + ','.join(removals))
    args += clean

    systemd_run = shutil.which('systemd-run')
    if systemd_run:
        base = [systemd_run, f'--unit={UNIT_NAME}', '--collect', '--no-block',
                '--description=Ragnar OS package update',
                '-p', 'Nice=10', '-p', 'IOSchedulingClass=best-effort',
                '-p', 'IOSchedulingPriority=7']
        launchers = [base + args]
        if os.geteuid() != 0:
            launchers.insert(0, ['sudo', '-n'] + base + args)
        last_error = ''
        for launcher in launchers:
            try:
                proc = subprocess.run(launcher, capture_output=True, text=True, timeout=30)
            except (subprocess.TimeoutExpired, OSError) as exc:
                last_error = str(exc)
                continue
            if proc.returncode == 0:
                return True, '', ('Checking for updates.' if action == 'check'
                                  else 'Upgrade started.')
            last_error = proc.stderr.strip() or proc.stdout.strip()
            if 'already exists' in last_error or 'already loaded' in last_error:
                return False, 'busy', 'A package run is already in progress.'
        _write_finished({'outcome': 'failed', 'action': action, 'packages': clean,
                         'error': f'Could not start the package run: {last_error}'})
        return False, 'launch_failed', f'Could not start the package run: {last_error}'

    # No systemd: detach from the web app's process group so a service restart
    # does not take the run down with it.
    try:
        command = args if os.geteuid() == 0 else ['sudo', '-n'] + args
        subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
        return True, '', 'Started.'
    except OSError as exc:
        _write_finished({'outcome': 'failed', 'action': action, 'packages': clean,
                         'error': f'Could not start the package run: {exc}'})
        return False, 'launch_failed', f'Could not start the package run: {exc}'


def _write_finished(fields):
    status = _read_json(STATUS_PATH)
    status.update({'state': 'finished', 'finished': time.time(), 'pid': None})
    status.update(fields)
    _write_json_atomic(STATUS_PATH, status)


# ---------------------------------------------------------------------------
# Runner (executes inside the transient unit)
# ---------------------------------------------------------------------------

_OFFLINE = re.compile(r'Temporary failure resolving|Could not resolve|Network is unreachable|'
                      r'Connection timed out|Failed to fetch|No route to host|'
                      r'Could not connect', re.I)
_KEY_ERROR = re.compile(r'NO_PUBKEY|EXPKEYSIG|KEYEXPIRED|is not signed|'
                        r'invalid signature|The following signatures', re.I)
_SPACE = re.compile(r'After this operation, ([\d.,]+)\s*([kMG]?B) of additional disk space', re.I)
_DOWNLOAD = re.compile(r'Need to get ([\d.,]+)\s*([kMG]?B)', re.I)
_SUMMARY = re.compile(r'(\d+) upgraded, (\d+) newly installed, (\d+) to remove and '
                      r'(\d+) not upgraded')
_NO_REMOVE = re.compile(r'Packages need to be removed but remove is disabled', re.I)
_REMOVING = re.compile(r'^Removing ([a-z0-9][a-z0-9+.\-]*)(?::\S+)? \(')
_SETTING_UP = re.compile(r'^Setting up ([a-z0-9][a-z0-9+.\-]*)(?::\S+)? \(')
_UNPACKING = re.compile(r'^Unpacking ([a-z0-9][a-z0-9+.\-]*)(?::\S+)? ')


def _to_mb(value, unit):
    number = float(value.replace(',', ''))
    unit = unit.upper()
    if unit == 'KB':
        return number / 1024.0
    if unit == 'GB':
        return number * 1024.0
    if unit == 'B':
        return number / (1024.0 * 1024.0)
    return number


class Runner:
    """One check or upgrade, logging everything and keeping the status file current."""

    def __init__(self, action, packages, status_path=STATUS_PATH, log_path=LOG_PATH,
                 disk_path='/', allow_remove=None):
        self.action = action
        self.packages = list(packages or [])
        self.allow_remove = list(allow_remove or [])
        # Removals are refused unless the operator approved them; flipped off only
        # once the plan has been checked against the approved list.
        self.no_remove = True
        self.status_path = status_path
        self.log_path = log_path
        self.disk_path = disk_path
        previous = _read_json(status_path)
        self.status = {
            'state': 'running', 'action': action, 'packages': self.packages,
            'step': 'Starting', 'started': time.time(), 'pid': os.getpid(),
            'boot_id': boot_id(),
            'last_check': float(previous.get('last_check') or 0),
            'progress': None, 'warnings': [],
            'allow_remove': self.allow_remove,
            # What the last successful analysis found; replaced at the end of
            # this run, kept if this run fails before getting there.
            'held_back': previous.get('held_back'),
        }
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self._log = open(log_path, 'a', buffering=1)
        self._last_write = 0.0
        self._save(force=True)

    # -- bookkeeping -------------------------------------------------------
    def _save(self, force=False):
        now = time.time()
        if not force and now - self._last_write < 1.0:
            return
        self._last_write = now
        _write_json_atomic(self.status_path, self.status)

    def log(self, line):
        self._log.write(line.rstrip('\n') + '\n')

    def step(self, text):
        self.status['step'] = text
        self.log(f'==> {text}')
        self._save(force=True)

    def finish(self, outcome, error='', hint='', **extra):
        self.status.update({'state': 'finished', 'outcome': outcome, 'error': error,
                            'hint': hint, 'finished': time.time(), 'pid': None})
        self.status.update(extra)
        if error:
            self.log(f'!! {error}')
        self.log(f'==> Finished: {outcome}')
        self._save(force=True)
        try:
            self._log.close()
        except OSError:
            pass
        return 0 if outcome == 'ok' else 1

    def run_cmd(self, cmd, timeout=None, on_line=None):
        """Run a command, streaming its output to the log. Returns (rc, lines)."""
        self.log('$ ' + ' '.join(cmd))
        lines = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL, text=True, env=_env(),
                                    errors='replace')
        except OSError as exc:
            self.log(f'could not run {cmd[0]}: {exc}')
            return 127, [str(exc)]
        deadline = time.time() + timeout if timeout else None
        timer = None
        if deadline:
            timer = threading.Timer(timeout, proc.kill)
            timer.daemon = True
            timer.start()
        try:
            for line in proc.stdout:
                line = line.rstrip('\n')
                lines.append(line)
                self.log(line)
                if on_line:
                    on_line(line)
            proc.wait()
        finally:
            if timer:
                timer.cancel()
        rc = proc.returncode
        if deadline and time.time() >= deadline and rc != 0:
            self.log(f'timed out after {timeout}s')
            return 124, lines
        return rc, lines

    # -- failure classification -------------------------------------------
    @staticmethod
    def _classify_update_failure(lines):
        text = '\n'.join(lines)
        if _KEY_ERROR.search(text):
            repo = ''
            for line in lines:
                if _KEY_ERROR.search(line):
                    m = re.search(r'https?://\S+', line)
                    if m:
                        repo = m.group(0).rstrip(':')
                        break
            where = f' ({repo})' if repo else ''
            return ('repo_key',
                    f'A repository signing key is missing or expired{where}.',
                    "Re-add that repository's signing key (for Tailscale, re-running "
                    'scripts/setup_mesh.sh install does it), then check again.')
        if _OFFLINE.search(text):
            return ('offline', 'Could not reach the package mirrors.',
                    "Check the box's internet connection and try again.")
        if re.search(r'Could not get lock|Unable to acquire|is held by process', text):
            return ('locked', 'Another package manager is holding the apt lock.',
                    'Wait for it to finish (an apt run over SSH, or apt-daily) and try again.')
        return ('apt_error', 'apt-get update failed.', 'See the log for the exact error.')

    # -- steps -------------------------------------------------------------
    def refresh_lists(self):
        self.step('Refreshing package lists')
        rc, lines = self.run_cmd(['apt-get'] + _APT_OPTS + ['update'], timeout=UPDATE_TIMEOUT)
        warnings = [l.strip() for l in lines if l.startswith(('W:', 'E:', 'Err:'))]
        self.status['warnings'] = warnings[-20:]
        if rc != 0:
            code, error, hint = self._classify_update_failure(lines)
            return code, error, hint
        self.status['last_check'] = time.time()
        self._save(force=True)
        return None

    def upgrade_command(self, download_only=False):
        cmd = ['apt-get', '-y'] + _APT_OPTS
        if download_only:
            cmd.append('-d')
        if self.no_remove:
            cmd.append('--no-remove')
        if self.packages:
            cmd += ['install', '--only-upgrade'] + self.packages
        else:
            cmd += ['upgrade', '--with-new-pkgs']
        return cmd

    def analyze_held(self):
        """Refresh status['held_back']; on a failed analysis keep the last one."""
        self.step('Checking for held-back packages')
        held = analyze_held_back()
        if held is None:
            self.log('held-back analysis failed; keeping the previous result')
            return self.status.get('held_back')
        for entry in held:
            extra = ''
            if entry.get('removes'):
                extra = f" (would remove: {', '.join(entry['removes'])})"
            self.log(f"held back: {entry['name']} - {entry['reason']}{extra}")
        self.status['held_back'] = held
        self._save(force=True)
        return held

    def check_removals(self):
        """For an approved targeted upgrade: (ok, error). Only planned removals that
        are all on the approved list let the run proceed with removals allowed."""
        rc, removes, _new, _versions, errors = simulate_install(self.packages)
        if rc != 0:
            return False, ' '.join(errors) or 'apt could not plan the upgrade.'
        extra = sorted(set(removes) - set(self.allow_remove))
        if extra:
            return False, ('apt now also wants to remove ' + ', '.join(extra) +
                           ', which was not approved.')
        self.no_remove = not removes
        self.status['planned_removals'] = removes
        self.log('planned removals: ' + (', '.join(removes) if removes else 'none'))
        return True, ''

    def execute(self):
        try:
            return self._execute()
        except Exception as exc:  # the status file must never be left at "running"
            return self.finish('failed', f'Unexpected error: {type(exc).__name__}: {exc}',
                               'See the log for details.')

    def _execute(self):
        failure = self.refresh_lists()
        if failure:
            code, error, hint = failure
            # A failed refresh still leaves usable lists from last time; an
            # upgrade on top of them would be installing yesterday's versions,
            # so stop here either way.
            return self.finish('failed', error, hint, code=code)

        if self.action == 'check':
            self.analyze_held()
            return self.finish('ok')

        self.step('Finishing any interrupted install')
        rc, lines = self.run_cmd(['dpkg', '--configure', '-a',
                                  '--force-confdef', '--force-confold'], timeout=30 * 60)
        if rc != 0:
            return self.finish('failed', 'dpkg could not finish a previous install.',
                               'Run "sudo dpkg --configure -a" over SSH to see why.',
                               code='dpkg_broken')

        if self.packages and self.allow_remove:
            self.step('Checking what the upgrade removes')
            ok, error = self.check_removals()
            if not ok:
                return self.finish('failed', error,
                                   'Nothing was changed. Check for updates again and review '
                                   'what the upgrade removes before approving it.',
                                   code='removal_changed')

        self.step('Downloading packages')
        rc, lines = self.run_cmd(self.upgrade_command(download_only=True),
                                 timeout=2 * 60 * 60)
        text = '\n'.join(lines)
        if rc != 0:
            if _NO_REMOVE.search(text):
                names = ', '.join(self.packages) or 'these packages'
                return self.finish('failed', f'Upgrading {names} would remove other packages.',
                                   'Nothing was changed. The card lists it as held back, with '
                                   'what it removes, and an Upgrade anyway button.',
                                   code='needs_removal')
            if re.search(r"You don't have enough free space", text):
                return self.finish('failed', 'Not enough free space to download the updates.',
                                   'Free some space (sudo apt-get clean removes old '
                                   'downloads) and try again.', code='disk_full')
            if _OFFLINE.search(text):
                return self.finish('failed', 'The download was interrupted.',
                                   'Nothing was installed. Check the connection and retry.',
                                   code='offline')
            return self.finish('failed', 'Downloading the updates failed.',
                               'Nothing was installed. See the log for the exact error.',
                               code='apt_error')

        summary = _SUMMARY.search(text)
        total = 0
        if summary:
            total = int(summary.group(1)) + int(summary.group(2))
            self.status['kept_back'] = int(summary.group(4))
        need_mb = 0.0
        space = _SPACE.search(text)
        if space:
            need_mb = _to_mb(space.group(1), space.group(2))
        download = _DOWNLOAD.search(text)
        if download:
            self.status['download_mb'] = round(_to_mb(download.group(1), download.group(2)), 1)

        if summary and total == 0:
            self.step('Nothing to install')
            held = self.analyze_held()
            return self.finish('ok', upgraded=[], upgraded_count=0,
                               held_count=len(held or []))

        free_mb = shutil.disk_usage(self.disk_path).free / (1024.0 * 1024.0)
        if free_mb < need_mb + FREE_SPACE_MARGIN_MB:
            return self.finish(
                'failed',
                f'Not enough free space: the install needs about {need_mb:.0f} MB plus '
                f'{FREE_SPACE_MARGIN_MB} MB headroom, and {free_mb:.0f} MB is free.',
                'Free some space and try again. Nothing was installed.', code='disk_full')

        self.step('Installing updates')
        configured = []
        unpacked = []
        removed = []

        def on_line(line):
            m = _REMOVING.match(line)
            if m:
                removed.append(m.group(1))
                return
            m = _SETTING_UP.match(line)
            if m:
                configured.append(m.group(1))
                if total:
                    self.status['progress'] = {'done': len(configured), 'total': total,
                                               'current': m.group(1)}
                self._save()
                return
            m = _UNPACKING.match(line)
            if m:
                unpacked.append(m.group(1))
                if total:
                    self.status['progress'] = {'done': len(configured), 'total': total,
                                               'current': m.group(1)}
                self._save()

        rc, lines = self.run_cmd(self.upgrade_command(), on_line=on_line)
        upgraded = sorted(set(unpacked) | set(configured))
        self.status['removed'] = sorted(set(removed))
        if rc != 0:
            return self.finish('failed', 'The install stopped with an error.',
                               'Start the upgrade again: Ragnar first runs '
                               '"dpkg --configure -a", which finishes what was left.',
                               code='dpkg_error', upgraded=upgraded,
                               upgraded_count=len(upgraded))

        self.step('Cleaning up downloaded packages')
        self.run_cmd(['apt-get', '-q', 'clean'], timeout=10 * 60)

        reboot = needs_reboot_for(upgraded) or reboot_required()[0]
        held = self.analyze_held()
        return self.finish('ok', upgraded=upgraded, upgraded_count=len(upgraded),
                           reboot_recommended=reboot, held_count=len(held or []),
                           tailscale_upgraded='tailscale' in upgraded)


def _install_signal_handlers(runner):
    def _stop(signum, _frame):
        runner.finish('failed', 'The package run was stopped before it finished.',
                      'Start it again: Ragnar first finishes any half-done install.',
                      code='interrupted')
        sys.exit(1)
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGHUP, _stop)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) >= 2 and argv[0] == 'run':
        action = argv[1]
        if action not in ('check', 'upgrade'):
            print(f'unknown action {action}', file=sys.stderr)
            return 2
        allow_remove = []
        packages = []
        for arg in argv[2:]:
            if arg.startswith('--allow-remove='):
                allow_remove = [p for p in arg.split('=', 1)[1].split(',') if _PKG_NAME.match(p)]
            elif _PKG_NAME.match(arg):
                packages.append(arg)
        runner = Runner(action, packages, allow_remove=allow_remove)
        _install_signal_handlers(runner)
        return runner.execute()
    if argv and argv[0] == 'status':
        print(json.dumps(overview(), indent=2, default=str))
        return 0
    print('usage: os_updates.py run check|upgrade [--allow-remove=a,b] [package ...] | status',
          file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
