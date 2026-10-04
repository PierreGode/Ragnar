#!/usr/bin/env python3
"""ragnar_scripts.py — discovery + auto-sync for the external RagnarScripts library.

RagnarScripts (github.com/PierreGode/RagnarScripts) is a separate, user-cloned
repo holding shareable scripts that install into Ragnar from the dashboard:

  * rubber-ducky/    .ducky / .txt  -> files/rubber-ducky/   (Rubber Ducky card)
  * console-scripts/ .json          -> data/console_scripts/ (Device Console card)

This module owns the canonical repo-discovery heuristic and a best-effort
``sync()`` that clones the repo when it is missing and ``git pull``s it when it
is present, so new shared scripts appear without a manual git pull. It is called
on web-server start and when the Dashboard / Pentest tabs are opened (throttled).

``serial_console._ragnar_scripts_repo`` and
``python/rubber_ducky._ragnar_scripts_repo`` delegate here (with an inline
fallback), so the discovery order lives in one place.
"""
import os
import time
import logging
import threading
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

CLONE_URL = 'https://github.com/PierreGode/RagnarScripts.git'

# This file sits at the Ragnar repo root.
_RAGNAR_ROOT = Path(__file__).resolve().parent


def _candidates():
    """Ordered discovery locations for an existing RagnarScripts checkout."""
    out = []
    env = os.environ.get('RAGNAR_SCRIPTS_DIR')
    if env:
        out.append(Path(env).expanduser())
    out += [
        _RAGNAR_ROOT.parent / 'RagnarScripts',   # sibling of the Ragnar repo
        Path.home() / 'RagnarScripts',
        Path('/home/pi/RagnarScripts'),
        Path('/home/ragnar/RagnarScripts'),
    ]
    return out


def repo_dir():
    """Return the first existing RagnarScripts checkout as a ``Path``, or None."""
    seen = set()
    for c in _candidates():
        try:
            rc = c.resolve()
        except Exception:
            continue
        if rc in seen:
            continue
        seen.add(rc)
        if c.is_dir():
            return c
    return None


def clone_target():
    """Where to clone when none is found. Always a path ``repo_dir()`` will then
    discover: ``$RAGNAR_SCRIPTS_DIR`` if set, else a sibling of the Ragnar repo
    (which is independent of which user runs the web server)."""
    env = os.environ.get('RAGNAR_SCRIPTS_DIR')
    if env:
        return Path(env).expanduser()
    return _RAGNAR_ROOT.parent / 'RagnarScripts'


_last = {'at': 0.0, 'status': None}
_lock = threading.Lock()
_MIN_INTERVAL = 30  # seconds — collapse rapid dashboard/pentest opens into one pull


def _git(args, cwd, timeout):
    # safe.directory=* so a pull still works when the web server runs as a
    # different user than the one that owns the checkout (root vs pi/ragnar) —
    # otherwise git aborts with "detected dubious ownership in repository".
    return subprocess.run(['git', '-c', 'safe.directory=*'] + args,
                          cwd=cwd, timeout=timeout,
                          capture_output=True, text=True)


def _do_sync(timeout):
    existing = repo_dir()
    if existing:
        if not (existing / '.git').exists():
            return {'ok': False, 'dir': str(existing), 'action': 'skip',
                    'error': 'folder exists but is not a git checkout'}
        r = _git(['pull', '--ff-only'], str(existing), timeout)
        if r.returncode != 0:
            return {'ok': False, 'dir': str(existing), 'action': 'pull',
                    'error': (r.stderr or r.stdout).strip()[:300]}
        out = r.stdout or ''
        return {'ok': True, 'dir': str(existing), 'action': 'pull',
                'changed': 'up to date' not in out.lower()}
    target = clone_target()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return {'ok': False, 'dir': str(target), 'action': 'clone', 'error': str(e)}
    r = _git(['clone', CLONE_URL, str(target)], str(target.parent), timeout)
    if r.returncode != 0:
        return {'ok': False, 'dir': str(target), 'action': 'clone',
                'error': (r.stderr or r.stdout).strip()[:300]}
    return {'ok': True, 'dir': str(target), 'action': 'clone', 'changed': True}


def sync(timeout=25, min_interval=_MIN_INTERVAL, force=False):
    """Clone the repo if missing, else ``git pull``. Best-effort: never raises;
    returns a status dict. Throttled so repeated tab opens don't spawn a git
    process each time (pass ``force=True`` to bypass the throttle)."""
    with _lock:
        now = time.time()
        if not force and _last['status'] and (now - _last['at']) < min_interval:
            return dict(_last['status'], throttled=True)
        try:
            status = _do_sync(timeout)
        except subprocess.TimeoutExpired:
            status = {'ok': False, 'action': 'timeout',
                      'error': f'git timed out after {timeout}s'}
        except FileNotFoundError:
            status = {'ok': False, 'action': 'skip', 'error': 'git not installed'}
        except Exception as e:  # pragma: no cover - defensive
            status = {'ok': False, 'action': 'error', 'error': str(e)}
        _last['at'] = now
        _last['status'] = status
        return status


def sync_async(**kwargs):
    """Run :func:`sync` on a daemon thread (so an HTTP handler or boot path never
    blocks on the network). Returns the thread."""
    t = threading.Thread(target=lambda: sync(**kwargs),
                         name='ragnar-scripts-sync', daemon=True)
    t.start()
    return t
