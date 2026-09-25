#!/usr/bin/env python3
"""Deterministic self-update engine for Ragnar.

Every box updates itself by pulling this repository from the Settings tab, and
for a long tail of users that click ended in a bare "Update failed. Fix issues
and retry." with nothing to act on. The cause was almost never the merge:

  * git commands ran with no timeout, so a fetch against an unreachable origin
    - or one that stopped to ask for credentials - blocked the request thread
    and the update mutex forever. The browser eventually gave up and reported
    "error" while the box sat there holding the lock for good.
  * the repository path came from ``os.getcwd()``, which is only correct for as
    long as nothing in a 20k-line web app ever changes the working directory.
  * installs with no ``.git`` at all (the installer unpacks a release tarball
    when git is unusable on the board) had every future update dead on arrival.
  * checkouts whose branch no longer exists upstream, detached HEADs, histories
    that diverged, untracked files standing exactly where a new tracked file
    wanted to land - each one failed the pull with a different message and no
    recovery.
  * a failed ``git stash pop`` left conflict markers in the working tree: an
    update that ends with a box that will not boot.

This module answers all of them the same way. Every git call is
non-interactive and time-bounded, every failure carries a machine-readable
code plus one sentence the user can act on, and an update either lands the
working tree exactly on ``origin/<branch>`` or leaves it exactly as it was.
Local edits are never dropped silently: they go to a stash which is only
deleted once it has been re-applied cleanly.

Private data is untouched throughout. Everything a box generates is gitignored,
and the forced paths use ``git clean -fd`` - never ``-x`` - which by definition
cannot remove an ignored file.
"""

import logging
import os
import pwd
import shutil
import subprocess
import threading
import time
from datetime import datetime

logger = logging.getLogger(__name__)

# --- tunables ---------------------------------------------------------------

# Network operations get a generous budget: a Pi Zero on a tethered phone can
# genuinely take minutes to fetch. Local operations that hang are always a bug
# or a stuck lock, so they are cut off much sooner.
GIT_NETWORK_TIMEOUT = 300
GIT_LOCAL_TIMEOUT = 120
GIT_QUICK_TIMEOUT = 30
# The background update check runs on a timer in every open dashboard tab and a
# user is waiting on its answer, so it gives up on a stalled network sooner than
# a user-initiated update does.
GIT_CHECK_TIMEOUT = 90

# Locks younger than this belong to a git process that is probably still
# running; older ones are debris from an interrupted run and safe to sweep.
LOCK_STALE_SECONDS = 120

# A pull needs room for the new objects plus the checkout. Below the hard floor
# git will corrupt its own object store, so refuse rather than try.
DISK_HARD_FLOOR = 60 * 1024 * 1024
DISK_WARN_FLOOR = 250 * 1024 * 1024

DEFAULT_REMOTE_URL = 'https://github.com/PierreGode/Ragnar.git'
FALLBACK_BRANCHES = ('main', 'master')

# Stash and merge commits need an author; the service runs as root, which
# usually has no git identity. pull.rebase settles git's "divergent branches"
# refusal, which otherwise aborts the pull outright on newer git.
GIT_IDENTITY = [
    '-c', 'user.name=Ragnar Updater',
    '-c', 'user.email=ragnar-updater@localhost',
    '-c', 'pull.rebase=false',
]

# Abort a transfer that has stalled below 1 kB/s for 30s instead of sitting
# there until the outer timeout fires - it turns a 5 minute hang into a fast,
# clearly-labelled network failure.
GIT_TRANSFER_GUARDS = [
    '-c', 'http.lowSpeedLimit=1000',
    '-c', 'http.lowSpeedTime=30',
]

# One update at a time per process. Held non-blocking: a second click gets an
# immediate "already running" instead of a request that hangs behind the first.
_UPDATE_LOCK = threading.Lock()
_UPDATE_STATE = {'running': False, 'started': None, 'step': ''}

# A missing .git is repaired by the update check itself rather than reported as
# a problem, but the repair needs the network. When it fails (box still
# offline), back off instead of retrying on every dashboard poll.
REATTACH_RETRY_SECONDS = 600
_LAST_REATTACH_ATTEMPT = [0.0]


class GitResult:
    """Outcome of one git invocation. Never raises - callers branch on .ok."""

    __slots__ = ('args', 'rc', 'out', 'err', 'timed_out')

    def __init__(self, args, rc, out='', err='', timed_out=False):
        self.args = args
        self.rc = rc
        self.out = (out or '').strip()
        self.err = (err or '').strip()
        self.timed_out = timed_out

    @property
    def ok(self):
        return self.rc == 0 and not self.timed_out

    @property
    def message(self):
        if self.timed_out:
            return f"git {' '.join(self.args[:2])} timed out"
        return self.err or self.out or f"git exited {self.rc}"

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"<GitResult rc={self.rc} timed_out={self.timed_out} {' '.join(self.args[:3])}>"


# --- environment ------------------------------------------------------------

def repo_root():
    """The checkout this module lives in.

    Deliberately derived from __file__ rather than os.getcwd(): the web app is
    long-lived and anything that chdir()s once would otherwise point every
    future update at the wrong directory (or at '/', where git's errors are
    bewildering).
    """
    return os.path.dirname(os.path.abspath(__file__))


def git_env():
    """Environment that makes git incapable of waiting for a human.

    Without this a checkout whose origin needs credentials, or an ssh remote
    whose host key is unknown, parks on a prompt that nobody will ever answer -
    the single worst failure mode, because it hangs instead of failing.
    """
    env = os.environ.copy()
    env.update({
        'GIT_TERMINAL_PROMPT': '0',
        'GIT_ASKPASS': 'echo',
        'SSH_ASKPASS': 'echo',
        'SSH_ASKPASS_REQUIRE': 'never',
        'GIT_SSH_COMMAND': ('ssh -oBatchMode=yes -oStrictHostKeyChecking=accept-new '
                            '-oConnectTimeout=15'),
        'GCM_INTERACTIVE': 'never',
        'GIT_PAGER': 'cat',
        'GIT_OPTIONAL_LOCKS': '0',
        # Error strings are matched below, so pin the language.
        'LC_ALL': 'C',
        'LANG': 'C',
    })
    # A stray GIT_DIR/GIT_WORK_TREE inherited from a parent process would send
    # every command at the wrong repository.
    env.pop('GIT_DIR', None)
    env.pop('GIT_WORK_TREE', None)
    return env


def run_git(args, cwd, timeout=GIT_LOCAL_TIMEOUT, identity=False, network=False):
    """Run one git command. Returns a GitResult; never raises."""
    cmd = ['git']
    if identity:
        cmd.extend(GIT_IDENTITY)
    if network:
        cmd.extend(GIT_TRANSFER_GUARDS)
    cmd.extend(args)
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True,
            env=git_env(), stdin=subprocess.DEVNULL, timeout=timeout,
        )
        result = GitResult(args, proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired:
        logger.error(f"git {' '.join(args)} timed out after {timeout}s")
        return GitResult(args, 124, '', f'timed out after {timeout}s', timed_out=True)
    except FileNotFoundError:
        return GitResult(args, 127, '', 'git executable not found')
    except Exception as exc:  # pragma: no cover - defensive
        return GitResult(args, 1, '', str(exc))
    if not result.ok:
        logger.debug(f"git {' '.join(args)} -> rc={result.rc}: {result.message}")
    return result


# --- failure taxonomy -------------------------------------------------------

# Ordered: the first pattern that matches wins, so the specific ones lead.
_ERROR_SIGNATURES = (
    ('disk_full', ('no space left on device', 'file write error', 'write error: no space'),
     'The disk is full. Free some space (data/logs and old captures are the usual culprits) and try again.'),
    ('auth', ('authentication failed', 'could not read username', 'could not read password',
              'terminal prompts disabled', 'permission denied (publickey)', 'invalid username or password',
              'support for password authentication was removed'),
     'The origin repository asked for credentials. Point it at the public URL: '
     f'git remote set-url origin {DEFAULT_REMOTE_URL}'),
    ('offline', ('could not resolve host', 'unable to access', 'connection timed out',
                 'could not read from remote repository', 'connection reset', 'early eof',
                 'network is unreachable', 'operation timed out', 'ssl connect error',
                 'failed to connect', 'temporary failure in name resolution', 'rpc failed'),
     'The box could not reach github.com. Check its internet connection and try again.'),
    ('branch_missing', ("couldn't find remote ref", 'unknown revision', 'not a valid object name',
                        'does not appear to be a git repository'),
     'This checkout tracks a branch that no longer exists upstream. Ragnar will fall back to the '
     'default branch on the next attempt.'),
    ('ownership', ('dubious ownership',),
     'Git refused the checkout because of file ownership. Ragnar tries to fix this automatically; '
     'if it persists run: sudo chown -R ragnar:ragnar ' + repo_root()),
    ('locked', ('index.lock', 'another git process', 'unable to create', '.lock'),
     'Another git process is using the repository. Wait a moment and try again.'),
    ('not_a_repo', ('not a git repository',),
     'This install has no git metadata. Run sudo bash update_ragnar.sh once to reattach it upstream.'),
    ('permission', ('permission denied', 'read-only file system', 'operation not permitted'),
     'Ragnar could not write to its own directory. Run: sudo chown -R ragnar:ragnar ' + repo_root()),
)

_HINTS = {
    'timeout': 'The git command stopped responding and was cancelled. This is almost always a slow '
               'or dropped internet connection - try again once the box is back online.',
    'busy': 'An update is already running. Give it a minute to finish.',
    'git_missing': 'git is not installed or does not run on this board. Install it with: '
                   'sudo apt update && sudo apt install --reinstall git',
    'no_remote': 'The checkout has no "origin" remote. Ragnar adds one automatically; if this keeps '
                 f'happening run: git remote add origin {DEFAULT_REMOTE_URL}',
    'dirty_after_update': 'The update landed but local edits could not be replayed on top of it. '
                          'They are safe in a git stash - recover them with: git stash list',
    'git_error': 'Git reported an error. The full message is above; running '
                 'sudo bash update_ragnar.sh from a terminal shows the same step with more detail.',
}


def classify(text, timed_out=False):
    """Map raw git output to (code, hint) so the UI can say something useful."""
    if timed_out:
        return 'timeout', _HINTS['timeout']
    low = (text or '').lower()
    for code, needles, hint in _ERROR_SIGNATURES:
        if any(needle in low for needle in needles):
            return code, hint
    return 'git_error', _HINTS['git_error']


def _fail(result, code, error, hint=None):
    result['ok'] = False
    result['success'] = False
    result['code'] = code
    result['error'] = error
    result['hint'] = hint or _HINTS.get(code) or ''
    logger.error(f"Update failed [{code}]: {error}")
    return result


# --- repository hygiene -----------------------------------------------------

def git_usable():
    """True when a git binary exists and actually runs on this board.

    Debian Trixie arm64 has shipped a git built with ARMv8.1 atomics that dies
    with SIGILL on a Cortex-A53 (Pi Zero 2 W). Such a box runs Ragnar perfectly
    but can never update, and every git command returns a signal instead of a
    message - worth naming explicitly rather than reporting "error".
    """
    try:
        proc = subprocess.run(['git', '--version'], capture_output=True, text=True,
                              timeout=GIT_QUICK_TIMEOUT, stdin=subprocess.DEVNULL)
        return proc.returncode == 0, (proc.stdout or proc.stderr).strip()
    except FileNotFoundError:
        return False, 'git executable not found'
    except subprocess.TimeoutExpired:
        return False, 'git --version timed out'
    except Exception as exc:
        return False, str(exc)


def ensure_safe_directory(repo_path):
    """Whitelist the checkout so root operating on a ragnar-owned tree is allowed.

    safe.directory is only honoured from the global config, so ``-c`` on the
    command line cannot substitute for writing it once.
    """
    try:
        existing = subprocess.run(
            ['git', 'config', '--global', '--get-all', 'safe.directory'],
            capture_output=True, text=True, timeout=GIT_QUICK_TIMEOUT,
            stdin=subprocess.DEVNULL, env=git_env(),
        ).stdout.splitlines()
        if repo_path not in existing and '*' not in existing:
            subprocess.run(
                ['git', 'config', '--global', '--add', 'safe.directory', repo_path],
                capture_output=True, text=True, timeout=GIT_QUICK_TIMEOUT,
                stdin=subprocess.DEVNULL, env=git_env(),
            )
    except Exception as exc:
        logger.debug(f"safe.directory setup skipped: {exc}")


def clear_stale_locks(repo_path, warnings=None, min_age_seconds=LOCK_STALE_SECONDS):
    """Delete every ``*.lock`` under .git older than min_age_seconds.

    The locks that actually stranded users were the ones no hardcoded list
    covered: refs/remotes/origin/<branch>.lock, packed-refs.lock, config.lock,
    ref locks for branches other than main. Sweeping the whole tree by age
    means an interrupted run self-heals on the next attempt, while a lock held
    by a git process that is still running is left alone.

    Implemented in pure Python on purpose - the old shell-out to ``sudo find``
    could itself block waiting for a sudo password.
    """
    git_dir = os.path.join(repo_path, '.git')
    if not os.path.isdir(git_dir):
        return []
    now = time.time()
    removed = []
    skip_dirs = {'objects', 'modules', 'lfs'}
    for root, dirs, files in os.walk(git_dir):
        # objects/ holds thousands of files and never a lock we care about.
        if root == git_dir:
            dirs[:] = [d for d in dirs if d not in skip_dirs]
        for name in files:
            if not name.endswith('.lock'):
                continue
            path = os.path.join(root, name)
            try:
                if min_age_seconds > 0 and (now - os.path.getmtime(path)) < min_age_seconds:
                    continue
                os.remove(path)
                removed.append(os.path.relpath(path, git_dir))
            except OSError as exc:
                logger.debug(f"could not remove {path}: {exc}")
    if removed:
        msg = f"Cleared {len(removed)} stale git lock(s): {', '.join(removed[:6])}"
        logger.warning(msg)
        if warnings is not None:
            warnings.append(msg)
    return removed


def abort_in_progress_operation(repo_path, warnings=None):
    """Undo a merge/rebase/cherry-pick a previous crashed run left half-done.

    A box stuck in this state fails every subsequent update with "you have not
    concluded your merge" and has no way out through the web UI.
    """
    git_dir = os.path.join(repo_path, '.git')
    states = (
        ('MERGE_HEAD', ['merge', '--abort'], 'merge'),
        ('rebase-merge', ['rebase', '--abort'], 'rebase'),
        ('rebase-apply', ['rebase', '--abort'], 'rebase'),
        ('CHERRY_PICK_HEAD', ['cherry-pick', '--abort'], 'cherry-pick'),
        ('REVERT_HEAD', ['revert', '--abort'], 'revert'),
    )
    for marker, args, label in states:
        if not os.path.exists(os.path.join(git_dir, marker)):
            continue
        run_git(args, repo_path, timeout=GIT_LOCAL_TIMEOUT, identity=True)
        msg = f"Aborted an unfinished {label} left by an earlier run"
        logger.warning(msg)
        if warnings is not None:
            warnings.append(msg)


def repo_owner(repo_path):
    """(uid, gid, name) the checkout should belong to.

    Derived from the directory itself rather than hardcoded to 'ragnar', so an
    install under a different account is not chowned out from under its own
    service. Only when the directory is root-owned do we look for 'ragnar'.
    """
    try:
        st = os.stat(repo_path)
    except OSError:
        return None
    uid, gid = st.st_uid, st.st_gid
    if uid == 0:
        try:
            entry = pwd.getpwnam('ragnar')
            uid, gid = entry.pw_uid, entry.pw_gid
        except KeyError:
            return None
    try:
        name = pwd.getpwuid(uid).pw_name
    except KeyError:
        name = str(uid)
    return uid, gid, name


def restore_ownership(repo_path, warnings=None):
    """Give the checkout back to the service account after root touched it.

    git run as root creates root-owned files; the app runs as 'ragnar' and then
    cannot write them. os.chown is used rather than ``sudo chown -R`` because
    sudo can prompt (and therefore hang), and because we can skip files that
    are already correct - on a Pi with a large data/ directory that is the
    difference between instant and tens of seconds.
    """
    owner = repo_owner(repo_path)
    if not owner:
        return 0
    uid, gid, _name = owner
    changed = 0
    skip = {'.git', 'data', 'node_modules', '__pycache__', 'venv', '.venv'}
    try:
        for root, dirs, files in os.walk(repo_path):
            if root == repo_path:
                dirs[:] = [d for d in dirs if d not in skip]
            for name in dirs + files:
                path = os.path.join(root, name)
                try:
                    st = os.lstat(path)
                    if st.st_uid != uid or st.st_gid != gid:
                        os.lchown(path, uid, gid)
                        changed += 1
                except OSError:
                    continue
        # .git itself must be owned correctly or the next git command fails,
        # but it is walked separately so the skip list above stays readable.
        git_dir = os.path.join(repo_path, '.git')
        for root, dirs, files in os.walk(git_dir):
            for name in dirs + files:
                path = os.path.join(root, name)
                try:
                    st = os.lstat(path)
                    if st.st_uid != uid or st.st_gid != gid:
                        os.lchown(path, uid, gid)
                        changed += 1
                except OSError:
                    continue
        try:
            os.lchown(repo_path, uid, gid)
            os.lchown(git_dir, uid, gid)
        except OSError:
            pass
    except PermissionError:
        # Not running as root - nothing to do, and nothing broken by it.
        return changed
    except Exception as exc:  # pragma: no cover - defensive
        if warnings is not None:
            warnings.append(f"Ownership refresh incomplete: {exc}")
    if changed:
        logger.info(f"Restored ownership on {changed} path(s) under {repo_path}")
    return changed


def refresh_exec_bits(repo_path, warnings=None):
    """Re-assert +x on the scripts the service and the installer invoke.

    Ragnar's own launchers live at the top level and the shell helpers are
    scattered; a checkout that lost its exec bits (tarball install, a filesystem
    mounted without them, a botched chmod) starts up broken after an update.
    """
    fixed = 0
    try:
        for name in os.listdir(repo_path):
            if name.endswith('.py') or name.endswith('.sh'):
                path = os.path.join(repo_path, name)
                if os.path.isfile(path):
                    try:
                        os.chmod(path, os.stat(path).st_mode | 0o755)
                        fixed += 1
                    except OSError:
                        continue
        for sub in ('scripts', 'bin'):
            subdir = os.path.join(repo_path, sub)
            if not os.path.isdir(subdir):
                continue
            for root, _dirs, files in os.walk(subdir):
                for name in files:
                    if not name.endswith('.sh'):
                        continue
                    path = os.path.join(root, name)
                    try:
                        os.chmod(path, os.stat(path).st_mode | 0o755)
                        fixed += 1
                    except OSError:
                        continue
    except Exception as exc:  # pragma: no cover - defensive
        if warnings is not None:
            warnings.append(f"Could not refresh executable bits: {exc}")
    return fixed


def ensure_remote(repo_path, warnings=None):
    """Make sure an 'origin' remote exists and is fetchable without credentials."""
    remotes = run_git(['remote'], repo_path, timeout=GIT_QUICK_TIMEOUT)
    names = remotes.out.split() if remotes.ok else []
    if 'origin' not in names:
        add = run_git(['remote', 'add', 'origin', DEFAULT_REMOTE_URL], repo_path,
                      timeout=GIT_QUICK_TIMEOUT)
        if not add.ok:
            return False, add.message
        msg = f"No 'origin' remote was configured; added {DEFAULT_REMOTE_URL}"
        logger.warning(msg)
        if warnings is not None:
            warnings.append(msg)
    return True, ''


def _reattach_branch_candidates(repo_path):
    """Branches to try when rebuilding metadata, upstream's own default first."""
    candidates = []
    res = run_git(['ls-remote', '--symref', 'origin', 'HEAD'], repo_path,
                  timeout=GIT_QUICK_TIMEOUT, network=True)
    if res.ok:
        for line in res.out.splitlines():
            if line.startswith('ref: ') and 'refs/heads/' in line:
                candidates.append(line.split('refs/heads/', 1)[1].split()[0])
                break
    for fallback in FALLBACK_BRANCHES:
        if fallback not in candidates:
            candidates.append(fallback)
    return candidates


def reattach_repository(repo_path, warnings=None):
    """Rebuild .git in place for a tarball install, keeping every file on disk.

    When git is unusable at install time the installer unpacks a release
    tarball, which leaves a complete working tree with no repository metadata -
    and from then on every update had nothing to work with. If git runs now,
    reattach instead of dead-ending the user into a full reinstall. Only .git
    is created; the working tree, including all local data, is left alone.
    """
    git_dir = os.path.join(repo_path, '.git')
    if os.path.isdir(git_dir):
        return True, ''
    logger.warning("No .git found - reattaching this tarball install to upstream")
    for args, timeout, network in (
        (['init', '-q', repo_path], GIT_LOCAL_TIMEOUT, False),
        (['remote', 'add', 'origin', DEFAULT_REMOTE_URL], GIT_QUICK_TIMEOUT, False),
    ):
        res = run_git(args, repo_path, timeout=timeout, network=network)
        if not res.ok:
            shutil.rmtree(git_dir, ignore_errors=True)
            return False, res.message

    # Ask upstream which branch it publishes rather than assuming 'main': a
    # wrong guess fails with "couldn't find remote ref", which reads to the user
    # as "the repair does not work" on a box that is perfectly fine.
    fetch_err = ''
    for branch in _reattach_branch_candidates(repo_path):
        res = run_git(['fetch', '--depth=1', 'origin', branch], repo_path,
                      timeout=GIT_NETWORK_TIMEOUT, network=True)
        if res.ok:
            break
        fetch_err = res.message
    else:
        shutil.rmtree(git_dir, ignore_errors=True)
        return False, fetch_err or 'no upstream branch could be fetched'

    # Point the branch at upstream WITHOUT touching the working tree: files
    # already on disk survive, and anything that differs from upstream simply
    # shows up as a normal local modification that the update path then handles.
    for args in (
        ['reset', '-q', '--mixed', 'FETCH_HEAD'],
        ['branch', '-q', '-f', branch, 'FETCH_HEAD'],
        ['symbolic-ref', 'HEAD', f'refs/heads/{branch}'],
        ['branch', '-q', f'--set-upstream-to=origin/{branch}', branch],
    ):
        run_git(args, repo_path, timeout=GIT_LOCAL_TIMEOUT, identity=True)
    # Restore only files upstream has that the tree is missing (a tarball can be
    # short of dotfiles). Modified files are left alone so real local edits
    # still reach the stash path intact.
    missing = run_git(['ls-files', '-d'], repo_path, timeout=GIT_LOCAL_TIMEOUT)
    if missing.ok and missing.out:
        paths = [p for p in missing.out.splitlines() if p.strip()]
        for chunk in (paths[i:i + 100] for i in range(0, len(paths), 100)):
            run_git(['checkout', '--'] + chunk, repo_path, timeout=GIT_LOCAL_TIMEOUT)
    msg = 'Repository metadata was missing (tarball install) and has been rebuilt'
    if warnings is not None:
        warnings.append(msg)
    return True, ''


# --- branch resolution ------------------------------------------------------

def _remote_has(repo_path, branch):
    res = run_git(['rev-parse', '--verify', '--quiet', f'refs/remotes/origin/{branch}^{{commit}}'],
                  repo_path, timeout=GIT_QUICK_TIMEOUT)
    return res.ok and bool(res.out)


def remote_default_branch(repo_path):
    """Upstream's default branch, without a network round trip if avoidable."""
    res = run_git(['symbolic-ref', '--short', 'refs/remotes/origin/HEAD'], repo_path,
                  timeout=GIT_QUICK_TIMEOUT)
    if res.ok and res.out.startswith('origin/'):
        return res.out.split('/', 1)[1]
    # origin/HEAD is often absent on clones made with --depth or --single-branch.
    run_git(['remote', 'set-head', 'origin', '--auto'], repo_path, timeout=GIT_QUICK_TIMEOUT,
            network=True)
    res = run_git(['symbolic-ref', '--short', 'refs/remotes/origin/HEAD'], repo_path,
                  timeout=GIT_QUICK_TIMEOUT)
    if res.ok and res.out.startswith('origin/'):
        return res.out.split('/', 1)[1]
    for candidate in FALLBACK_BRANCHES:
        if _remote_has(repo_path, candidate):
            return candidate
    return FALLBACK_BRANCHES[0]


def current_branch(repo_path):
    """Checked-out branch name, or None when HEAD is detached/unborn."""
    res = run_git(['symbolic-ref', '--short', '--quiet', 'HEAD'], repo_path,
                  timeout=GIT_QUICK_TIMEOUT)
    if res.ok and res.out:
        return res.out
    return None


def resolve_target_branch(repo_path, warnings=None):
    """Which branch this box should end up on, and whether it must switch.

    A detached HEAD, or a branch that upstream has since deleted, used to fail
    the pull outright. Both now fall back to upstream's default branch.
    """
    head = current_branch(repo_path)
    if head and _remote_has(repo_path, head):
        return head, False
    default = remote_default_branch(repo_path)
    if head:
        msg = (f"Branch '{head}' no longer exists on origin; updating from "
               f"'{default}' instead")
    else:
        msg = f"Checkout was detached from any branch; switching to '{default}'"
    logger.warning(msg)
    if warnings is not None:
        warnings.append(msg)
    return default, True


# --- preflight --------------------------------------------------------------

def preflight(repo_path=None, warnings=None):
    """Make the checkout usable before the first real git command runs.

    Returns (ok, code, error). Everything here is idempotent and safe to run on
    a perfectly healthy box.
    """
    repo_path = repo_path or repo_root()
    warnings = warnings if warnings is not None else []

    usable, detail = git_usable()
    if not usable:
        return False, 'git_missing', f"git does not run on this system ({detail})"

    if not os.path.isdir(os.path.join(repo_path, '.git')):
        ok, err = reattach_repository(repo_path, warnings)
        if not ok:
            code, _hint = classify(err)
            return False, ('not_a_repo' if code == 'git_error' else code), (
                f"This install has no git metadata and could not be reattached upstream: {err}")

    try:
        free = shutil.disk_usage(repo_path).free
        if free < DISK_HARD_FLOOR:
            return False, 'disk_full', (
                f"Only {free // (1024 * 1024)} MB free on the Ragnar partition - "
                "an update needs more room than that")
        if free < DISK_WARN_FLOOR:
            warnings.append(f"Low disk space: {free // (1024 * 1024)} MB free")
    except OSError:
        pass

    ensure_safe_directory(repo_path)
    clear_stale_locks(repo_path, warnings)
    abort_in_progress_operation(repo_path, warnings)
    ok, err = ensure_remote(repo_path, warnings)
    if not ok:
        return False, 'no_remote', f"Could not configure the 'origin' remote: {err}"
    return True, '', ''


# --- status -----------------------------------------------------------------

def _short_commit(repo_path, rev):
    res = run_git(['log', '-1', '--format=%h %s', rev], repo_path, timeout=GIT_QUICK_TIMEOUT)
    return res.out if res.ok else ''


def _working_tree_status(repo_path):
    status = {
        'is_dirty': False,
        'has_conflicts': False,
        'has_stash': False,
        'stash_entries': 0,
        'modified_files': [],
        'conflicted_files': [],
        'status_error': '',
    }
    res = run_git(['--no-optional-locks', 'status', '--porcelain'], repo_path,
                  timeout=GIT_LOCAL_TIMEOUT)
    if not res.ok:
        status['status_error'] = res.message
        return status
    conflict_codes = {'AA', 'DD', 'AU', 'UA', 'DU', 'UD', 'UU'}
    for line in res.out.splitlines():
        if not line.strip():
            continue
        code = line[:2]
        path = line[3:].strip() if len(line) > 3 else line.strip()
        entry = {'code': code, 'path': path}
        status['modified_files'].append(entry)
        if code in conflict_codes:
            status['conflicted_files'].append(entry)
    status['is_dirty'] = bool(status['modified_files'])
    status['has_conflicts'] = bool(status['conflicted_files'])

    stash = run_git(['stash', 'list'], repo_path, timeout=GIT_LOCAL_TIMEOUT)
    if stash.ok:
        lines = [ln for ln in stash.out.splitlines() if ln.strip()]
        status['stash_entries'] = len(lines)
        status['has_stash'] = bool(lines)
    elif not status['status_error']:
        status['status_error'] = stash.message
    return status


def _reattach_for_check(repo_path, warnings):
    """Rebuild missing repository metadata from inside the update check.

    Bounded on both sides: it never runs while an update holds the lock, and a
    failure (offline box) backs off instead of re-downloading on every
    dashboard poll - every open tab polls this endpoint.
    """
    now = time.time()
    if now - _LAST_REATTACH_ATTEMPT[0] < REATTACH_RETRY_SECONDS:
        return False
    if not _UPDATE_LOCK.acquire(blocking=False):
        return False
    try:
        _LAST_REATTACH_ATTEMPT[0] = now
        ok, err = reattach_repository(repo_path, warnings)
        if not ok:
            logger.warning(f"Automatic reattach during update check failed: {err}")
        return ok
    finally:
        _UPDATE_LOCK.release()


def check(repo_path=None, allow_fetch=True):
    """Report whether an update is available. Bounded, and never raises.

    Called on a timer by every open dashboard tab, so it must not be able to
    block an update the user is trying to start: when one is running it answers
    from the refs already on disk instead of taking the lock.
    """
    repo_path = repo_path or repo_root()
    warnings = []
    result = {
        'ok': True,
        'code': '',
        'error': '',
        'hint': '',
        'repo_path': repo_path,
        'updates_available': False,
        'commits_behind': 0,
        'commits_ahead': 0,
        'current_commit': '',
        'latest_commit': '',
        'branch': '',
        'detached': False,
        'fetched': False,
        'update_in_progress': _UPDATE_STATE['running'],
        'warnings': warnings,
        'git_status': {},
    }

    usable, detail = git_usable()
    if not usable:
        result.update({'ok': False, 'code': 'git_missing',
                       'error': f"git does not run on this system ({detail})",
                       'hint': _HINTS['git_missing']})
        return result

    ensure_safe_directory(repo_path)

    if not os.path.isdir(os.path.join(repo_path, '.git')):
        # A tarball install is not broken and it is not behind: the installer
        # unpacked the current release, it just left no metadata to compare
        # against. Rebuilding that is cheap and needs no user decision, so do it
        # here rather than parking a freshly installed box on "Needs attention"
        # and asking the user to click Repair on an install that is up to date.
        if not _reattach_for_check(repo_path, warnings):
            result.update({'ok': False, 'code': 'not_a_repo',
                           'error': 'This install has no git metadata (installed from a tarball).',
                           'hint': 'Ragnar could not rebuild it - check the box\'s internet '
                                   'connection. Clicking Update retries the repair.'})
            return result

    # Only fetch when no update holds the lock. A background check's fetch
    # racing a user-clicked pull is exactly what made first-click updates fail.
    if allow_fetch and _UPDATE_LOCK.acquire(blocking=False):
        try:
            clear_stale_locks(repo_path)
            ensure_remote(repo_path, warnings)
            fetch = run_git(['fetch', '--prune', 'origin'], repo_path,
                            timeout=GIT_CHECK_TIMEOUT, network=True)
            result['fetched'] = fetch.ok
            if not fetch.ok:
                code, hint = classify(fetch.message, fetch.timed_out)
                result.update({'ok': False, 'code': code, 'error': fetch.message, 'hint': hint})
                # Keep going: the counts below are still worth showing, they are
                # just computed against the refs we already had.
        finally:
            _UPDATE_LOCK.release()
    elif allow_fetch:
        warnings.append('An update is running; showing the last known state')

    head = current_branch(repo_path)
    result['detached'] = head is None
    branch = head or remote_default_branch(repo_path)
    result['branch'] = branch
    if not _remote_has(repo_path, branch):
        branch = remote_default_branch(repo_path)
        result['branch'] = branch

    result['current_commit'] = _short_commit(repo_path, 'HEAD')
    result['latest_commit'] = _short_commit(repo_path, f'origin/{branch}')
    if not result['latest_commit'] and result['ok']:
        # No upstream ref to compare against - report it rather than showing a
        # confident "up to date" that is really "I could not tell".
        result.update({
            'ok': False, 'code': 'branch_missing',
            'error': f"origin/{branch} is not available locally",
            'hint': 'Ragnar could not read the upstream branch. Check the box\'s internet '
                    'connection, then click Update to let it repair the checkout.',
        })
        return result

    counts = run_git(['rev-list', '--left-right', '--count', f'HEAD...origin/{branch}'],
                     repo_path, timeout=GIT_LOCAL_TIMEOUT)
    if counts.ok:
        parts = counts.out.split()
        if len(parts) == 2:
            try:
                result['commits_ahead'] = int(parts[0])
                result['commits_behind'] = int(parts[1])
            except ValueError:
                pass
    result['updates_available'] = result['commits_behind'] > 0
    result['git_status'] = _working_tree_status(repo_path)
    return result


# --- the update itself ------------------------------------------------------

def is_updating():
    return _UPDATE_STATE['running']


def update_state():
    return dict(_UPDATE_STATE)


def update(repo_path=None, on_step=None):
    """Bring the checkout to origin/<branch>, or leave it exactly as it was.

    The happy path is a fast-forward, which needs no identity, writes no merge
    commit and cannot conflict. Anything else - local edits, local commits, a
    diverged history, untracked files in the way - is handled by stashing what
    the user has and forcing the tree onto origin, which is deterministic and
    always lands. The stash is only dropped once it has been re-applied
    cleanly, so nothing is ever destroyed silently.
    """
    repo_path = repo_path or repo_root()
    result = {
        'ok': False,
        'success': False,
        'code': '',
        'error': '',
        'hint': '',
        'output': '',
        'warnings': [],
        'steps': [],
        'branch': '',
        'from_commit': '',
        'to_commit': '',
        'forced': False,
        'stash_ref': '',
        'stash_kept': False,
        'requirements_changed': False,
        'already_current': False,
        'repo_path': repo_path,
    }
    warnings = result['warnings']

    def step(name):
        result['steps'].append(name)
        _UPDATE_STATE['step'] = name
        logger.info(f"Update step: {name}")
        if on_step:
            try:
                on_step(name)
            except Exception:
                pass

    if not _UPDATE_LOCK.acquire(blocking=False):
        return _fail(result, 'busy', 'An update is already running on this box.')
    _UPDATE_STATE.update({'running': True, 'started': time.time(), 'step': 'starting'})
    try:
        step('preflight')
        ok, code, err = preflight(repo_path, warnings)
        if not ok:
            return _fail(result, code, err)

        result['from_commit'] = run_git(['rev-parse', 'HEAD'], repo_path,
                                        timeout=GIT_QUICK_TIMEOUT).out

        step('fetch')
        fetch = _fetch_with_retry(repo_path, warnings)
        if not fetch.ok:
            code, hint = classify(fetch.message, fetch.timed_out)
            return _fail(result, code, f"Could not fetch from origin: {fetch.message}", hint)

        branch, must_switch = resolve_target_branch(repo_path, warnings)
        result['branch'] = branch
        target = run_git(['rev-parse', f'origin/{branch}^{{commit}}'], repo_path,
                         timeout=GIT_QUICK_TIMEOUT)
        if not target.ok:
            return _fail(result, 'branch_missing',
                         f"origin/{branch} does not exist after fetching")
        result['to_commit'] = target.out

        status = _working_tree_status(repo_path)
        dirty = status['is_dirty']

        # Fast path: clean tree, no local commits, plain fast-forward.
        if not dirty and not must_switch:
            step('fast-forward')
            ff = run_git(['merge', '--ff-only', f'origin/{branch}'], repo_path,
                         timeout=GIT_LOCAL_TIMEOUT, identity=True)
            if ff.ok:
                result['output'] = ff.out or f"Fast-forwarded to origin/{branch}"
                return _finish(result, repo_path, warnings)
            warnings.append('Fast-forward was not possible; syncing the checkout to origin')

        # Everything else: protect what the user has, then force the tree onto
        # origin. Deterministic, and it cannot be defeated by conflicts.
        result['forced'] = True
        if dirty:
            step('stash local changes')
            label = f"Ragnar auto stash {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            stash = run_git(['stash', 'push', '-u', '-m', label], repo_path,
                            timeout=GIT_LOCAL_TIMEOUT, identity=True)
            if stash.ok and 'No local changes' not in stash.out:
                result['stash_ref'] = 'stash@{0}'
                logger.info(f"Local changes stashed as {result['stash_ref']}")
            elif not stash.ok:
                # Stashing can fail on an unreadable file; the reset below still
                # works, so warn loudly rather than abandoning the update.
                warnings.append(
                    f"Could not stash local changes ({stash.message}); they will be replaced "
                    "by the upstream versions")

        step('sync to origin')
        if must_switch:
            switch = run_git(['checkout', '-f', '-B', branch, f'origin/{branch}'], repo_path,
                             timeout=GIT_LOCAL_TIMEOUT, identity=True)
            if not switch.ok:
                code, hint = classify(switch.message)
                return _restore(result, repo_path, code,
                                f"Could not switch to {branch}: {switch.message}", hint)
        reset = run_git(['reset', '--hard', f'origin/{branch}'], repo_path,
                        timeout=GIT_LOCAL_TIMEOUT, identity=True)
        if not reset.ok:
            code, hint = classify(reset.message)
            return _restore(result, repo_path, code,
                            f"Could not sync the checkout to origin/{branch}: {reset.message}",
                            hint)
        # -fd removes untracked leftovers that would shadow new tracked files.
        # Never -x: ignored files are the box's own data and must survive.
        run_git(['clean', '-fd'], repo_path, timeout=GIT_LOCAL_TIMEOUT)
        result['output'] = f"Synced to origin/{branch} ({result['to_commit'][:8]})"

        if result['stash_ref']:
            step('replay local changes')
            _replay_stash(repo_path, result, warnings, branch)

        return _finish(result, repo_path, warnings)
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Unexpected error during update")
        return _fail(result, 'git_error', f"Unexpected error during update: {exc}")
    finally:
        _UPDATE_STATE.update({'running': False, 'step': ''})
        _UPDATE_LOCK.release()


def _fetch_with_retry(repo_path, warnings, attempts=3):
    """Fetch, retrying transient network trouble with a short backoff."""
    last = None
    for attempt in range(1, attempts + 1):
        res = run_git(['fetch', '--prune', 'origin'], repo_path,
                      timeout=GIT_NETWORK_TIMEOUT, network=True)
        if res.ok:
            return res
        last = res
        code, _hint = classify(res.message, res.timed_out)
        if code == 'locked':
            clear_stale_locks(repo_path, warnings, min_age_seconds=0)
        elif code not in ('offline', 'timeout'):
            # Nothing about auth, disk or a broken repo improves by retrying.
            return res
        if attempt < attempts:
            warnings.append(f"Fetch attempt {attempt} failed ({code}); retrying")
            time.sleep(2 * attempt)
    return last


def _replay_stash(repo_path, result, warnings, branch):
    """Re-apply stashed local edits, but never at the cost of a working box.

    ``git stash pop`` on a conflict leaves conflict markers in tracked source
    files - the update "succeeds" and the service then refuses to start. So the
    stash is applied, and if that does not come out clean the tree is put back
    on origin and the stash is kept for the user to recover by hand.
    """
    apply_res = run_git(['stash', 'apply', '--index', result['stash_ref']], repo_path,
                        timeout=GIT_LOCAL_TIMEOUT, identity=True)
    if not apply_res.ok:
        apply_res = run_git(['stash', 'apply', result['stash_ref']], repo_path,
                            timeout=GIT_LOCAL_TIMEOUT, identity=True)
    conflicted = _working_tree_status(repo_path)['has_conflicts']
    if apply_res.ok and not conflicted:
        run_git(['stash', 'drop', result['stash_ref']], repo_path, timeout=GIT_LOCAL_TIMEOUT)
        logger.info("Local changes replayed on top of the update")
        return
    run_git(['reset', '--hard', f'origin/{branch}'], repo_path, timeout=GIT_LOCAL_TIMEOUT)
    run_git(['clean', '-fd'], repo_path, timeout=GIT_LOCAL_TIMEOUT)
    result['stash_kept'] = True
    warnings.append(
        "Your local edits clashed with this update, so they were left in a git stash instead of "
        "being applied. The box is running the new version; recover them with "
        "'git stash list' and 'git stash pop'.")


def _restore(result, repo_path, code, error, hint=None):
    """Abandon a failed update without leaving the box worse off."""
    if result.get('stash_ref'):
        pop = run_git(['stash', 'pop', result['stash_ref']], repo_path,
                      timeout=GIT_LOCAL_TIMEOUT, identity=True)
        if pop.ok:
            result['warnings'].append('Update failed; local changes were restored')
        else:
            result['stash_kept'] = True
            result['warnings'].append(
                'Update failed and local changes could not be restored automatically - '
                "they are safe in a git stash ('git stash list')")
    return _fail(result, code, error, hint)


def _finish(result, repo_path, warnings):
    """Post-update housekeeping and a check that the tree really did land."""
    head = run_git(['rev-parse', 'HEAD'], repo_path, timeout=GIT_QUICK_TIMEOUT).out
    if result['to_commit'] and head != result['to_commit']:
        # Only reachable if git reported success while the tree stayed behind.
        return _fail(result, 'git_error',
                     f"The checkout is still at {head[:8]} after updating to "
                     f"{result['to_commit'][:8]}")
    result['already_current'] = bool(result['from_commit']) and head == result['from_commit']

    if result['from_commit'] and result['from_commit'] != head:
        diff = run_git(['diff', '--name-only', result['from_commit'], head], repo_path,
                       timeout=GIT_LOCAL_TIMEOUT)
        if diff.ok:
            changed = diff.out.splitlines()
            result['requirements_changed'] = any(
                name.strip() == 'requirements.txt' for name in changed)
            result['files_changed'] = len(changed)
        else:
            # A shallow clone cannot always diff across the update. Assume the
            # dependencies moved: an unnecessary pip run costs a minute, a
            # skipped one restarts the service into imports that do not exist.
            result['requirements_changed'] = True
            result['files_changed'] = 0
            warnings.append('Could not list changed files; installing dependencies to be safe')
    else:
        result['files_changed'] = 0

    restore_ownership(repo_path, warnings)
    refresh_exec_bits(repo_path, warnings)

    result['ok'] = True
    result['success'] = True
    result['code'] = ''
    if not result['output']:
        result['output'] = f"Updated to {head[:8]}"
    logger.info(f"Update finished: {result['output']}")
    return result


__all__ = [
    'check', 'update', 'preflight', 'repo_root', 'is_updating', 'update_state',
    'clear_stale_locks', 'ensure_safe_directory', 'reattach_repository',
    'resolve_target_branch', 'remote_default_branch', 'current_branch',
    'restore_ownership', 'refresh_exec_bits', 'classify', 'run_git', 'git_usable',
    'GIT_NETWORK_TIMEOUT', 'GIT_LOCAL_TIMEOUT', 'LOCK_STALE_SECONDS',
]
