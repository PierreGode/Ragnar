"""Tests for the self-update engine.

Thousands of boxes update themselves by clicking Update in the web UI, and the
bug reports that motivated git_updater.py all looked the same from the outside:
"it just says error". So these tests are built around the checkout states that
produced those errors - dirty trees, untracked files in the way, detached HEADs,
branches deleted upstream, diverged history, leftover locks, a half-finished
merge, no .git at all - and assert the two properties that actually matter:

  1. the update lands (HEAD ends up on origin/<branch>), and
  2. nothing the user cares about is destroyed - local edits survive in a stash,
     and gitignored private data is never touched.

Every test drives real git against real repositories in a temp dir; nothing is
mocked, because the failures being fixed were all in git's actual behaviour.
"""

import os
import subprocess
import time

import pytest

import git_updater as gu


pytestmark = pytest.mark.skipif(
    subprocess.run(['git', '--version'], capture_output=True).returncode != 0,
    reason='git is not usable on this machine',
)


# --- fixtures ---------------------------------------------------------------

def _git(repo, *args, check=True):
    proc = subprocess.run(
        ['git', '-c', 'user.name=Test', '-c', 'user.email=test@localhost',
         '-c', 'commit.gpgsign=false', '-c', 'protocol.file.allow=always'] + list(args),
        cwd=repo, capture_output=True, text=True,
    )
    if check and proc.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {proc.stderr}")
    return proc.stdout.strip()


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as fh:
        fh.write(text)


@pytest.fixture
def upstream(tmp_path):
    """A bare-ish origin repository with one commit on main."""
    origin = tmp_path / 'origin'
    origin.mkdir()
    _git(origin, 'init', '-q', '-b', 'main')
    _write(str(origin / 'app.py'), "VERSION = 1\n")
    _write(str(origin / '.gitignore'), "data/\n*.db\n")
    _git(origin, 'add', '-A')
    _git(origin, 'commit', '-qm', 'initial')
    return origin


@pytest.fixture
def box(tmp_path, upstream):
    """A checkout standing in for a user's Ragnar box, with private data in it."""
    clone = tmp_path / 'box'
    _git(tmp_path, 'clone', '-q', str(upstream), str(clone))
    _git(clone, 'config', 'user.name', 'Box')
    _git(clone, 'config', 'user.email', 'box@localhost')
    # The private data every real box carries: gitignored, and must survive
    # every recovery path the updater can take.
    _write(str(clone / 'data' / 'ragnar.db'), 'PRIVATE-DB')
    _write(str(clone / 'secrets.db'), 'PRIVATE-KEYS')
    return clone


def _publish(upstream, filename='app.py', content='VERSION = 2\n', message='v2'):
    """Push a new commit into origin so the box has something to update to."""
    _write(str(upstream / filename), content)
    _git(upstream, 'add', '-A')
    _git(upstream, 'commit', '-qm', message)
    return _git(upstream, 'rev-parse', 'HEAD')


def _head(repo):
    return _git(repo, 'rev-parse', 'HEAD')


def _private_data_intact(box):
    return (
        (box / 'data' / 'ragnar.db').read_text() == 'PRIVATE-DB'
        and (box / 'secrets.db').read_text() == 'PRIVATE-KEYS'
    )


# --- the ordinary case ------------------------------------------------------

def test_clean_checkout_fast_forwards(box, upstream):
    target = _publish(upstream)
    result = gu.update(str(box))
    assert result['ok'], result
    assert _head(box) == target
    assert result['forced'] is False       # a plain fast-forward, no merge commit
    assert 'fast-forward' in result['steps']
    assert _private_data_intact(box)


def test_up_to_date_box_reports_success_without_changing_anything(box):
    before = _head(box)
    result = gu.update(str(box))
    assert result['ok'], result
    assert _head(box) == before
    assert result['already_current'] is True


def test_requirements_change_is_reported_so_dependencies_get_installed(box, upstream):
    # A commit that adds a Python dependency used to leave the box restarting
    # into modules it could not import: the web updater never ran pip.
    _publish(upstream, 'requirements.txt', 'requests>=2\n', 'add a dependency')
    result = gu.update(str(box))
    assert result['ok'], result
    assert result['requirements_changed'] is True


def test_unrelated_change_does_not_trigger_a_dependency_install(box, upstream):
    _publish(upstream)
    result = gu.update(str(box))
    assert result['requirements_changed'] is False


# --- local modifications ----------------------------------------------------

def test_local_commits_give_way_to_upstream(box, upstream):
    _write(str(box / 'notes.txt'), 'my local notes\n')
    _git(box, 'add', 'notes.txt')
    _git(box, 'commit', '-qm', 'local note')   # committed, so the tree is clean
    target = _publish(upstream)

    result = gu.update(str(box))
    assert result['ok'], result
    assert _head(box) == target
    # Local commits are not upstream's problem: the box is force-synced, and the
    # commit is still reachable through the reflog if the user needs it.
    assert result['forced'] is True


def test_uncommitted_edit_survives_the_update(box, upstream):
    _write(str(box / 'local_config.txt'), 'my tweak\n')     # untracked local file
    _publish(upstream)

    result = gu.update(str(box))
    assert result['ok'], result
    assert (box / 'local_config.txt').read_text() == 'my tweak\n'
    assert result['stash_kept'] is False      # replayed cleanly, stash dropped
    assert _private_data_intact(box)


def test_conflicting_edit_leaves_a_working_box_and_keeps_the_changes(box, upstream):
    # The worst historical outcome: `git stash pop` hit a conflict, wrote
    # conflict markers into a tracked source file, and the service would not
    # start afterwards. The update must land clean and park the edit in a stash.
    _write(str(box / 'app.py'), "VERSION = 1\nMY_LOCAL_HACK = True\n")
    target = _publish(upstream, 'app.py', "VERSION = 2\nUPSTREAM_FEATURE = True\n")

    result = gu.update(str(box))
    assert result['ok'], result
    assert _head(box) == target
    assert 'MY_LOCAL_HACK' not in (box / 'app.py').read_text()
    assert '<<<<<<<' not in (box / 'app.py').read_text()
    assert result['stash_kept'] is True
    stashes = _git(box, 'stash', 'list')
    assert 'Ragnar auto stash' in stashes
    assert any('git stash' in w for w in result['warnings'])


def test_untracked_file_standing_where_a_new_tracked_file_lands(box, upstream):
    # "error: The following untracked working tree files would be overwritten by
    # merge" - a plain pull cannot recover from this on its own.
    _write(str(box / 'newmodule.py'), 'stale copy\n')
    target = _publish(upstream, 'newmodule.py', 'upstream version\n', 'add newmodule')

    result = gu.update(str(box))
    assert result['ok'], result
    assert _head(box) == target
    assert (box / 'newmodule.py').read_text() == 'upstream version\n'


def test_gitignored_data_survives_a_forced_sync(box, upstream):
    # The forced path uses `git clean -fd`, never -x, precisely so this holds.
    _write(str(box / 'app.py'), 'locally mangled\n')
    _publish(upstream, 'app.py', "VERSION = 3\n")
    result = gu.update(str(box))
    assert result['ok'], result
    assert result['forced'] is True
    assert _private_data_intact(box)


# --- broken checkout states -------------------------------------------------

def test_detached_head_recovers_to_the_default_branch(box, upstream):
    _git(box, 'checkout', '-q', '--detach', 'HEAD')
    target = _publish(upstream)

    result = gu.update(str(box))
    assert result['ok'], result
    assert _head(box) == target
    assert gu.current_branch(str(box)) == 'main'


def test_branch_deleted_upstream_falls_back_to_the_default_branch(box, upstream):
    _git(box, 'checkout', '-qb', 'experiment')
    target = _publish(upstream)

    result = gu.update(str(box))
    assert result['ok'], result
    assert result['branch'] == 'main'
    assert _head(box) == target
    assert any('no longer exists on origin' in w for w in result['warnings'])


def test_diverged_history_is_force_synced(box, upstream):
    _write(str(box / 'app.py'), 'divergent local work\n')
    _git(box, 'add', '-A')
    _git(box, 'commit', '-qm', 'local divergence')
    target = _publish(upstream, 'app.py', 'upstream work\n')

    result = gu.update(str(box))
    assert result['ok'], result
    assert _head(box) == target
    assert (box / 'app.py').read_text() == 'upstream work\n'


def test_unfinished_merge_from_an_earlier_crash_is_aborted(box, upstream):
    # A box left mid-merge failed every later update with "you have not
    # concluded your merge" and had no way out through the web UI.
    _git(box, 'checkout', '-qb', 'side')
    _write(str(box / 'app.py'), 'side change\n')
    _git(box, 'add', '-A')
    _git(box, 'commit', '-qm', 'side')
    _git(box, 'checkout', '-q', 'main')
    _write(str(box / 'app.py'), 'main change\n')
    _git(box, 'add', '-A')
    _git(box, 'commit', '-qm', 'main')
    _git(box, 'merge', 'side', check=False)        # leaves MERGE_HEAD + conflict
    assert os.path.exists(str(box / '.git' / 'MERGE_HEAD'))

    target = _publish(upstream)
    result = gu.update(str(box))
    assert result['ok'], result
    assert not os.path.exists(str(box / '.git' / 'MERGE_HEAD'))
    assert _head(box) == target


def test_missing_origin_remote_is_recreated(box, upstream, monkeypatch):
    monkeypatch.setattr(gu, 'DEFAULT_REMOTE_URL', str(upstream))
    _git(box, 'remote', 'remove', 'origin')
    target = _publish(upstream)

    result = gu.update(str(box))
    assert result['ok'], result
    assert _head(box) == target
    assert any("origin" in w for w in result['warnings'])


def test_tarball_install_without_git_metadata_is_reattached(box, upstream, monkeypatch):
    # The installer falls back to unpacking a tarball when git is unusable at
    # install time, which leaves a full working tree and no .git - and every
    # update from then on had nothing to work with.
    monkeypatch.setattr(gu, 'DEFAULT_REMOTE_URL', str(upstream))
    subprocess.run(['rm', '-rf', str(box / '.git')], check=True)
    target = _publish(upstream)

    result = gu.update(str(box))
    assert result['ok'], result
    assert os.path.isdir(str(box / '.git'))
    assert _head(box) == target
    assert _private_data_intact(box)
    assert any('tarball' in w for w in result['warnings'])


# --- locks and concurrency --------------------------------------------------

def test_stale_locks_are_swept_but_live_ones_are_left_alone(box):
    stale = box / '.git' / 'refs' / 'remotes' / 'origin' / 'main.lock'
    os.makedirs(os.path.dirname(str(stale)), exist_ok=True)
    stale.write_text('')
    old = time.time() - 10 * 60
    os.utime(str(stale), (old, old))
    live = box / '.git' / 'index.lock'
    live.write_text('')

    removed = gu.clear_stale_locks(str(box))
    assert any('main.lock' in name for name in removed)
    assert not stale.exists()
    assert live.exists(), 'a lock from a running git process must not be deleted'


def test_locks_of_every_kind_are_swept_not_just_the_well_known_ones(box):
    names = ['packed-refs.lock', 'config.lock', 'HEAD.lock',
             os.path.join('refs', 'heads', 'feature-x.lock')]
    for name in names:
        path = box / '.git' / name
        os.makedirs(os.path.dirname(str(path)), exist_ok=True)
        path.write_text('')
        os.utime(str(path), (time.time() - 600, time.time() - 600))

    gu.clear_stale_locks(str(box))
    for name in names:
        assert not (box / '.git' / name).exists(), f'{name} was left behind'


def test_a_second_update_is_refused_instead_of_queued(box, monkeypatch):
    # Two dashboard tabs, two clicks. The second used to block on the mutex with
    # no feedback; now it returns immediately with a code the UI can explain.
    gu._UPDATE_LOCK.acquire()
    try:
        result = gu.update(str(box))
    finally:
        gu._UPDATE_LOCK.release()
    assert result['ok'] is False
    assert result['code'] == 'busy'
    assert result['hint']


def test_a_running_update_never_blocks_the_background_check(box):
    gu._UPDATE_LOCK.acquire()
    try:
        status = gu.check(str(box))
    finally:
        gu._UPDATE_LOCK.release()
    assert status['fetched'] is False          # skipped the fetch rather than waiting
    assert status['current_commit']


# --- status reporting -------------------------------------------------------

def test_check_counts_commits_behind(box, upstream):
    _publish(upstream)
    _publish(upstream, 'app.py', 'VERSION = 3\n', 'v3')
    status = gu.check(str(box))
    assert status['ok'], status
    assert status['updates_available'] is True
    assert status['commits_behind'] == 2
    assert status['branch'] == 'main'


def test_check_reports_local_modifications(box):
    _write(str(box / 'app.py'), 'edited\n')
    status = gu.check(str(box))
    assert status['git_status']['is_dirty'] is True
    assert status['git_status']['has_conflicts'] is False


def test_check_on_a_tarball_install_says_what_to_do(box):
    subprocess.run(['rm', '-rf', str(box / '.git')], check=True)
    status = gu.check(str(box))
    assert status['ok'] is False
    assert status['code'] == 'not_a_repo'
    assert 'Update' in status['hint']          # actionable, not just "error"


# --- error classification ---------------------------------------------------

@pytest.mark.parametrize('text,expected', [
    ("fatal: unable to access 'https://github.com/': Could not resolve host: github.com", 'offline'),
    ('fatal: Authentication failed for https://github.com/PierreGode/Ragnar.git/', 'auth'),
    ('fatal: could not read Username for https://github.com: terminal prompts disabled', 'auth'),
    ('fatal: write error: No space left on device', 'disk_full'),
    ("fatal: detected dubious ownership in repository at '/home/ragnar/Ragnar'", 'ownership'),
    ('fatal: Unable to create /home/ragnar/Ragnar/.git/index.lock: File exists', 'locked'),
    ("fatal: couldn't find remote ref nonexistent-branch", 'branch_missing'),
    ('fatal: not a git repository (or any of the parent directories): .git', 'not_a_repo'),
])
def test_git_errors_are_classified_with_an_actionable_hint(text, expected):
    code, hint = gu.classify(text)
    assert code == expected
    assert hint


def test_a_timeout_is_reported_as_a_timeout_not_a_git_error():
    code, hint = gu.classify('', timed_out=True)
    assert code == 'timeout'
    assert 'connection' in hint.lower()


def test_run_git_reports_a_timeout_instead_of_hanging(box):
    # The failure that had no ceiling before: a git command that never returns
    # held the request thread and the update lock forever.
    result = gu.run_git(['-c', 'core.pager=cat', 'log'], str(box), timeout=0.001)
    assert result.ok is False
    assert result.timed_out is True
    assert 'timed out' in result.message


def test_git_is_never_allowed_to_ask_a_human_for_anything():
    env = gu.git_env()
    assert env['GIT_TERMINAL_PROMPT'] == '0'
    assert 'BatchMode=yes' in env['GIT_SSH_COMMAND']
    assert env['LC_ALL'] == 'C'            # error matching must not depend on locale
    assert 'GIT_DIR' not in env            # a stray inherited GIT_DIR retargets everything


def test_repo_root_does_not_depend_on_the_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert os.path.isfile(os.path.join(gu.repo_root(), 'git_updater.py'))
