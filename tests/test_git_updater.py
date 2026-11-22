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


def test_freshly_installed_box_without_git_metadata_reports_up_to_date(box, upstream, monkeypatch):
    # A tarball install carries the current release; it just has no metadata to
    # compare against. Reported as "Needs attention", a brand-new box asked its
    # owner to click Repair on an install that was already up to date - so the
    # check rebuilds the metadata itself and then answers the real question.
    monkeypatch.setattr(gu, 'DEFAULT_REMOTE_URL', str(upstream))
    monkeypatch.setattr(gu, '_LAST_REATTACH_ATTEMPT', [0.0])
    subprocess.run(['rm', '-rf', str(box / '.git')], check=True)

    status = gu.check(str(box))
    assert status['ok'], status
    assert status['code'] == ''
    assert status['updates_available'] is False
    assert status['commits_behind'] == 0
    assert os.path.isdir(str(box / '.git'))
    assert _private_data_intact(box)
    assert any('rebuilt' in w for w in status['warnings'])


def test_reattached_box_then_sees_the_next_release(box, upstream, monkeypatch):
    monkeypatch.setattr(gu, 'DEFAULT_REMOTE_URL', str(upstream))
    monkeypatch.setattr(gu, '_LAST_REATTACH_ATTEMPT', [0.0])
    subprocess.run(['rm', '-rf', str(box / '.git')], check=True)
    gu.check(str(box))

    target = _publish(upstream)
    status = gu.check(str(box))
    assert status['updates_available'] is True
    assert status['commits_behind'] == 1

    assert gu.update(str(box))['ok']
    assert _head(box) == target


def test_tarball_install_that_cannot_reach_upstream_says_what_to_do(box, upstream, monkeypatch):
    monkeypatch.setattr(gu, 'DEFAULT_REMOTE_URL', str(upstream / 'nope.git'))
    monkeypatch.setattr(gu, '_LAST_REATTACH_ATTEMPT', [0.0])
    subprocess.run(['rm', '-rf', str(box / '.git')], check=True)

    status = gu.check(str(box))
    assert status['ok'] is False
    assert status['code'] == 'not_a_repo'
    assert 'Update' in status['hint']          # actionable, not just "error"
    # A half-built repository would be worse than none at all.
    assert not os.path.exists(str(box / '.git'))


def test_a_failing_reattach_is_not_retried_on_every_dashboard_poll(box, upstream, monkeypatch):
    # Every open tab polls the check on a timer; a repair that needs the network
    # must not be re-attempted each time.
    monkeypatch.setattr(gu, 'DEFAULT_REMOTE_URL', str(upstream / 'nope.git'))
    monkeypatch.setattr(gu, '_LAST_REATTACH_ATTEMPT', [0.0])
    subprocess.run(['rm', '-rf', str(box / '.git')], check=True)

    attempts = []
    real = gu.reattach_repository
    monkeypatch.setattr(gu, 'reattach_repository',
                        lambda *a, **k: (attempts.append(1), real(*a, **k))[1])

    gu.check(str(box))
    gu.check(str(box))
    gu.check(str(box))
    assert len(attempts) == 1


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


# --- broken tag recovery ----------------------------------------------------
#
# A release tag (os-v1.8.0) that was force-pushed, partially deleted or had its
# objects GC'd leaves a ref pointing at an object git can no longer read. From
# then on a plain `git fetch` aborts with "bad object refs/tags/..." / "did not
# send all necessary objects", which blocks every update AND every branch
# switch - the exact symptom users reported. The updater never needs a tag, so
# it drops the broken ref and fetches branch heads only.

def _plant_broken_tag(box, name='os-v1.8.0'):
    """Point a tag ref at an object that does not exist."""
    ref = box / '.git' / 'refs' / 'tags' / name
    ref.parent.mkdir(parents=True, exist_ok=True)
    ref.write_text('deadbeef' * 5 + '\n')   # 40 hex chars, no such object


def test_classify_flags_the_broken_tag_signature():
    code, _ = gu.classify('fatal: bad object refs/tags/os-v1.8.0\n'
                          'error: origin did not send all necessary objects')
    assert code == 'broken_tag'


def test_prune_broken_tags_drops_the_corrupt_ref_and_keeps_healthy_ones(box):
    _git(box, 'tag', 'v-good')               # a real tag on HEAD
    _plant_broken_tag(box)
    removed = gu.prune_broken_tags(str(box))
    assert removed == 1
    tags = _git(box, 'tag', '-l').split()
    assert 'v-good' in tags
    assert 'os-v1.8.0' not in tags


def test_plain_fetch_breaks_on_a_bad_tag_but_resilient_fetch_recovers(box, upstream):
    _publish(upstream)
    _plant_broken_tag(box)
    # The raw fetch really is broken by the planted tag (guards the premise).
    raw = gu.run_git(['fetch', '--prune', 'origin'], str(box))
    assert not raw.ok
    assert gu.classify(raw.message)[0] == 'broken_tag'
    # The resilient fetch prunes the bad ref and gets the new commit anyway.
    warnings = []
    res = gu.resilient_fetch(str(box), warnings)
    assert res.ok, res.message
    assert gu._remote_has(str(box), 'main')


def test_update_lands_even_with_a_broken_tag_present(box, upstream):
    target = _publish(upstream)
    _plant_broken_tag(box)
    result = gu.update(str(box))
    assert result['ok'], result
    assert _head(box) == target
    assert _private_data_intact(box)


# --- damaged git data ---------------------------------------------------------
# What a power cut during a write leaves behind: empty or half-written files
# under .git. Each of these used to leave a box unable to update, several of
# them behind the "a tag ... is corrupt" message with a dead Update button.

import glob as _glob
import shutil as _shutil


def _tags_dir(box):
    d = box / '.git' / 'refs' / 'tags'
    d.mkdir(parents=True, exist_ok=True)
    return d


def _unpack_all(box):
    """Turn packs into loose objects so one of them can be damaged."""
    for pack in _glob.glob(str(box / '.git' / 'objects' / 'pack' / '*.pack')):
        tmp = str(box / 'tmp.pack')
        _shutil.move(pack, tmp)
        for leftover in _glob.glob(str(box / '.git' / 'objects' / 'pack' / '*')):
            os.remove(leftover)
        with open(tmp, 'rb') as fh:
            subprocess.run(['git', 'unpack-objects', '-q'], cwd=box, stdin=fh, check=True)
        os.remove(tmp)


def _head_object_file(box):
    sha = (box / '.git' / 'refs' / 'heads' / 'main').read_text().strip()
    path = box / '.git' / 'objects' / sha[:2] / sha[2:]
    os.chmod(path, 0o644)
    return path


def _d_tag_bogus(box):
    (_tags_dir(box) / 'os-v1').write_text('deadbeef' * 5 + '\n')


def _d_tag_empty(box):
    (_tags_dir(box) / 'os-v1').write_text('')


def _d_tag_zero_bytes(box):
    (_tags_dir(box) / 'os-v1').write_bytes(b'\x00' * 41)


def _d_tag_packed(box):
    path = box / '.git' / 'packed-refs'
    old = path.read_text() if path.exists() else '# pack-refs with: peeled fully-peeled sorted \n'
    path.write_text(old + 'deadbeef' * 5 + ' refs/tags/os-v1\n')


def _d_remote_ref_bogus(box):
    (box / '.git' / 'refs' / 'remotes' / 'origin' / 'main').write_text('deadbeef' * 5 + '\n')


def _d_remote_ref_empty(box):
    (box / '.git' / 'refs' / 'remotes' / 'origin' / 'main').write_text('')


def _d_branch_empty(box):
    (box / '.git' / 'refs' / 'heads' / 'main').write_text('')


def _d_branch_bogus(box):
    (box / '.git' / 'refs' / 'heads' / 'main').write_text('deadbeef' * 5 + '\n')


def _d_stash_bogus(box):
    (box / '.git' / 'refs' / 'stash').write_text('deadbeef' * 5 + '\n')


def _d_object_empty(box):
    _unpack_all(box)
    _head_object_file(box).write_bytes(b'')


def _d_object_missing(box):
    _unpack_all(box)
    os.remove(_head_object_file(box))


def _d_head_empty(box):
    (box / '.git' / 'HEAD').write_text('')


def _d_index_empty(box):
    (box / '.git' / 'index').write_bytes(b'')


def _d_index_zero_bytes(box):
    (box / '.git' / 'index').write_bytes(b'\x00' * 200)


def _d_config_empty(box):
    (box / '.git' / 'config').write_text('')


def _d_config_half_written(box):
    (box / '.git' / 'config').write_bytes(b'[core\x00\x00\n\trepositoryformatversion = \n[remote "ori')


def _d_fetch_head_zero_bytes(box):
    (box / '.git' / 'FETCH_HEAD').write_bytes(b'\x00' * 64)


def _d_packed_refs_zero_bytes(box):
    (box / '.git' / 'packed-refs').write_bytes(b'\x00' * 120)


def _d_pack_truncated(box):
    _git(box, 'gc', '-q', check=False)
    for pack in _glob.glob(str(box / '.git' / 'objects' / 'pack' / '*.pack')):
        os.chmod(pack, 0o644)
        data = open(pack, 'rb').read()
        open(pack, 'wb').write(data[:len(data) // 2])


_DAMAGE = [_d_tag_bogus, _d_tag_empty, _d_tag_zero_bytes, _d_tag_packed, _d_remote_ref_bogus,
           _d_remote_ref_empty, _d_branch_empty, _d_branch_bogus, _d_stash_bogus, _d_object_empty,
           _d_object_missing, _d_head_empty, _d_index_empty, _d_index_zero_bytes, _d_config_empty,
           _d_config_half_written, _d_fetch_head_zero_bytes, _d_packed_refs_zero_bytes,
           _d_pack_truncated]
_damage_ids = [f.__name__[3:] for f in _DAMAGE]


@pytest.mark.parametrize('damage', _DAMAGE, ids=_damage_ids)
def test_update_lands_whatever_is_damaged(damage, box, upstream, monkeypatch):
    monkeypatch.setattr(gu, 'DEFAULT_REMOTE_URL', str(upstream))
    target = _publish(upstream)
    damage(box)
    result = gu.update(str(box))
    assert result['ok'], result
    assert _head(box) == target
    assert (box / 'app.py').read_text() == 'VERSION = 2\n'
    assert _private_data_intact(box)
    after = gu.check(str(box))
    assert after['ok'] and not after['updates_available'], after
    assert not (box / gu.BROKEN_GIT_BACKUP).exists()


@pytest.mark.parametrize('damage', _DAMAGE, ids=_damage_ids)
def test_background_check_never_changes_the_files_on_disk(damage, box, upstream, monkeypatch):
    """The check may repair git's own files. It must not move the code: that
    would be an update without the dependency install and restart."""
    monkeypatch.setattr(gu, 'DEFAULT_REMOTE_URL', str(upstream))
    _publish(upstream)
    damage(box)
    report = gu.check(str(box))
    assert (box / 'app.py').read_text() == 'VERSION = 1\n'
    assert _private_data_intact(box)
    assert (box / '.git').is_dir()
    # Either it healed (and sees the update) or it says the box needs the
    # repair that Update performs. Never the old dead-end codes.
    assert report['code'] in ('', 'repo_damaged'), report
    if report['ok']:
        assert report['updates_available']
    else:
        assert 'Repair and Update' in report['hint']


def test_rebuild_that_cannot_reach_upstream_puts_the_old_git_data_back(box, upstream, monkeypatch, tmp_path):
    marker = box / '.git' / 'ragnar-test-marker'
    marker.write_text('original')
    monkeypatch.setattr(gu, 'DEFAULT_REMOTE_URL', str(tmp_path / 'no-such-remote'))
    monkeypatch.setattr(gu, 'FALLBACK_BRANCHES', ('main',))
    ok, err = gu.rebuild_repository(str(box))
    assert not ok and err
    assert marker.read_text() == 'original'                 # the same .git is back
    assert not (box / gu.BROKEN_GIT_BACKUP).exists()
    assert (box / 'app.py').read_text() == 'VERSION = 1\n'
    assert _private_data_intact(box)


def test_rebuild_installs_dependencies_because_it_cannot_compare(box, upstream, monkeypatch):
    monkeypatch.setattr(gu, 'DEFAULT_REMOTE_URL', str(upstream))
    target = _publish(upstream)
    # Damage no in-place repair can fix: the object store is gone.
    _shutil.rmtree(box / '.git' / 'objects')
    result = gu.update(str(box))
    assert _head(box) == target and (box / 'app.py').read_text() == 'VERSION = 2\n'
    assert _private_data_intact(box)
    assert result['ok'] and result.get('rebuilt') is True
    assert result['requirements_changed'] is True and result['already_current'] is False
    assert any('rebuilt from upstream' in w for w in result['warnings'])


def test_an_offline_box_is_not_treated_as_damaged(box, upstream):
    """No network must never trigger repairs, least of all a rebuild."""
    marker = box / '.git' / 'ragnar-test-marker'
    marker.write_text('original')
    _git(box, 'remote', 'set-url', 'origin', 'https://ragnar-no-such-host.invalid/x.git')
    result = gu.update(str(box))
    assert not result['ok'] and result['code'] in ('offline', 'timeout')
    assert marker.read_text() == 'original' and not result.get('rebuilt')
    assert (box / 'app.py').read_text() == 'VERSION = 1\n'


def test_healthy_refs_survive_the_pruning(box):
    _git(box, 'tag', 'v-good')
    _git(box, 'branch', 'feature')
    _git(box, 'pack-refs', '--all')
    _git(box, 'tag', 'v-loose')
    _d_tag_empty(box)
    _d_stash_bogus(box)
    gu.tidy_git_files(str(box))
    removed = gu.prune_broken_refs(str(box))
    assert removed == 1                                     # the stash; the empty tag was tidied
    refs = _git(box, 'for-each-ref', '--format=%(refname)').split()
    for ref in ('refs/tags/v-good', 'refs/tags/v-loose', 'refs/heads/feature', 'refs/heads/main',
                'refs/remotes/origin/main'):
        assert ref in refs
    assert 'refs/stash' not in refs and 'refs/tags/os-v1' not in refs


def test_packed_refs_keeps_its_good_lines(box):
    _git(box, 'tag', 'v-good')
    _git(box, 'pack-refs', '--all')
    path = box / '.git' / 'packed-refs'
    good = path.read_bytes()
    path.write_bytes(good + b'\x00' * 40 + b'\nnot a ref line\n')
    assert gu.tidy_git_files(str(box)) == 2
    assert path.read_bytes() == good
    assert 'v-good' in _git(box, 'tag', '-l').split()


@pytest.mark.parametrize('text', [
    'fatal: bad object refs/heads/main',
    'error: object file .git/objects/3d/d4cd is empty',
    'fatal: .git/index: index file smaller than expected',
    'fatal: unterminated line in .git/packed-refs: ',
    'fatal: bad config line 1 in file .git/config',
    'error: packfile .git/objects/pack/pack-1.pack does not match index'])
def test_damage_is_named_as_damage_with_a_way_out(text):
    code, hint = gu.classify(text)
    assert code in ('repo_damaged', 'broken_tag')
    assert 'Repair and Update' in hint and 'no action is needed' not in hint


def _shell_helpers(script):
    """The fetch-recovery functions from a shell updater, ready to source."""
    text = open(os.path.join(os.path.dirname(gu.__file__), script)).read()
    start = text.index('resilient_fetch() {')
    end = text.index('\necho -e "${BLUE}Step 2:', start)
    return 'YELLOW=""; GREEN=""; NC=""; BLUE=""; RED=""\n' + text[start:end]


@pytest.mark.parametrize('script', ['update_ragnar.sh', 'scripts/update_ragnar.sh'])
@pytest.mark.parametrize('damage', [_d_tag_empty, _d_branch_bogus, _d_remote_ref_empty,
                                    _d_stash_bogus, _d_index_zero_bytes],
                         ids=lambda f: f.__name__[3:])
def test_shell_updater_repairs_the_same_damage(script, damage, box, upstream, tmp_path):
    target = _publish(upstream)
    _shutil.copy(gu.__file__, box / 'git_updater.py')
    for name in ('logger.py',):
        src = os.path.join(os.path.dirname(gu.__file__), name)
        if os.path.exists(src):
            _shutil.copy(src, box / name)
    damage(box)
    runner = tmp_path / 'run.sh'
    runner.write_text(_shell_helpers(script) + '\nresilient_fetch\n')
    proc = subprocess.run(['bash', str(runner)], cwd=box, capture_output=True, text=True,
                          env=dict(os.environ, GIT_CONFIG_COUNT='1',
                                   GIT_CONFIG_KEY_0='protocol.file.allow',
                                   GIT_CONFIG_VALUE_0='always'))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _git(box, 'rev-parse', 'origin/main') == target


def test_an_error_ragnar_does_not_recognise_never_triggers_a_rebuild(box, upstream, monkeypatch):
    """A rebuild resets tracked files. Only damage git names itself earns one."""
    (box / 'app.py').write_text('VERSION = 1  # my local edit\n')
    calls = []
    monkeypatch.setattr(gu, 'rebuild_repository', lambda *a, **k: calls.append(1) or (True, ''))
    real = gu.run_git

    def flaky(args, cwd, **kw):
        if args and args[0] == 'fetch':
            return gu.GitResult(args, 128, '', 'fatal: remote error: something new and strange')
        return real(args, cwd, **kw)

    monkeypatch.setattr(gu, 'run_git', flaky)
    result = gu.update(str(box))
    assert not result['ok'] and calls == []
    assert (box / 'app.py').read_text() == 'VERSION = 1  # my local edit\n'


@pytest.mark.parametrize('text', ['error: The requested URL returned error: 503',
                                  'fatal: the remote end hung up unexpectedly',
                                  'fatal: unable to connect to github.com'])
def test_server_trouble_is_offline_not_damage(text):
    assert gu.classify(text)[0] == 'offline'


# --- a real report, step for step ---------------------------------------------
# "One git object file was empty. The branch pointer origin/fix/cardputer-
#  keymap-i2c still pointed to the broken object, which blocked the fetch.
#  git update-ref -d couldn't [delete it] because the object was missing.
#  Some files in .git belonged to root."

def _reported_damage(box, upstream):
    """An empty object that only a remote-tracking branch still points at."""
    _git(upstream, 'checkout', '-q', '-b', 'fix/cardputer-keymap-i2c')
    sha = _publish(upstream, filename='keys.py', content='KEYS = 1\n', message='keymap')
    _git(upstream, 'checkout', '-q', 'main')
    _git(box, 'fetch', '-q', 'origin')
    _unpack_all(box)
    obj = box / '.git' / 'objects' / sha[:2] / sha[2:]
    assert obj.exists()
    os.chmod(obj, 0o644)
    obj.write_bytes(b'')
    return sha, obj


def test_the_reported_damage_really_blocks_a_plain_fetch(box, upstream):
    _reported_damage(box, upstream)
    _publish(upstream)
    raw = gu.run_git(['fetch', '--prune', 'origin'], str(box))
    assert not raw.ok                                       # the premise of the report
    assert gu.classify(raw.message)[0] in ('repo_damaged', 'broken_tag')
    # And the tool the user reached for first cannot remove the pointer.
    ref = 'refs/remotes/origin/fix/cardputer-keymap-i2c'
    assert (box / '.git' / ref).exists()


def test_the_reported_damage_clears_itself_on_the_next_check(box, upstream, monkeypatch):
    monkeypatch.setattr(gu, 'DEFAULT_REMOTE_URL', str(upstream))
    sha, obj = _reported_damage(box, upstream)
    _publish(upstream)
    report = gu.check(str(box))
    assert report['ok'] and report['code'] == '' and report['updates_available'], report
    # Steps 2-4 of the user's manual fix happened by themselves.
    assert obj.exists() and obj.stat().st_size > 0          # a good copy was downloaded
    assert _git(box, 'rev-parse', 'origin/fix/cardputer-keymap-i2c') == sha
    assert _git(box, 'cat-file', '-t', sha) == 'commit'
    assert (box / 'app.py').read_text() == 'VERSION = 1\n'  # the check did not update
    assert _private_data_intact(box)
    assert gu.update(str(box))['ok']


def test_wrong_owner_is_fixed_before_anything_else_is_tried(box, upstream, monkeypatch):
    """Step 1 of the user's fix. Not root here, so ownership is simulated: the
    first fetch fails the way it does on root-owned files, and the repair must
    call the ownership fix before its retry."""
    _publish(upstream)
    order = []
    real_run = gu.run_git
    state = {'failed': False}

    def run(args, cwd, **kw):
        if args and args[0] == 'fetch' and not state['failed']:
            state['failed'] = True
            order.append('fetch-denied')
            return gu.GitResult(args, 128, '', "error: cannot open .git/FETCH_HEAD: Permission denied")
        if args and args[0] == 'fetch':
            order.append('fetch')
        return real_run(args, cwd, **kw)

    monkeypatch.setattr(gu, 'run_git', run)
    monkeypatch.setattr(gu, 'restore_git_ownership',
                        lambda repo, warnings=None: order.append('chown') or 3)
    monkeypatch.setattr(gu, 'rebuild_repository', lambda *a, **k: pytest.fail('no rebuild for this'))
    res = gu.resilient_fetch(str(box), [], allow_rebuild=True)
    assert res.ok
    assert order[:3] == ['fetch-denied', 'chown', 'fetch']


def test_git_ownership_fix_changes_only_what_is_wrong(box, monkeypatch):
    calls = []
    me = os.getuid()
    monkeypatch.setattr(gu, 'repo_owner', lambda repo: (me, os.getgid(), 'box'))
    monkeypatch.setattr(gu.os, 'lchown', lambda path, uid, gid: calls.append(path))
    assert gu.restore_git_ownership(str(box)) == 0 and calls == []   # all correct already
    foreign = str(box / '.git' / 'HEAD')
    real_lstat = os.lstat

    class Stat:
        def __init__(self, st):
            self.st_uid, self.st_gid = 0, 0

    monkeypatch.setattr(gu.os, 'lstat', lambda p: Stat(real_lstat(p)) if p == foreign else real_lstat(p))
    warnings = []
    assert gu.restore_git_ownership(str(box), warnings) == 1
    assert calls == [foreign] and 'back to user box' in warnings[0]


def test_ownership_fix_without_root_does_not_fail(box, monkeypatch):
    monkeypatch.setattr(gu, 'repo_owner', lambda repo: (12345, 12345, 'someone'))

    def denied(path, uid, gid):
        raise PermissionError(1, 'Operation not permitted')

    monkeypatch.setattr(gu.os, 'lchown', denied)
    assert gu.restore_git_ownership(str(box)) == 0


def test_a_fetch_run_as_root_hands_its_files_back(box, upstream, monkeypatch):
    """The service is root, the checkout is not: without this every background
    check leaves root-owned objects that block git for the owner."""
    _publish(upstream)
    handed = []
    monkeypatch.setattr(gu.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(gu, 'restore_git_ownership', lambda repo, warnings=None: handed.append(warnings) or 0)
    assert gu.resilient_fetch(str(box), []).ok
    assert handed == [None]                       # ran once, quietly
    handed.clear()
    monkeypatch.setattr(gu.os, 'geteuid', lambda: 1000)
    assert gu.resilient_fetch(str(box), []).ok
    assert handed == []                           # nothing to do when not root


def test_network_git_never_leaves_a_background_gc_running():
    """A detached gc outlives the fetch and writes files as root after the
    ownership hand-back has already run."""
    assert 'gc.autoDetach=false' in gu.GIT_TRANSFER_GUARDS
