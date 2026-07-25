# Updating Ragnar

Ragnar updates itself from GitHub. There are two ways to do it and they now
behave identically:

| | |
|---|---|
| **Web UI** | **Settings → System Updates → Update System** |
| **Terminal** | `sudo /home/ragnar/Ragnar/update_ragnar.sh` |

The web path is handled by [`git_updater.py`](../git_updater.py), a dedicated
update engine, plus [`scripts/post_update.sh`](../scripts/post_update.sh) which
finishes the job and restarts the service.

---

## What an update actually does

1. **Preflight.** Checks that git runs, that the checkout has repository
   metadata, that there is disk space, whitelists the directory for root
   (`safe.directory`), sweeps stale `*.lock` files, and aborts any merge or
   rebase a previous crashed run left half-finished.
2. **Fetch** from `origin`, retrying transient network errors.
3. **Land the new code.** A clean checkout is **fast-forwarded** — no merge
   commit, nothing that can conflict. Anything else (local edits, local
   commits, a diverged history, untracked files in the way) is **synced to
   `origin/<branch>`** after your local changes are stashed.
4. **Replay your local changes**, if there were any, and drop the stash once
   they apply cleanly. If they clash with the update, the box stays on the new
   version and your changes stay in the stash (see below).
5. **Post-update tasks** run in a transient systemd unit: Python dependencies
   (only when `requirements.txt` changed), data-file templates, network-tool
   provisioning, permissions — then the service restarts.
6. **The browser verifies the result**, waiting for the box to report the new
   commit rather than just answering HTTP again.

### Your data is never touched

Everything a box generates — the database, captures, logs, keys, configs — is
gitignored, and every recovery path uses `git clean -fd`, never `-x`. By
definition that cannot remove an ignored file. `data/` is not walked, chowned,
cleaned or reset by the updater.

### Your local code changes are never destroyed silently

If you have edited tracked files, they are stashed before the update and
replayed afterwards. If they conflict with the incoming version, the update
still lands (the box is left running a known-good tree) and the edits stay in
the stash:

```bash
cd /home/ragnar/Ragnar
git stash list         # your changes are the newest "Ragnar auto stash" entry
git stash pop          # reapply them by hand
```

An update never leaves conflict markers in a source file — that used to end
with a service that would not start.

Local *commits* are a different matter: a box that has diverged from upstream is
force-synced to the released version. The old commits are still reachable
through `git reflog` if you need them.

---

## What the update card tells you

Every failure now carries a **code** and one sentence of what to do about it,
in the card and in the console panel underneath it.

| Code | Meaning | What to do |
|---|---|---|
| `offline` | The box could not reach github.com | Check its internet connection and retry |
| `timeout` | A git command stopped responding and was cancelled | Usually a slow or dropped link; retry when back online |
| `auth` | `origin` asked for credentials | Point it at the public URL: `git remote set-url origin https://github.com/PierreGode/Ragnar.git` |
| `disk_full` | Not enough space to pull | Free space — `data/logs` and old captures first |
| `not_a_repo` | No `.git` (tarball install) **and** upstream unreachable | Check the box's internet connection; the check repairs this by itself once it can reach github.com |
| `branch_missing` | The tracked branch is gone upstream | Nothing — the updater falls back to the default branch automatically |
| `ownership` | Git refused the checkout's file ownership | Usually self-repairing; else `sudo chown -R ragnar:ragnar /home/ragnar/Ragnar` |
| `locked` | Another git process holds the repository | Wait a moment and retry; stale locks are swept automatically |
| `permission` | The service cannot write its own directory | `sudo chown -R ragnar:ragnar /home/ragnar/Ragnar` |
| `busy` | An update is already running | Wait for it — a second click is refused, not queued |
| `git_missing` | git does not run on this board | See [git is broken on this board](#git-is-broken-on-this-board) |

The **Check for Updates** card also reports when the box is *ahead* of upstream
(local commits), when the working tree is dirty, and when a branch no longer
exists upstream — all states that used to silently show "up to date".

---

## Watching an update finish

The service restarts as part of an update, so the browser cannot simply wait for
a response. It polls `GET /api/system/update-status`:

```json
{
  "commit": "ab099c4e…",
  "branch": "main",
  "update_in_progress": false,
  "post_update": { "state": "running", "step": "python dependencies" },
  "service_started": 1785016739.5
}
```

An update is only reported as successful once the box reports **the commit that
was pulled** and the post-update tasks have finished. Progress steps appear in
the console panel as they happen, including across the restart.

Transcripts live on the box:

```
data/logs/post_update.log     # full output of the post-update run
data/logs/post_update.json    # machine-readable state, step and outcome
```

---

## Troubleshooting

### The update button reports an error and nothing else

That should no longer happen — but if it does, the console panel under the
button carries the raw git message, the code and the hint. The same run can be
reproduced with more detail from a terminal:

```bash
sudo /home/ragnar/Ragnar/update_ragnar.sh
```

### git is broken on this board

```bash
git --version
```

If that prints **Illegal instruction**, git itself is broken, not Ragnar —
Debian Trixie arm64 has shipped a git built with ARMv8.1 atomics that crashes on
the Pi Zero 2 W's Cortex-A53:

```bash
sudo apt update && sudo apt install --reinstall git
```

Because the installer falls back to a release tarball when git is unusable, such
a box has no `.git` at all. Nothing needs reinstalling: the update check rebuilds
it in place on its own, keeping every file on disk, and `update_ragnar.sh` does
the same. A box in that state is not "behind" — it is running the release it was
installed from — so once the metadata is back the card simply reads **Up to
Date**. Only a box that cannot reach github.com at all reports `not_a_repo`, and
the repair is retried at most every 10 minutes until it succeeds.

### The service did not come back after an update

Post-update work (dependency installs especially) runs *before* the restart, so
give it a few minutes on a Pi Zero. Then:

```bash
sudo systemctl status ragnar
tail -50 /home/ragnar/Ragnar/data/logs/post_update.log
```

### Recovering a box by hand

The updater is designed so this is never necessary, but the equivalent of what
it does is:

```bash
cd /home/ragnar/Ragnar
sudo systemctl stop ragnar
sudo -u ragnar git stash push -u -m "manual backup"
sudo -u ragnar git fetch origin
sudo -u ragnar git reset --hard origin/main
sudo -u ragnar git clean -fd            # note: NOT -x, your data stays
sudo bash scripts/post_update.sh --deps
```

---

## For developers

* [`git_updater.py`](../git_updater.py) — the engine. Every git call is
  non-interactive (`GIT_TERMINAL_PROMPT=0`, ssh `BatchMode=yes`) and
  time-bounded, the repository path comes from `__file__` rather than the
  process working directory, and failures are classified into the codes above.
* [`scripts/post_update.sh`](../scripts/post_update.sh) — dependencies, data
  templates, provisioning, permissions, restart. Launched through `systemd-run`
  so it survives the restart it triggers (anything the service spawns otherwise
  dies with the service's cgroup).
* [`tests/test_git_updater.py`](../tests/test_git_updater.py) — drives real git
  repositories through every broken checkout state the engine is meant to
  survive. Run with `python3 -m pytest tests/test_git_updater.py`.

### Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /api/system/check-updates` | Commits behind/ahead, branch, working-tree state, failure code + hint |
| `POST /api/system/update` | Run an update (handles dirty checkouts too) |
| `POST /api/system/stash-update` | Kept for compatibility; identical to the above |
| `POST /api/system/resolve-conflicts` | Discard a half-finished merge, then update |
| `GET /api/system/update-status` | Current commit, post-update step, process start time |

A second concurrent update returns **409** with code `busy` instead of blocking.
