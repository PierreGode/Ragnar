# Updating Ragnar

Ragnar updates itself from GitHub. There are two ways to do it and they now
behave identically:

| | |
|---|---|
| **Web UI** | **Config → System → Update System** |
| **Terminal** | `sudo /home/ragnar/Ragnar/update_ragnar.sh` |

The web path is handled by [`git_updater.py`](../git_updater.py), a dedicated
update engine, plus [`scripts/post_update.sh`](../scripts/post_update.sh) which
finishes the job and restarts the service.

This updates **Ragnar's code**. The operating system underneath it (the kernel,
security fixes, and third-party packages such as **Tailscale**) comes from apt
and is updated separately: see
[Operating-system packages (apt)](#operating-system-packages-apt).

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
| `broken_tag` | A tag in this clone or on the remote is corrupt and was blocking the fetch | Nothing — the updater drops the broken tag and refetches branches only; see [A corrupt tag blocks every update](#a-corrupt-tag-blocks-every-update) |
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

### "Finishing update: … " — what each step is

That line is `scripts/post_update.sh` reporting where it is. In order:

| Step | What it does | Why it can be slow |
|---|---|---|
| `python dependencies` | `pip install -r requirements.txt` | Only runs when `requirements.txt` changed in the pull; a source build (`cryptography`, `sslyze`) takes minutes on a Pi |
| `data file templates` | `init_data_files.sh` | Fast |
| `network tools` | `scripts/provision_network_tools.sh` — rfkill, traceroute/mtr/lldpd/arp-scan, lldpd config | Fast when everything is already installed. When something is missing it refreshes the apt index first, which is the slowest thing in an update |
| `permissions` | exec bits and ownership | Fast |
| `restart` | `systemctl restart ragnar` | The web UI is briefly unreachable here — expected |

Each step is safe to re-run and skips work already done, so a normal update
passes through all of them in seconds. `network tools` is the one that can sit
there: a package that is simply not in your Debian suite (`speedtest-cli` is the
usual one) counts as "missing" forever, so it used to trigger a full
`apt-get update` on *every* update. The index refresh is now reused for six
hours, and a missing package is still retried against the index already on disk.

If the card sits on a step, `data/logs/post_update.log` says what is happening.
A run that never finishes — power cut, a hung apt — is ignored after 30 minutes
rather than pinning the card on a step from an update that ended days ago.

Transcripts live on the box:

```
data/logs/post_update.log     # full output of the post-update run
data/logs/post_update.json    # machine-readable state, step and outcome
```

---

## Operating-system packages (apt)

**Config → System → OS Packages** updates everything apt manages: the kernel and
firmware, Debian / Raspberry Pi OS / Kali security fixes, and the third-party
repositories the installer adds (Tailscale from `pkgs.tailscale.com`, Docker,
cloudflared, ...). Before this card existed none of that was reachable from the
web UI. `update_ragnar.sh` does not do it either: it installs Tailscale when the
mesh is enabled, but never upgrades a copy that is already there.

| Button | What it runs |
|---|---|
| **Check for Updates** | `apt-get update`, then lists what can be upgraded. Security fixes are tagged and listed first |
| **Upgrade All (N)** | `apt-get upgrade --with-new-pkgs`: every upgradable package, plus any new dependency they need (new kernels do) |
| **Update Tailscale only** | `apt-get install --only-upgrade tailscale`. Shown when a Tailscale update is waiting; the **Ragnar Mesh** tab shows the same button |

The list is read from apt's own state, so updates that `apt-get update` found
elsewhere (in an SSH session, or apt-daily) show up too. "Package lists
refreshed ... ago" says how current it is.

### Safe by design

- **Nothing is ever removed.** Ragnar uses `upgrade --with-new-pkgs`, never
  `full-upgrade`. An upgrade can add a dependency, but it can never uninstall a
  tool Ragnar relies on. A package that would need something removed stays
  *kept back* and is reported as such.
- **Download first, install second.** Everything is downloaded before dpkg
  touches the system, so a dropped connection mid-download changes nothing.
- **Disk-space check.** Between download and install, apt's own estimate of the
  space the install adds is compared with what is free (plus 300 MB headroom).
  If it doesn't fit, nothing is installed. A root filesystem filling up halfway
  through dpkg is the one way an upgrade really breaks a box.
- **Non-interactive.** No debconf questions, no conffile prompts: every changed
  config file keeps **your** version (`--force-confold`). `needrestart` only
  lists services; it never restarts them on its own.
- **Survives the restarts it causes.** The run executes in a transient systemd
  unit, `ragnar-os-update`, not inside the web service. An upgrade can restart
  `tailscaled` (a browser on the tailnet drops for a few seconds), NetworkManager
  or wpa_supplicant (Wi-Fi blips), or Ragnar's own dependencies. The run carries
  on regardless, and the card reconnects and picks up the progress by itself.
- **Interrupted runs are repaired.** Every upgrade starts with
  `dpkg --configure -a`, so a run cut short by a power loss is finished by the
  next one. A run whose process vanished, including across a reboot, shows as
  *interrupted* instead of leaving the card stuck on "Upgrading...".
- **Cleans up after itself.** `apt-get clean` drops the downloaded `.deb` files
  afterwards; on a 16 GB card a big upgrade can otherwise leave hundreds of MB
  behind.

### After an upgrade

The card says **Reboot recommended** when a newer kernel is installed than the
one running, when a package raised Debian's `/run/reboot-required` flag, or when
the kernel, firmware, libc, systemd, dbus or OpenSSL was upgraded. Rebooting is
up to you; the button is right there.

A large first upgrade on an old image (hundreds of packages) can take tens of
minutes on a Pi 4/5 and much longer on a Pi Zero 2 W. Leave the box powered.
You can close the page: the run continues, and reopening the card shows where it
is. **Last run output** on the card is the full apt log
(`data/logs/os_update.log`).

### When a check or upgrade fails

The card shows one sentence on what happened and one on what to do:

| Code | Meaning |
|---|---|
| `offline` | The package mirrors could not be reached. Nothing was installed |
| `repo_key` | A repository's signing key is missing or expired (the card names the repo). For Tailscale, `sudo bash scripts/setup_mesh.sh install` re-adds it |
| `locked` | Another apt run (SSH, apt-daily) held the lock for 10 minutes |
| `disk_full` | Not enough space for the download or the install. Nothing was installed |
| `dpkg_broken` / `dpkg_error` | dpkg stopped part-way. Run the upgrade again: it starts with `dpkg --configure -a` |
| `interrupted` | The run was stopped (power loss, reboot, unit stopped) before it finished |

In a Docker container the card says OS updates are not available there: the
packages come with the image, so pull or rebuild it instead. On a distribution
without apt the card explains that too.

### Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /api/system/os-updates` | Upgradable packages (cached against apt's state), current/last run, Tailscale versions, reboot state |
| `POST /api/system/os-updates/check` | Start `apt-get update` in the `ragnar-os-update` unit |
| `POST /api/system/os-updates/upgrade` | Upgrade everything, or `{"packages": ["tailscale"]}` for named packages. Names must be on the upgradable list |
| `GET /api/system/os-updates/log` | Tail of the run's apt output |

All four need a logged-in session. A second run while one is active returns
**409** `busy`. The engine is [`os_updates.py`](../os_updates.py); its tests,
[`tests/test_os_updates.py`](../tests/test_os_updates.py), drive the real
runner against fake `apt-get` / `dpkg` binaries through every failure above.

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

### A corrupt tag blocks every update

A release tag that was force-pushed, partially deleted or had its objects
garbage-collected (for example an `os-v*` OS-image tag) leaves a tag ref pointing
at an object git can no longer read. From then on a plain `git fetch` aborts with:

```
fatal: bad object refs/tags/os-v1.8.0
error: ... did not send all necessary objects
```

Because a pull and a branch checkout both fetch first, this blocks **every**
update *and* every branch switch — not just the tag. **Ragnar now recovers from
this automatically:** the web updater and `update_ragnar.sh` detect the signature,
delete the broken tag ref (the updater only ever syncs to a branch head, never a
tag) and refetch branches only. Note that `--no-tags` alone does **not** fix a
broken *local* tag — git still uses it during negotiation — so the broken ref is
deleted first.

If you ever need to clear it by hand:

```bash
cd /home/ragnar/Ragnar
# drop any local tag ref whose object is missing, then refetch branches only
for t in $(git for-each-ref --format='%(refname)' refs/tags); do
  git rev-parse --verify --quiet "$t^{object}" >/dev/null || git update-ref -d "$t"
done
git fetch --no-tags --prune --force origin '+refs/heads/*:refs/remotes/origin/*'
```

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
