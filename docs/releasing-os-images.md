# Releasing the Ragnar OS images

The **Release OS images** workflow (`.github/workflows/release-os-images.yml`) is a
one-click, manually-triggered pipeline that cuts a fresh release of the Ragnar OS
images — the standard (defensive) edition, the Ulfberht (offensive) edition and
the M5Stack CardputerZero image — and follows each build through to a published,
downloadable release.

It lives in this **public** repo on purpose: anyone with write access here (for
example a collaborator such as `solarflere`) can start a release from the Actions
tab without needing direct access to the private build repo.

## How to run it

1. Open **Actions ▸ Release OS images ▸ Run workflow**.
2. Pick the options (all have sensible defaults):

   | Input | Default | Meaning |
   |---|---|---|
   | `which` | `both` | `both` = standard + Ulfberht, `all` = those two plus the CardputerZero image, or just one: `standard` / `ulfberht` / `cardputer`. |
   | `bump` | `minor` | How to bump each edition's version: `minor` (1.7.0 → 1.8.0), `patch` (→ 1.7.1) or `major` (→ 2.0.0). Ignored for an edition where you type an explicit version. |
   | `std_version` | *(blank)* | Explicit standard version, e.g. `1.8.0`. Blank = auto-bump from the latest `os-v*` release. |
   | `ulf_version` | *(blank)* | Explicit Ulfberht version, e.g. `1.5.0`. Blank = auto-bump from the latest `os-ulfberht-v*` release. |
   | `cpz_version` | *(blank)* | Explicit CardputerZero version, e.g. `1.1.0`. Blank = auto-bump from the latest `os-cardputer-v*` release (`1.0.0` when there is none yet). |
   | `dry_run` | `false` | Only print the versions it *would* release, create no tags. Handy to double-check the numbers **and to confirm the cross-repo token is healthy** before committing to a ~3-hour release. |

3. Click **Run workflow** and watch it. The run page (and its summary) shows the
   planned tags, links to each build on the private runner, and the final result.

> **Tip:** run it once with `dry_run` ticked first. The summary then shows the
> **Release plan** (the versions it would cut) on top, and below it a **Token
> validation** section for `RAGNAROS_DISPATCH_TOKEN` — token owner, that it can
> reach the build repo, that it holds **Contents: write** + **Actions: read**, and
> **when it expires** — so you catch a wrong version number or an expired /
> under-scoped token in seconds instead of part-way through a real release.

## What happens under the hood

```
Actions tab (this repo)
   │  workflow_dispatch
   ▼
Release OS images
   │  1. compute next versions → print the Release plan (or use your overrides)
   │  2. validate RAGNAROS_DISPATCH_TOKEN (present, unexpired, Contents:write + Actions:read)
   │  3. create tags  os-v<X.Y.Z> / os-ulfberht-v<X.Y.Z> / os-cardputer-v<X.Y.Z>  in PierreGode/RagnarOS
   ▼
RagnarOS build workflows (tag-triggered, self-hosted Pi runner)
   │  build image → upload to ragnar.life → publish GitHub Release here
   ▼
Release OS images (same run, still watching)
   │  4. wait for the builds, verify the release + ragnar.life manifest
   │  5. mark the standard release as "Latest"
   ▼
Done — images live at https://ragnar.life/ and on the Releases page
```

The image builds themselves are defined in the private `PierreGode/RagnarOS` repo
(`build-os-image.yml` / `build-ulfberht-image.yml` / `build-cardputer-image.yml`). They fire on a tag push, build
natively on the self-hosted `ragnar-os-builder` runner (the project's Raspberry Pi),
upload the `.img.xz` to ragnar.life, and publish the GitHub Release back onto this
repo. This pipeline just creates the tags and babysits the result.

## One-time setup — the cross-repo token

This repo has no access to the private RagnarOS repo by default, so the pipeline
needs a Personal Access Token stored as a repo secret named
**`RAGNAROS_DISPATCH_TOKEN`**:

- **Fine-grained PAT** (recommended) — resource owner `PierreGode`, repository
  `RagnarOS`, permissions **Contents: Read and write** + **Actions: Read**.
- or a **classic PAT** with the `repo` scope.

Add it under **Settings ▸ Secrets and variables ▸ Actions ▸ New repository secret**.
Until it exists, the pipeline stops with a clear error before it creates any tags.

The pipeline **validates this token on every run** (dry runs included), right after
it prints the Release plan and before it creates any tags, and fails fast with a
specific message if the token is missing, **expired**, cannot reach the build repo,
or is missing **Contents: write** or **Actions: read** — so a stale or under-scoped
PAT is caught up front rather than mid-release. A near-expiry token (≤ 7 days left)
passes with a warning so you have time to rotate it.

> The **Contents: write** check genuinely attempts a write — it creates a git
> *blob* in the build repo, which needs write access but leaves only a dangling
> object (no tag, commit, ref, event or notification, and git garbage-collects it).
> A repo's reported `permissions` reflect your *account* role, not what a
> fine-grained PAT was actually granted, so a real write is the only way to tell a
> read-only token from a read/write one.

## Prerequisites for a build to actually run

- The self-hosted **`ragnar-os-builder`** runner (the Pi) must be powered on with
  its Actions runner service running. If it is offline the builds queue and the
  pipeline eventually times out (it waits up to ~5¾ hours).
- The private repo's **`RAGNAR_RELEASE_TOKEN`** secret must be valid — that is what
  the build uses to publish the Release and upload to ragnar.life (already set up).

## Notes

- The images version **independently** (standard is currently ahead of Ulfberht,
  and the CardputerZero image starts at 1.0.0), so each is bumped from its own
  latest release.
- Builds share the single Pi runner, so they run **back-to-back**, not in parallel —
  expect roughly 2½–3 hours for `both`, and about an hour more for `all`.
- The standard edition is deliberately kept as the **Latest** release; the other
  editions publish later and would otherwise take the badge.
- Re-running with a version that already has a tag fails fast ("tag exists") — bump
  to a higher number.
