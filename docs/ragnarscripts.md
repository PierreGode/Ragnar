# RagnarScripts — external script library

[RagnarScripts](https://github.com/PierreGode/RagnarScripts) is a separate,
user-cloned repo that holds shareable scripts you can install into Ragnar
straight from the dashboard — without touching the Files tab or SSH. Two script
types are supported today:

| RagnarScripts folder | Script type | Installs into | Dashboard card |
|---|---|---|---|
| `rubber-ducky/` | USB HID payloads (`.ducky` / `.txt`) | `files/rubber-ducky/` | Pentest → **Rubber Ducky** |
| `console-scripts/` | Serial-console sequences (`.json`) | `data/console_scripts/` | Dashboard → **Device Console** |

The built-in demo scripts that ship inside Ragnar (`demo_hello.ducky`, the five
default console scripts, the bundled `resources/ducky_payloads/` library) are
unchanged and stay where they are. RagnarScripts is an **additional** source,
not a replacement — and installing never deletes your own scripts.

## Setup

**You normally don't have to do anything** — Ragnar clones the library for you
(see [Auto-sync](#auto-sync)). To place it yourself, clone it next to the Ragnar
repo:

```bash
cd ~            # or wherever your Ragnar checkout lives
git clone https://github.com/PierreGode/RagnarScripts
```

Ragnar discovers an existing checkout automatically, trying in order:

1. `$RAGNAR_SCRIPTS_DIR` (set this to override everything else)
2. a `RagnarScripts/` folder beside the Ragnar repo
3. `~/RagnarScripts`
4. `/home/pi/RagnarScripts` or `/home/ragnar/RagnarScripts`

The first path that exists wins. To keep the library elsewhere, export
`RAGNAR_SCRIPTS_DIR=/path/to/RagnarScripts` in Ragnar's environment.

## Auto-sync

Ragnar keeps the checkout current on its own, so scripts pushed to the GitHub
repo show up without you touching a shell. It runs a best-effort `git clone`
(when the repo is missing) or `git pull` (when it's present):

- **on web-server start** (i.e. after a restart);
- **when the Dashboard tab opens**;
- **when the Pentest tab opens**.

The clone is anonymous over HTTPS (the repo is public — no SSH key or token
needed). Sync is throttled (~30 s) so switching tabs quickly never spawns a git
process each time, runs in the background so it never blocks the UI, and is
silently skipped if the box is offline or `git` is missing — your already-listed
scripts keep working either way. A fresh clone lands at `$RAGNAR_SCRIPTS_DIR`
if set, otherwise beside the Ragnar repo. You can still pull manually, and the
↺ button on each install section re-lists on demand.

## Installing a script

- **Ducky payloads** — on the **Rubber Ducky** card (Pentest tab), RagnarScripts
  payloads appear directly in the **Payload Library** list, mixed in with the
  bundled ones and tagged **RagnarScripts** so you can tell them apart.
- **Console scripts** — on the **Device Console** card (Dashboard), expand
  **Install console scripts**.

Each row shows name, description and (for console scripts) vendor and command
count. Click **Install** — the file is copied into the local library
(`files/rubber-ducky/` or `data/console_scripts/`) and selected in the picker.
A script already installed shows **Reinstall** instead (which overwrites the
local copy with the repo's). Console scripts install to **this unit** (the one
serving the dashboard); enable **Allow write** on the Device Console to run them.

If nothing from RagnarScripts shows up, the clone isn't in any of the discovery
paths above — Ragnar normally [auto-clones](#auto-sync) it, but you can also
clone it by hand or set `RAGNAR_SCRIPTS_DIR`, then hit the ↺ refresh button.

## Contributing scripts

Add a file to the matching folder in your RagnarScripts checkout and push:

- **Ducky payloads** — official Ducky syntax or Ragnar's plain-text form; the
  first `REM`/`#` line becomes the description. See [rubber-ducky.md](rubber-ducky.md).
- **Console scripts** — JSON; the file name is the script id (letters, digits,
  `_`, `-`). See the schema in [serial-console.md](serial-console.md).

Authorized testing only.
