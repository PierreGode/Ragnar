# Files — File Manager & Editor

The **Files** tab is a full file manager for everything Ragnar stores on the
device, plus an in-browser text editor and the encrypted [Vault](vault.md). It
is a two-pane layout: a **Directories** list on the left and the **Files** list
on the right, with search, sort (name / date / size), Back and Up navigation.

## What you can browse

The top-level **Directories** are:

| Folder | Holds |
| --- | --- |
| **Uploads** | Your own uploaded files — the general-purpose workspace |
| **Backups** | Backup archives |
| **Data Stolen / Cracked Passwords / Vulnerabilities / Scan Results** | Captured loot and scan output, grouped per network |
| **Logs** | Ragnar's log files |
| **Camera** | Photos and videos taken with the camera, from the browser or the device's own screen ([camera](CardputerZero-Caps.md#camera)) |
| **Console Scripts / Rubber Ducky** | The script libraries ([console](ragnarscripts.md), [ducky](rubber-ducky.md)) |

The loot categories (Data Stolen, Scan Results, …) first list the **networks**
they hold data for; open a network to reach the actual files.

## Managing files

The Files tab works as a general file manager — every real folder is fully
writable:

- **New file** — creates a text file. Type the name *with the extension you
  want* (`notes.txt`, `hosts.csv`, `run.sh`, …) — that is how you pick the
  file's format — and it opens straight in the editor so you can type and
  **Save**.
- **New folder** — creates a subfolder in the folder you are in.
- **Upload here** — uploads one or more files straight into the current folder.
  (The header **Upload** button uploads into Uploads by default.)
- **Move** (folder icon on each row) — opens a picker; browse to any folder and
  tap **Move here**. Files and folders can be moved **across trees** — e.g. pull
  a scan result into Uploads, or reorganize Uploads however you like.
- **Rename** (pencil icon) — rename a file or folder. Changing the extension
  here changes the file's format (e.g. `capture.bin` → `capture.pcap`).
- **Download** / **Send to unit** / **Delete** — per-row actions. Send pushes a
  file to another unit over the [mesh](mesh.md).

Moves, renames and new files stay inside Ragnar's data tree — paths that try to
escape it, and the synthetic category roots that only list networks, are
rejected.

## In-browser editor

Open any text file (`.txt`, `.json`, `.py`, `.sh`, `.yaml`, `.conf`, `.csv`,
`.md`, …) to preview it. Editable types show an **Edit** button; edit in place
and **Save** writes back to disk — handy for tweaking console scripts, configs
and scan results without SSH. Images, PDFs and video preview inline; large files
offer a download instead.

## Uploading from a phone

Uploads work from mobile browsers, including **iPhone/iPad Safari** — tap
**Upload** (or **Upload here** inside a folder) and pick from Photos, iCloud
Drive or Files. The upload shows a live progress toast.

## Vault

The **Vault** is a password-protected, AES-256-GCM encrypted store that also
lives in this tab. See [Vault](vault.md).
