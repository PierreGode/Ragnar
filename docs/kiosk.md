# On-Screen Kiosk Mode

Ragnar can drive a locally attached screen as a fullscreen dashboard: enable
**kiosk mode**, connect a display to the Pi's HDMI, and the Ragnar web UI comes
up fullscreen in Chromium (`--kiosk`). It launches automatically on every boot.

## Hardware requirement — Ragnar Pi server only

The kiosk is a **Ragnar Pi server** feature. Chromium needs roughly **1 GB of
RAM resident on its own**, so on a 512 MB Pi Zero 2 W it swaps continuously: the
dashboard crawls and it drags the rest of Ragnar (scanning, wardriving, the web
UI) down with it. Rather than ship a feature that only half works there, the
kiosk is gated:

| Board | Kiosk |
|-------|-------|
| Pi Zero / Pi Zero 2 W (512 MB) | **Not available** — card hidden, API refuses |
| Any board < 2 GB RAM or < 2 cores | **Not available** |
| Pi 4 / Pi 5 (2 GB+), mini-PC, x86 server | Available |

The gate lives in `server_capabilities.py`
(`KIOSK_MIN_RAM_GB = 2.0`, `KIOSK_MIN_CORES = 2`) and is enforced in three places:

- **Web UI** — the *On-screen Display* card is hidden entirely on boards below
  the bar (`/api/kiosk/status` returns `capable: false` plus a
  `capability_reason`). The one exception: a box that already had a kiosk
  installed before the gate existed still shows the card, with the reason and
  the toggle left usable *to switch it off*.
- **API** — `POST /api/config` with `kiosk_enabled: true` returns `400`, and
  `POST /api/kiosk/repair` returns `403`, with the reason as the error text.
- **Installer** — `scripts/install_kiosk.sh` exits `3` and explains why.

If you want it anyway on an unsupported board, the installer can be forced:

```bash
sudo bash scripts/install_kiosk.sh --force
```

Expect the lag described above; the web UI will still not show the card, so
manage it with `systemctl {start,stop} ragnar-kiosk` from the shell.

Running headless on a Pi Zero 2 W? Nothing is lost — point a browser or phone at
`http://<pi>:8000`, or use the e-Paper/LCD display, which costs almost no RAM.

## Enabling

Turn on **On-screen Display** in the **Config** tab (visible only on supported
hardware — see above). Ragnar then:

1. Runs `scripts/install_kiosk.sh`, which auto-detects your setup and installs
   only what's missing.
2. Starts the kiosk immediately (no reboot needed) and arranges for it to launch
   on every boot.

Disable the toggle to stop and remove it.

## The two modes (auto-detected)

| Image | Mode | How it runs |
|-------|------|-------------|
| **Pi OS Desktop** (a desktop session is already running) | `autostart` | An XDG autostart entry launches Chromium inside your existing labwc/Wayland (or X) session. |
| **Pi OS Lite** / headless (no session) | `service` | A systemd unit (`ragnar-kiosk.service`) spawns its own Xorg on vt7 with openbox, then Chromium. |

The default URL is `http://localhost:8000`; rotation and cursor-hiding are read
live from the app config, so changing them only requires the kiosk to relaunch.

## Supported boards

Tested and tuned for **Pi 4 and Pi 5** (2 GB and up). Pi Zero class boards are
not supported — see the hardware requirement above. The wrapper adapts to the
board at launch:

- **Low-memory boards (≤ 1 GB, only reachable via `--force`):** applies Chromium
  low-end flags (`--enable-low-end-device-mode`, single renderer,
  `--disable-dev-shm-usage`) so it isn't OOM-killed to a black screen.
- **Pi 5 / Bookworm service mode:** the installer pulls in `xserver-xorg-legacy`
  so the non-root Xorg the kiosk starts actually launches (Bookworm is rootless-X
  by default).
- **All boards:** the "Restore pages? Chrome didn't shut down correctly" banner
  after a power-cut is suppressed by sanitizing the profile's exit state on each
  launch; `--password-store=basic` avoids a keyring hang.

The board model and RAM are logged at startup in `/var/log/ragnar/kiosk-wrapper.log`.

## Touchscreen & on-screen keyboard

The wrapper inspects the attached input devices at launch (via udev) and adapts:

- **Touchscreen detected** → Chromium touch events are forced
  (`--touch-events=enabled`) so tap-to-click and drag-scroll are reliable, **and**
  an on-screen keyboard is launched.
- **No physical keyboard** (e.g. an HDMI screen with only a mouse) → an on-screen
  keyboard is launched too, so you can still type into fields (login, the Web
  Terminal, WiFi passphrases) by clicking the keys with the mouse.
- **Mouse + keyboard, no touch** → nothing extra is added; the kiosk behaves as a
  normal fullscreen browser.

On-screen keyboard by session type:
- **Wayland** (Pi OS Desktop) → `squeekboard`, which follows text-input focus.
- **X** (Pi OS Lite) → `matchbox-keyboard` (falls back to `onboard`).

**Overrides** (set on the service/autostart entry):
- `RAGNAR_KIOSK_TOUCH=on|off|auto` — force/disable touch events (default `auto`).
- `RAGNAR_KIOSK_OSK=on|off|auto` — force/disable the on-screen keyboard
  (default `auto`). Useful if a wireless-mouse dongle advertises a phantom
  keyboard interface and the keyboardless auto-detection misfires.

The keyboard packages are installed best-effort at kiosk install/update time and
never block the install if unavailable.

## Handheld decks — escape hatch & scaling (Hackberry Pi CM5)

The kiosk runs Chromium in hard `--kiosk` (locked full-screen). On a normal HDMI
appliance with a full keyboard that is fine — Alt+F4 gets you out. But on a
handheld like the **Hackberry Pi CM5**, whose BlackBerry keyboard has no obvious
Ctrl/F-keys, `--kiosk` would trap you in the dashboard with no way back to the
desktop. Two knobs make the kiosk usable there:

**Escape hatch** — a floating touch **✕ button** (bottom-right by default) plus a
global **Ctrl+Alt+Q** hotkey, both of which close the kiosk: in autostart mode
they kill the kiosk browser (returning to the desktop); in service mode they stop
`ragnar-kiosk.service` (via a scoped, `visudo`-validated sudoers rule limited to
that one `systemctl stop`). The ✕ button is drawn by `python3-tk` and floats over
the full-screen browser; the hotkey uses `xbindkeys` (X sessions only — the
button is the reliable escape under Wayland/XWayland). Both deps are installed
best-effort at kiosk install/update time.

- `RAGNAR_KIOSK_EXIT=on|off|auto` — show the escape hatch (default `auto`: on
  when a touchscreen is present, off on a plain HDMI + keyboard appliance).
- `RAGNAR_KIOSK_EXIT_CORNER=ne|nw|se|sw` — which corner the ✕ sits in
  (default `se`, clear of Ragnar's top-right menu).

**Small-screen scaling** — the CM5's square 4" 720×720 panel packs the dashboard
tightly at native scale. Bump Chromium's device scale factor for bigger text and
touch targets:

- `RAGNAR_KIOSK_SCALE=1.0–1.5` — Chromium `--force-device-scale-factor` (unset =
  native, the unchanged default).

**From the UI:** the kiosk card in **Config → On-screen Display** has a
**Handheld deck (Hackberry CM5)** toggle and a **Display scale** field. Turning
the toggle on forces the escape hatch on and applies the scale (saved to
`/api/config`, picked up on the kiosk's next launch) — no env editing needed. The
environment variables above still override the saved values at launch, so set
them on the systemd unit (`Environment=…` in service mode) or export them in the
desktop session (autostart mode) when you want a per-box override. Existing kiosk
installs pick up the escape hatch on a plain `git pull` + update — no re-install
needed.

## Troubleshooting

**"Kiosk state did not settle"** in the web UI means the poll gave up: no
background job was running, nothing reported an error, and the state never
reached `active`/`installed`. Two things it is *not*:

- **A slow first install is no longer this.** Enabling the kiosk for the first
  time runs the installer, which apt-installs chromium — minutes on a slow SD
  card or link. The UI now shows `Installing the kiosk (fetching chromium)…` with an
  elapsed counter and waits, instead of timing out at ~25 s on a healthy job.
- **An installer failure is no longer this either.** It now reports the actual
  error (e.g. `Installer failed: E: Unable to locate package chromium`). Note
  that this failure never reaches `journalctl -u ragnar-kiosk` — the unit does
  not exist yet — so look in the **Ragnar log** for lines tagged `[kiosk]`.

If you still see it, the service exists but is stuck part-way (usually
`activating`). Check both logs below.

**"Nothing happened when I turned it on."** Use **Reinstall** in
**Config → On-screen Display**. It runs the installer and the enable step for
you — the same two commands people were resorting to by hand:

```bash
sudo bash scripts/install_kiosk.sh
sudo systemctl enable --now ragnar-kiosk.service   # service mode only
```

Why it was needed: the toggle only acts on a *change*, and it used to skip the
installer whenever anything already looked installed. An attempt that got as far
as writing the unit file, or left an autostart entry behind, therefore counted as
"installed" — so flipping the switch never re-ran the installer and never fixed
what was missing, while running the script by hand did. The installer is
idempotent, so it is now run on every enable, and **Reinstall** gives a box whose
config already says enabled a way back without toggling off and on.

**Start here — the Diagnose button.** In **Config → On-screen Display** it runs
`scripts/kiosk_doctor.sh` on the box and prints the whole report in the card, so
a blank screen can be diagnosed without an ssh session. Same thing from a
terminal:

```bash
sudo ./scripts/kiosk_doctor.sh
```

> `sudo journalctl -u ragnar-kiosk` returning **`-- No entries --`** is the most
> common dead end, and it is usually not a fault: that unit only exists in
> *service* mode. On a desktop image the kiosk runs as an autostart entry inside
> your session and there is no unit at all — and if the installer failed, there
> is no unit either. The web UI now says which of those applies instead of
> naming a journal that cannot exist. Use Diagnose, or
> `sudo journalctl -u ragnar | grep '\[kiosk\]'`.

It reports install mode, browser, the whole X stack (including the suid
`Xorg.wrap` that causes most Pi 5 crash loops), service state and restart
count, the kiosk unit's journal **filtered to that unit**, and the tail of the
wrapper and Xorg logs. Output is saved to `/tmp/kiosk_doctor_<timestamp>.log`
— paste that when reporting a problem.

> Reading the *whole* journal instead is the common wrong turn. `journalctl`
> without `-u ragnar-kiosk` returns unrelated boot chatter — cloud-init lines
> like `Completed socket interaction for boot stage final` are not the kiosk.
> And when the **installer** fails there is no unit at all, so
> `journalctl -u ragnar-kiosk` is legitimately empty; those failures are logged
> by Ragnar itself under `[kiosk]`.

**Service starts and immediately fails with `status=1/FAILURE`, and there is no
Xorg log at all.** This was Ragnar's own bug, fixed — the wrapper passed
`-logfile` to Xorg, and Xorg *refuses* that flag whenever it runs with elevated
privileges:

```
Invalid argument -logfile with elevated privileges
```

Elevated privileges is exactly how service mode runs it: the unit runs as a
non-root user, so X can only start through the setuid `Xorg.wrap` the installer
installs (`xserver-xorg-legacy` + `needs_root_rights=yes`). X therefore aborted
while still parsing its arguments — before opening any log — which is why the
journal showed a bare exit code with nothing to go on and the restart loop
tripped the start limit. The wrapper no longer passes the flag. X then writes wherever its default is —
`/var/log/Xorg.0.log` when it is really root (the setuid wrapper case, which is
service mode) or `~/.local/share/xorg/Xorg.0.log` when it is rootless — and the
wrapper copies whichever it finds to `/var/log/ragnar/kiosk-Xorg.log`, so that
stays the one place to look. Update and click **Reinstall**.

**Service `active (running)` but the screen is blank.** In service mode the unit
uses `PAMName=login`, so logind moves the real work into the login session's own
scope: `systemctl status` shows `Tasks: 0` and no browser, however healthy the
kiosk is. That is normal and not a symptom. The doctor checks for the Chromium
and X processes directly for exactly this reason — read those two lines, not the
task count. On an under-spec board — one the gate would refuse and that was
installed with `--force` — a missing browser is nearly always memory; confirm
with `sudo dmesg | grep -i 'killed process'`.

**"Cannot establish any listening sockets — Make sure an X server isn't already
running"** means service mode is trying to start its own X on `:0` while a
desktop session already owns it. The kiosk has two modes and this box was set
up in the wrong one: disable the kiosk, then re-enable it **from inside the
desktop session** so the installer picks autostart mode. The wrapper now
detects this and says so instead of crash-looping until the start limit trips.

**Logs (on the Pi):**
- Wrapper log: `/var/log/ragnar/kiosk-wrapper.log` — board, RAM, the
  `input: touchscreen=… keyboard=… osk=…` line, which OSK launched, target URL.
- Xorg log (service mode): `/var/log/ragnar/kiosk-Xorg.log`.
- Service state: `journalctl -u ragnar-kiosk` — **service mode only**; empty by
  design in autostart mode.
- Install/enable failures, either mode: `journalctl -u ragnar | grep '\[kiosk\]'`.

**Crash loop** (`status=1/FAILURE`, restart counter climbing) in service mode is
almost always X failing to start. The service now stops itself after 5 failures
in 2 minutes instead of spinning, and the wrapper dumps the last Xorg log lines
into the journal on failure. The most common cause on **Pi 5 / Bookworm** is a
missing suid `Xorg.wrap` — fix with:

```
sudo apt-get install xserver-xorg-legacy
```

(Fresh installs pull this in automatically.) After fixing the root cause, clear
the failure counter with `sudo systemctl reset-failed ragnar-kiosk` and start it
again.
