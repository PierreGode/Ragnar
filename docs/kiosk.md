# On-Screen Kiosk Mode

Ragnar can drive a locally attached screen as a fullscreen dashboard: enable
**kiosk mode**, connect a display to the Pi's HDMI, and the Ragnar web UI comes
up fullscreen in Chromium (`--kiosk`). It launches automatically on every boot.

## Enabling

Turn on **On-screen Display** in the **Config** tab. Ragnar then:

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

Tested and tuned for **Pi Zero 2 W, Pi 4, and Pi 5**. The wrapper adapts to the
board at launch:

- **Low-memory boards (≤ 1 GB, e.g. Pi Zero 2 W 512 MB):** applies Chromium
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

## Troubleshooting

**"Kiosk state did not settle"** in the web UI means the poll gave up: no
background job was running, nothing reported an error, and the state never
reached `active`/`installed`. Two things it is *not*:

- **A slow first install is no longer this.** Enabling the kiosk for the first
  time runs the installer, which apt-installs chromium — minutes on a Pi Zero
  2 W. The UI now shows `Installing the kiosk (fetching chromium)…` with an
  elapsed counter and waits, instead of timing out at ~25 s on a healthy job.
- **An installer failure is no longer this either.** It now reports the actual
  error (e.g. `Installer failed: E: Unable to locate package chromium`). Note
  that this failure never reaches `journalctl -u ragnar-kiosk` — the unit does
  not exist yet — so look in the **Ragnar log** for lines tagged `[kiosk]`.

If you still see it, the service exists but is stuck part-way (usually
`activating`). Check both logs below.

**Start here — `scripts/kiosk_doctor.sh`.** One command that collects every
answer in the right order, so you are not guessing which log to read:

```bash
sudo ./scripts/kiosk_doctor.sh
```

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
- Service state: `journalctl -u ragnar-kiosk`.

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
