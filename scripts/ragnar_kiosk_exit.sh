#!/bin/bash
# ragnar_kiosk_exit.sh — the kiosk escape hatch. Closes the Ragnar kiosk from the
# floating ✕ touch button or the Ctrl+Alt+Q hotkey, both wired up by
# ragnar_kiosk_run.sh. Needed on handhelds like the Hackberry Pi CM5 whose
# BlackBerry keyboard has no easy Ctrl/F11, so Chromium's --kiosk would otherwise
# trap you in the dashboard with no way out.
#
# - Service mode (Pi OS Lite, own-X): stop the unit so it doesn't just respawn.
# - Autostart mode (desktop session, the handheld case): kill the kiosk Chromium
#   bound to its dedicated profile only — never a normal browser — returning to
#   the desktop.
#
# POSIX sh–safe (no pipefail): the on-screen ✕ button invokes it via /bin/sh
# (dash on Debian), which rejects `set -o pipefail`.
set -u

# Same fixed profile dir ragnar_kiosk_run.sh launches Chromium with.
PROFILE="${RAGNAR_KIOSK_PROFILE:-$HOME/.config/ragnar-kiosk-chromium}"

# Service mode: stop the systemd unit (needs the scoped passwordless sudoers rule
# the kiosk installer adds); harmless/no-op in autostart mode where no unit runs.
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ragnar-kiosk.service 2>/dev/null; then
    sudo -n systemctl stop ragnar-kiosk.service 2>/dev/null \
        || systemctl --user stop ragnar-kiosk.service 2>/dev/null || true
fi

# Autostart mode (or a fallback if the service stop was refused): kill the kiosk
# browser bound to our profile only, plus the on-screen keyboard we launched.
pkill -f -- "--user-data-dir=${PROFILE}" 2>/dev/null || true
pkill -f 'matchbox-keyboard' 2>/dev/null || true

# Tear down the floating exit button itself (it also self-exits via its watchdog).
pkill -f 'ragnar_kiosk_exit_button\.py' 2>/dev/null || true

# Restore screen blanking/DPMS if we're on an X session.
if [ -n "${DISPLAY:-}" ] && command -v xset >/dev/null 2>&1; then
    xset s on +dpms >/dev/null 2>&1 || true
fi
exit 0
