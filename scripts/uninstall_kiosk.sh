#!/bin/bash
# Ragnar on-screen kiosk uninstaller.
# Removes the systemd unit (service mode) and/or the XDG autostart entry
# (autostart mode) for every regular user. Also drops the wrapper and tty1
# autologin drop-in. Apt packages are left in place unless --purge is given.

set -euo pipefail

SERVICE_FILE="/etc/systemd/system/ragnar-kiosk.service"
WRAPPER_DST="/usr/local/bin/ragnar-kiosk-run"
AUTOLOGIN_DROPIN="/etc/systemd/system/getty@tty1.service.d/autologin.conf"
AUTOSTART_REL=".config/autostart/ragnar-kiosk.desktop"
PURGE=0

for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
    esac
done

# Systemd unit (service mode)
if systemctl list-unit-files 2>/dev/null | grep -q '^ragnar-kiosk\.service'; then
    systemctl disable --now ragnar-kiosk.service 2>/dev/null || true
fi
rm -f "$SERVICE_FILE"
rm -f "$WRAPPER_DST"
rm -f "$AUTOLOGIN_DROPIN"
rm -f /etc/sudoers.d/ragnar-kiosk

if [[ -d "$(dirname "$AUTOLOGIN_DROPIN")" ]]; then
    rmdir --ignore-fail-on-non-empty "$(dirname "$AUTOLOGIN_DROPIN")" || true
fi

# Try to kill any running kiosk chromium (autostart mode users) + the escape-hatch
# button/hotkey we may have launched alongside it.
pkill -f 'ragnar-kiosk-chromium' 2>/dev/null || true
pkill -f 'ragnar_kiosk_exit_button\.py' 2>/dev/null || true
pkill -f 'ragnar-kiosk-xbk' 2>/dev/null || true

# Autostart entries — scan every regular user's home for the .desktop file.
getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $6}' | while read -r home; do
    if [[ -n "$home" && -f "$home/$AUTOSTART_REL" ]]; then
        rm -f "$home/$AUTOSTART_REL"
        echo "[kiosk-uninstall] removed autostart entry for $home"
    fi
done

systemctl daemon-reload || true

# Restore the physical console. The kiosk ran Xorg on tty7 and switched the
# active VT there; tearing it down leaves the display on that now-dead VT (a
# black screen) with no way back to the CLI. Worse, some Ragnar OS images ship
# getty@tty1 masked/disabled so ONLY the kiosk draws the screen — then even a
# reboot comes up black. So make sure a real login console exists on tty1 and
# switch the display back to it. All steps are no-ops on a box that was already
# fine (tty1 getty is enabled by default), so this is safe to always run.
systemctl unmask getty@tty1.service 2>/dev/null || true
systemctl enable getty@tty1.service 2>/dev/null || true
systemctl restart getty@tty1.service 2>/dev/null || true
command -v chvt >/dev/null 2>&1 && chvt 1 2>/dev/null || true
echo "[kiosk-uninstall] console restored on tty1"

if [[ "$PURGE" -eq 1 ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge \
        chromium-browser xserver-xorg xinit x11-xserver-utils openbox unclutter xauth || true
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y || true
fi

echo "[kiosk-uninstall] done"
