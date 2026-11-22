#!/bin/bash
# Reverse scripts/install_power_button.sh: restore the Pi5 power button to its
# default behaviour (short press = systemd-logind power off).
#
# Usage:  sudo bash scripts/uninstall_power_button.sh

set -euo pipefail

TOGGLE_BIN="/usr/local/bin/ragnar-power-toggle"
LOGIND_DROPIN="/etc/systemd/logind.conf.d/ragnar-power-toggle.conf"
SERVICE_FILE="/etc/systemd/system/ragnar-power-toggle.service"

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Run as root: sudo bash scripts/uninstall_power_button.sh"
    exit 1
fi

echo "[INFO] Removing Pi5 power-button mode toggle..."

systemctl disable --now ragnar-power-toggle >/dev/null 2>&1 || true
rm -f "$SERVICE_FILE"
systemctl daemon-reload || true
systemctl reset-failed ragnar-power-toggle >/dev/null 2>&1 || true

rm -f "$LOGIND_DROPIN"
# Reload (not restart) so we don't drop the TFT kiosk's PAM-login session.
systemctl reload systemd-logind 2>/dev/null || \
    echo "[WARN] Could not reload systemd-logind; default applies on next reboot"

rm -f "$TOGGLE_BIN"

echo "[INFO] Done. The power button follows systemd-logind again"
echo "[INFO] (HandlePowerKey default = poweroff). A reboot fully restores it."
