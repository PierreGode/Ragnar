#!/bin/bash
# Ragnar Pi5 power-button mode toggle installer.
#
# Repurposes the Raspberry Pi 5 on-board power button so a single short press
# flips between Ragnar (dashboard :8000) and the built-in Pwnagotchi mode
# (web UI :8080). See docs/POWER_BUTTON.md.
#
# What it installs:
#   * /usr/local/bin/ragnar-power-toggle            -> symlink to scripts/ragnar_power_toggle.py
#   * /etc/systemd/logind.conf.d/ragnar-power-toggle.conf   HandlePowerKey=ignore
#   * /etc/systemd/system/ragnar-power-toggle.service       the listener (both modes)
#
# Behaviour change: a short press no longer powers the Pi off (it toggles mode).
# A long-hold (~10s) still triggers the firmware hard power-off. Use
# `sudo poweroff` or the dashboard for a normal shutdown.
#
# Platform: Raspberry Pi 5 (on-board "pwr_button" input device). Idempotent:
# safe to re-run. Reverse with scripts/uninstall_power_button.sh.
#
# Usage:  sudo bash scripts/install_power_button.sh [--force]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LOG_DIR="/var/log/ragnar"
LOG_FILE="$LOG_DIR/power_button_install_$(date +%Y%m%d_%H%M%S).log"

TOGGLE_SRC="$REPO_ROOT/scripts/ragnar_power_toggle.py"
TOGGLE_BIN="/usr/local/bin/ragnar-power-toggle"
LOGIND_DROPIN_DIR="/etc/systemd/logind.conf.d"
LOGIND_DROPIN="$LOGIND_DROPIN_DIR/ragnar-power-toggle.conf"
SERVICE_FILE="/etc/systemd/system/ragnar-power-toggle.service"

FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Run as root: sudo bash scripts/install_power_button.sh"
    exit 1
fi

if [[ ! -f "$TOGGLE_SRC" ]]; then
    echo "[ERROR] $TOGGLE_SRC not found"
    exit 1
fi

# The feature needs the Pi 5 on-board power button (kernel "pwr_button").
if ! grep -q "pwr_button" /proc/bus/input/devices 2>/dev/null; then
    echo "[WARN] No 'pwr_button' input device found."
    echo "[WARN] This is a Raspberry Pi 5 feature; on other boards the button"
    echo "[WARN] may not emit KEY_POWER to userspace."
    if [[ $FORCE -ne 1 ]]; then
        echo "[WARN] Re-run with --force to install anyway."
        exit 1
    fi
fi

echo "[INFO] Installing Pi5 power-button mode toggle..."

# 1) Listener: symlink straight from the repo so a git pull updates it, matching
#    how the swap button is deployed.
chmod 755 "$TOGGLE_SRC"
ln -sf "$TOGGLE_SRC" "$TOGGLE_BIN"
echo "[INFO] Linked $TOGGLE_BIN -> $TOGGLE_SRC"

# 2) Tell systemd-logind to stop powering off on the power key.
mkdir -p "$LOGIND_DROPIN_DIR"
cat >"$LOGIND_DROPIN" <<'EOF'
# Ragnar: the Pi5 power button is a Ragnar<->Pwnagotchi mode toggle.
# ragnar-power-toggle.service handles the short press, so logind must not act
# on it. A long-hold (~10s) still triggers the firmware hard power-off.
[Login]
HandlePowerKey=ignore
EOF
chmod 644 "$LOGIND_DROPIN"
echo "[INFO] Wrote $LOGIND_DROPIN (HandlePowerKey=ignore)"

# Apply the logind change with a RELOAD, never a restart: restarting
# systemd-logind tears down PAM-login sessions, which kills the SPI-TFT kiosk
# (ragnar-tft.service logs in on vt7 via PAMName=login). Reload is enough for
# HandlePowerKey; a reboot also applies it cleanly.
if systemctl reload systemd-logind 2>/dev/null; then
    echo "[INFO] Reloaded systemd-logind"
else
    echo "[WARN] Could not reload systemd-logind; change applies on next reboot"
fi

# 3) The listener service (runs in BOTH modes).
cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=Ragnar Pi5 Power Button Mode Toggle (Ragnar<->Pwnagotchi)
After=multi-user.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $TOGGLE_SRC
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
chmod 644 "$SERVICE_FILE"
echo "[INFO] Wrote $SERVICE_FILE"

systemctl daemon-reload || true
systemctl enable ragnar-power-toggle >/dev/null 2>&1 || true
systemctl restart ragnar-power-toggle || true

echo "[INFO] Done. Short-press the power button to flip Ragnar <-> Pwnagotchi."
echo "[INFO] Watch it:   journalctl -u ragnar-power-toggle -f"
echo "[INFO] NOTE: the power button no longer shuts the Pi down on a short"
echo "[INFO]       press. Long-hold (~10s) = hard off; 'sudo poweroff' = clean."
