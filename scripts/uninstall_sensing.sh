#!/usr/bin/env bash
# uninstall_sensing.sh — Stop and remove Ragnar's bundled sensing backend.
# Leaves the vendored bin/sensing-server in the repo so it can be reinstalled.
set -euo pipefail

UNIT_NAME="ragnar-sensing.service"
UNIT_PATH="/etc/systemd/system/$UNIT_NAME"
INSTALL_BIN="/usr/local/bin/ragnar-sensing-server"

as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

echo "[uninstall_sensing] Stopping and disabling $UNIT_NAME"
as_root systemctl disable --now "$UNIT_NAME" 2>/dev/null || true
as_root rm -f "$UNIT_PATH"
as_root systemctl daemon-reload
as_root rm -f "$INSTALL_BIN"
echo "[uninstall_sensing] Removed. Vendored binary kept for reinstall."
