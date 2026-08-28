#!/bin/bash
# Ragnar SPI TFT kiosk uninstaller — reverses install_tft35_kiosk.sh.
# Safe to run on any Pi; no-ops if components aren't present.
# Does NOT remove installed packages (chromium, xorg, etc.) as they
# may be used by other features.

set -euo pipefail

echo "[tft35-kiosk-uninstall] starting at $(date -Iseconds)"

# Stop and disable service
if systemctl is-active --quiet kiosk-tft.service 2>/dev/null; then
    systemctl stop kiosk-tft.service
    echo "[tft35-kiosk-uninstall] stopped kiosk-tft.service"
fi
if systemctl is-enabled --quiet kiosk-tft.service 2>/dev/null; then
    systemctl disable kiosk-tft.service
    echo "[tft35-kiosk-uninstall] disabled kiosk-tft.service"
fi
rm -f /etc/systemd/system/kiosk-tft.service
systemctl daemon-reload

# Remove ragnar service drop-in (restore wipe_epd pre-start)
rm -f /etc/systemd/system/ragnar.service.d/tft.conf
rmdir --ignore-fail-on-non-empty /etc/systemd/system/ragnar.service.d 2>/dev/null || true
systemctl daemon-reload

# Remove X11 config
rm -f /etc/X11/xorg.conf.d/99-tft-fbdev.conf
echo "[tft35-kiosk-uninstall] removed X11 TFT config"

# Remove dtoverlay from config.txt
CONFIG_TXT="/boot/firmware/config.txt"
if [ -f "$CONFIG_TXT" ] && grep -q "dtoverlay=tft35a" "$CONFIG_TXT"; then
    sed -i '/# MPI3501 3.5" ILI9486 SPI TFT display/d' "$CONFIG_TXT"
    sed -i '/dtoverlay=tft35a/d' "$CONFIG_TXT"
    echo "[tft35-kiosk-uninstall] removed tft35a overlay from $CONFIG_TXT"
fi

# Remove dtbo
rm -f /boot/firmware/overlays/tft35a.dtbo
echo "[tft35-kiosk-uninstall] removed tft35a.dtbo"

echo ""
echo "[tft35-kiosk-uninstall] Done. Reboot to restore normal display output."
echo "[tft35-kiosk-uninstall] To reboot now: sudo reboot"
