#!/bin/bash
# Ragnar SPI TFT kiosk installer — MPI3501 / ILI9486 3.5" display with ADS7846 touch.
# Idempotent: safe to re-run; only installs what's missing.
#
# Supported displays (ILI9486 + ADS7846, standard GPIO pinout):
#   - MPI3501 Display-F 3.5" 480x320 (tested)
#   - Waveshare 3.5" (A)
#   - goodtft / LCD-show 3.5" B
#
# Pin wiring (hardwired, not configurable):
#   RST=GPIO25 (active-low), DC=GPIO24, BL=GPIO18, SPI0 CS0, Touch IRQ=GPIO17
#
# Platform: Raspberry Pi 4/5 only (not CM5 — different GPIO block).
# This is an INSTALL-TIME option: config.txt changes require a reboot.
# Existing HDMI kiosk (ragnar-kiosk.service) is NOT touched.
#
# Usage:  sudo bash scripts/install_tft35_kiosk.sh [--force]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LOG_DIR="/var/log/ragnar"
LOG_FILE="$LOG_DIR/tft35_kiosk_install_$(date +%Y%m%d_%H%M%S).log"

DTBO_SRC="$REPO_ROOT/resources/overlays/tft35a.dtbo"
DTBO_DST="/boot/firmware/overlays/tft35a.dtbo"
CONFIG_TXT="/boot/firmware/config.txt"
XORG_CONF="/etc/X11/xorg.conf.d/99-tft-fbdev.conf"
XWRAP_CONF="/etc/X11/Xwrapper.config"
SERVICE_FILE="/etc/systemd/system/kiosk-tft.service"
RAGNAR_DROPIN_DIR="/etc/systemd/system/ragnar.service.d"
RAGNAR_DROPIN="$RAGNAR_DROPIN_DIR/tft.conf"
TOUCH_DEVICE="/dev/input/event5"

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

FORCE=0
for arg in "$@"; do
    case "$arg" in
        --force|-f) FORCE=1 ;;
        *) echo "[tft35-kiosk] unknown argument: $arg" >&2; exit 2 ;;
    esac
done

echo "[tft35-kiosk] starting at $(date -Iseconds)"
echo "[tft35-kiosk] repo root: $REPO_ROOT"

# ---------------------------------------------------------------------------
# Platform check — Pi 4/5 only
# ---------------------------------------------------------------------------
BOARD_MODEL="$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo unknown)"
echo "[tft35-kiosk] board: $BOARD_MODEL"

is_pi45() {
    case "${BOARD_MODEL,,}" in
        *"raspberry pi 4"*|*"raspberry pi 5"*) return 0 ;;
        *) return 1 ;;
    esac
}

if ! is_pi45; then
    if [ "$FORCE" -eq 1 ]; then
        echo "[tft35-kiosk] WARNING: board is not Pi 4/5 — SPI TFT GPIO pinout may differ. Continuing (--force)."
    else
        echo "[tft35-kiosk] REFUSING: this installer is for Raspberry Pi 4/5 only."
        echo "[tft35-kiosk] Detected: $BOARD_MODEL"
        echo "[tft35-kiosk] Re-run with --force to override."
        exit 3
    fi
fi

if [ ! -f "$CONFIG_TXT" ]; then
    echo "[tft35-kiosk] FATAL: $CONFIG_TXT not found — not a Pi OS firmware layout?" >&2
    exit 1
fi

if [ ! -f "$DTBO_SRC" ]; then
    echo "[tft35-kiosk] FATAL: $DTBO_SRC not found — run from the Ragnar repo root." >&2
    exit 1
fi

# Detect kiosk user
detect_kiosk_user() {
    for candidate in ragnar pi; do
        if id "$candidate" >/dev/null 2>&1; then
            echo "$candidate"; return 0
        fi
    done
    getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1; exit}'
}
KIOSK_USER="$(detect_kiosk_user)"
if [ -z "${KIOSK_USER:-}" ]; then
    echo "[tft35-kiosk] FATAL: no user found for kiosk session" >&2
    exit 1
fi
echo "[tft35-kiosk] kiosk user: $KIOSK_USER"

# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------
PKGS=()
for pkg in \
    chromium \
    xserver-xorg-core \
    xserver-xorg-video-fbdev \
    xserver-xorg-input-evdev \
    xinit \
    x11-xserver-utils \
    xinput \
    unclutter \
    libinput-tools; do
    dpkg -s "$pkg" >/dev/null 2>&1 || PKGS+=("$pkg")
done

if [ "${#PKGS[@]}" -gt 0 ]; then
    echo "[tft35-kiosk] installing packages: ${PKGS[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${PKGS[@]}"
else
    echo "[tft35-kiosk] all required packages already present"
fi

# Find chromium binary
BROWSER_BIN=""
for bin in chromium chromium-browser; do
    command -v "$bin" >/dev/null 2>&1 && { BROWSER_BIN="$bin"; break; }
done
if [ -z "$BROWSER_BIN" ]; then
    echo "[tft35-kiosk] FATAL: chromium not found after install" >&2
    exit 1
fi
echo "[tft35-kiosk] browser: $BROWSER_BIN"

# ---------------------------------------------------------------------------
# Device tree overlay (active-low RST — fixes white screen on ILI9486)
# ---------------------------------------------------------------------------
echo "[tft35-kiosk] installing tft35a.dtbo -> $DTBO_DST"
install -m 0644 "$DTBO_SRC" "$DTBO_DST"

# Add dtoverlay to config.txt (idempotent, under [all] section)
if grep -q "dtoverlay=tft35a" "$CONFIG_TXT"; then
    echo "[tft35-kiosk] tft35a overlay already in $CONFIG_TXT"
else
    echo "[tft35-kiosk] adding dtoverlay=tft35a:rotate=0 to $CONFIG_TXT"
    # Insert after [all] if present, otherwise append
    if grep -q "^\[all\]" "$CONFIG_TXT"; then
        sed -i '/^\[all\]/a # MPI3501 3.5" ILI9486 SPI TFT display (fbtft framebuffer driver)\ndtoverlay=tft35a:rotate=0' "$CONFIG_TXT"
    else
        printf '\n[all]\n# MPI3501 3.5" ILI9486 SPI TFT display (fbtft framebuffer driver)\ndtoverlay=tft35a:rotate=0\n' >> "$CONFIG_TXT"
    fi
fi

# ---------------------------------------------------------------------------
# Xwrapper (allow non-root X startup)
# ---------------------------------------------------------------------------
mkdir -p /etc/X11
if [ ! -f "$XWRAP_CONF" ]; then
    cat > "$XWRAP_CONF" <<'EOF'
allowed_users=anybody
needs_root_rights=yes
EOF
    echo "[tft35-kiosk] Xwrapper.config created"
else
    grep -q '^allowed_users=' "$XWRAP_CONF" \
        && sed -i 's/^allowed_users=.*/allowed_users=anybody/' "$XWRAP_CONF" \
        || echo 'allowed_users=anybody' >> "$XWRAP_CONF"
    grep -q '^needs_root_rights=' "$XWRAP_CONF" \
        && sed -i 's/^needs_root_rights=.*/needs_root_rights=yes/' "$XWRAP_CONF" \
        || echo 'needs_root_rights=yes' >> "$XWRAP_CONF"
    echo "[tft35-kiosk] Xwrapper.config updated"
fi

# ---------------------------------------------------------------------------
# X11 config — fbdev display + evdev touch (blocks libinput on ADS7846)
# ---------------------------------------------------------------------------
mkdir -p /etc/X11/xorg.conf.d
cat > "$XORG_CONF" <<'EOF'
Section "Device"
    Identifier "TFT fbdev"
    Driver     "fbdev"
    Option     "fbdev" "/dev/fb0"
EndSection

Section "Monitor"
    Identifier "TFT Monitor"
    Option     "DPMS" "false"
EndSection

Section "Screen"
    Identifier "TFT Screen"
    Device     "TFT fbdev"
    Monitor    "TFT Monitor"
    DefaultDepth 16
    SubSection "Display"
        Depth  16
        Modes  "320x480"
    EndSubSection
EndSection

Section "ServerLayout"
    Identifier "TFT Layout"
    Screen     "TFT Screen"
    InputDevice "ADS7846 Touchscreen" "CorePointer"
EndSection

# evdev handles ADS7846 with calibration tuned for MPI3501 portrait (rotate=0).
# Calibration: X inverted (300→3932), Y normal (500→3800).
# GrabDevice prevents libinput from also binding the same device (which would
# make xinput property changes have no effect).
Section "InputDevice"
    Identifier "ADS7846 Touchscreen"
    Driver     "evdev"
    Option     "Device"      "/dev/input/event5"
    Option     "Calibration" "300 3932 500 3800"
    Option     "SwapAxes"    "0"
    Option     "InvertX"     "0"
    Option     "InvertY"     "0"
    Option     "GrabDevice"  "true"
EndSection

# Block libinput from grabbing ADS7846 — without this, evdev calibration
# applies but libinput events override it, making calibration appear to have
# no effect.
Section "InputClass"
    Identifier  "ADS7846 block libinput"
    MatchProduct "ADS7846 Touchscreen"
    Option      "Ignore" "true"
EndSection
EOF
echo "[tft35-kiosk] X11 config written -> $XORG_CONF"

# ---------------------------------------------------------------------------
# Ragnar service drop-in — skip wipe_epd.py (hangs in D-state on SPI TFT)
# ---------------------------------------------------------------------------
mkdir -p "$RAGNAR_DROPIN_DIR"
cat > "$RAGNAR_DROPIN" <<'EOF'
[Service]
# Skip wipe_epd.py pre-start: it hangs in kernel D-state when fbtft owns SPI.
ExecStartPre=
ExecStartPre=-/bin/bash -c '/home/ragnar/Ragnar/kill_port_8000.sh; ip link set mon0 down 2>/dev/null; iw mon0 del 2>/dev/null; systemctl stop pwnagotchi 2>/dev/null; systemctl stop bettercap 2>/dev/null; true'
EOF
echo "[tft35-kiosk] ragnar service drop-in written -> $RAGNAR_DROPIN"

# ---------------------------------------------------------------------------
# kiosk-tft systemd service
# ---------------------------------------------------------------------------
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Ragnar TFT Kiosk — Chromium on 3.5" SPI display (MPI3501/ILI9486)
After=ragnar.service network.target
Requires=ragnar.service
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
User=$KIOSK_USER
# Wait for Ragnar web server to be ready (up to 60s)
ExecStartPre=/bin/bash -c 'for i in \$(seq 1 30); do curl -s http://localhost:8000 >/dev/null 2>&1 && break; sleep 2; done'
ExecStart=/bin/bash -c '\\
    sudo Xorg :1 -nolisten tcp vt7 & \\
    sleep 4 && \\
    DISPLAY=:1 xinput set-prop "ADS7846 Touchscreen" "Coordinate Transformation Matrix" 1 0 0.003 0 1 0.048 0 0 1 && \\
    DISPLAY=:1 unclutter -idle 0 -root & \\
    exec DISPLAY=:1 $BROWSER_BIN \\
        --no-sandbox \\
        --kiosk \\
        --noerrdialogs \\
        --disable-infobars \\
        --disable-session-crashed-bubble \\
        --disable-restore-session-state \\
        --disable-features=TranslateUI \\
        --disable-pinch \\
        --overscroll-history-navigation=0 \\
        --disable-gpu \\
        --force-device-scale-factor=0.5 \\
        --touch-events=enabled \\
        http://localhost:8000'
ExecStop=/bin/bash -c 'pkill -f "$BROWSER_BIN.*localhost:8000"; pkill -f "Xorg :1"'
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
echo "[tft35-kiosk] systemd service written -> $SERVICE_FILE"

# ---------------------------------------------------------------------------
# Enable service
# ---------------------------------------------------------------------------
systemctl daemon-reload
systemctl enable kiosk-tft.service
echo "[tft35-kiosk] kiosk-tft.service enabled"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "[tft35-kiosk] ============================================================"
echo "[tft35-kiosk] Installation complete."
echo "[tft35-kiosk]"
echo "[tft35-kiosk] A REBOOT IS REQUIRED to activate the SPI TFT display."
echo "[tft35-kiosk] The kiosk will start automatically after reboot."
echo "[tft35-kiosk]"
echo "[tft35-kiosk] To reboot now:  sudo reboot"
echo "[tft35-kiosk] To uninstall:   sudo bash scripts/uninstall_tft35_kiosk.sh"
echo "[tft35-kiosk] ============================================================"
