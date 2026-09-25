#!/bin/bash
# Ragnar on-screen kiosk installer.
# Idempotent: safe to re-run; only installs what's missing.
#
# Auto-detects the environment:
#   - Pi OS Desktop / any image with a display manager + Wayland/X session
#     already running: installs an XDG autostart .desktop entry into the
#     session user's ~/.config/autostart/. Chromium kiosk launches inside
#     the existing labwc/Xwayland session — no separate X server.
#   - Pi OS Lite / headless: installs a systemd unit that spawns its own
#     Xorg on vt7 and runs chromium in --kiosk.
#
# Hardware requirement: this is a Ragnar Pi server feature. Chromium needs
# roughly 1GB resident on its own, so a 512MB Pi Zero 2 W swaps itself into the
# ground and drags Ragnar's scanning down with it. The installer refuses to run
# below 2GB RAM / 2 cores. Pass --force to override (you are on your own).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LOG_DIR="/var/log/ragnar"
LOG_FILE="$LOG_DIR/kiosk_install_$(date +%Y%m%d_%H%M%S).log"
SERVICE_FILE="/etc/systemd/system/ragnar-kiosk.service"
WRAPPER_DST="/usr/local/bin/ragnar-kiosk-run"
WRAPPER_SRC="$REPO_ROOT/scripts/ragnar_kiosk_run.sh"
AUTOSTART_REL=".config/autostart/ragnar-kiosk.desktop"
AUTOLOGIN_DROPIN_DIR="/etc/systemd/system/getty@tty1.service.d"
AUTOLOGIN_DROPIN="$AUTOLOGIN_DROPIN_DIR/autologin.conf"

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

FORCE=0
for arg in "$@"; do
    case "$arg" in
        --force|-f) FORCE=1 ;;
        *) echo "[kiosk-install] unknown argument: $arg" >&2; exit 2 ;;
    esac
done

BOARD_MODEL="$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo unknown)"
BOARD_RAM_MB="$(awk '/^MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)"
BOARD_CORES="$(nproc 2>/dev/null || echo 1)"

echo "[kiosk-install] starting at $(date -Iseconds)"
echo "[kiosk-install] repo root: $REPO_ROOT"
echo "[kiosk-install] board: ${BOARD_MODEL} | RAM: ${BOARD_RAM_MB}MB | cores: ${BOARD_CORES}"

# Hardware gate — mirrors server_capabilities.KIOSK_MIN_RAM_GB / KIOSK_MIN_CORES.
# Keep the two in step: the web UI hides the kiosk card using the Python side,
# this catches anyone running the script by hand.
# 1800MB, not 2048: a real 2GB Pi 4 reports ~1900MB after firmware reservations.
KIOSK_MIN_RAM_MB=1800
KIOSK_MIN_CORES=2
kiosk_hardware_verdict() {
    case "${BOARD_MODEL,,}" in
        *zero*) echo "This is a Pi Zero class board (${BOARD_RAM_MB}MB RAM); Chromium alone needs about 1GB."; return ;;
    esac
    if [ "$BOARD_RAM_MB" -lt "$KIOSK_MIN_RAM_MB" ]; then
        echo "This board has ${BOARD_RAM_MB}MB RAM; the kiosk needs a 2GB board or better."
        return
    fi
    if [ "$BOARD_CORES" -lt "$KIOSK_MIN_CORES" ]; then
        echo "This board has ${BOARD_CORES} CPU core(s); the kiosk needs at least ${KIOSK_MIN_CORES}."
        return
    fi
    echo ""
}
KIOSK_BLOCK_REASON="$(kiosk_hardware_verdict)"
if [ -n "$KIOSK_BLOCK_REASON" ]; then
    if [ "$FORCE" -eq 1 ]; then
        echo "[kiosk-install] WARNING: $KIOSK_BLOCK_REASON"
        echo "[kiosk-install] --force given; installing anyway. Expect the box to lag badly."
    else
        echo "[kiosk-install] REFUSING: the on-screen kiosk is a Ragnar Pi server feature."
        echo "[kiosk-install] $KIOSK_BLOCK_REASON"
        echo "[kiosk-install] Run a Ragnar Pi server (2GB+ RAM, 2+ cores) for the on-screen display,"
        echo "[kiosk-install] or re-run with --force to install anyway."
        exit 3
    fi
fi

# Detect if a desktop session is already running on this Pi.
detect_desktop_mode() {
    if systemctl is-active --quiet lightdm 2>/dev/null \
       || systemctl is-active --quiet gdm 2>/dev/null \
       || systemctl is-active --quiet sddm 2>/dev/null \
       || systemctl is-active --quiet display-manager 2>/dev/null; then
        return 0
    fi
    if pgrep -x labwc >/dev/null 2>&1 \
       || pgrep -x Xwayland >/dev/null 2>&1 \
       || pgrep -x Xorg >/dev/null 2>&1 \
       || pgrep -x wayfire >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Find the user who actually owns the active graphical session.
#
# Deliberately asks each session what it is instead of parsing the columns of
# `loginctl list-sessions`, whose layout has changed between systemd versions.
# The old parse had two problems: its first pass compared the *user* column
# against "seat0" so it never matched anything, and when no seated session
# existed at all it fell back to whoever `who` listed first - an ssh login on a
# pty. The autostart entry then landed in that user's home directory, so it
# never ran for the person actually sitting at the screen. Returning nothing is
# the right answer there: the caller falls back to detect_kiosk_user_bare.
_session_prop() {   # _session_prop <session-id> <property>
    local out
    out="$(loginctl show-session "$1" -p "$2" --value 2>/dev/null)" && [[ -n "$out" ]] && {
        echo "$out"; return 0
    }
    # --value predates systemd 238; fall back to Property=value output.
    loginctl show-session "$1" -p "$2" 2>/dev/null | cut -d= -f2-
}

detect_session_user() {
    if command -v loginctl >/dev/null 2>&1; then
        local sid user stype pass
        # Pass 1: a genuinely graphical session. Pass 2: any seated session.
        for pass in graphical seated; do
            while read -r sid; do
                [[ -z "$sid" ]] && continue
                user="$(_session_prop "$sid" Name)"
                stype="$(_session_prop "$sid" Type)"
                case "$user" in
                    lightdm|gdm|gdm3|sddm|greeter|'') continue ;;
                esac
                if [[ "$pass" == "graphical" ]]; then
                    case "$stype" in
                        wayland|x11|mir) ;;
                        *) continue ;;
                    esac
                else
                    [[ "$(_session_prop "$sid" Seat)" == "" ]] && continue
                fi
                echo "$user"
                return 0
            done < <(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}')
        done
    fi
    # Fallback: whoever is logged in on a real (non-pty) tty.
    if command -v who >/dev/null 2>&1; then
        who 2>/dev/null | awk '$2 !~ /^pts/ {print $1; exit}'
    fi
}

# Bare-mode user fallback (Pi OS Lite — no session yet, we make one).
detect_kiosk_user_bare() {
    for candidate in ragnar pi; do
        if id "$candidate" >/dev/null 2>&1; then
            echo "$candidate"
            return 0
        fi
    done
    getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1; exit}'
}

# Browser detection (both modes need this)
HAS_BROWSER=0
BROWSER_BIN=""
for bin in chromium-browser chromium firefox-esr; do
    if command -v "$bin" >/dev/null 2>&1; then
        HAS_BROWSER=1
        BROWSER_BIN="$bin"
        break
    fi
done

if detect_desktop_mode; then
    MODE="autostart"
    KIOSK_USER="$(detect_session_user)"
    if [[ -z "${KIOSK_USER:-}" ]]; then
        KIOSK_USER="$(detect_kiosk_user_bare)"
    fi
    echo "[kiosk-install] mode: autostart (existing desktop session)"
    echo "[kiosk-install] session user: $KIOSK_USER"
else
    MODE="service"
    KIOSK_USER="$(detect_kiosk_user_bare)"
    echo "[kiosk-install] mode: service (headless / Pi OS Lite)"
    echo "[kiosk-install] kiosk user: $KIOSK_USER"
fi

if [[ -z "${KIOSK_USER:-}" ]]; then
    echo "[kiosk-install] FATAL: no user found for kiosk session" >&2
    exit 1
fi

# Package installation depends on mode.
PKGS_TO_INSTALL=()
if [[ "$HAS_BROWSER" -eq 0 ]]; then
    echo "[kiosk-install] no browser detected — adding chromium-browser"
    PKGS_TO_INSTALL+=(chromium-browser)
fi
# unclutter: hides X cursor. Only useful in service mode where we own X.
if [[ "$MODE" == "service" ]] && ! command -v unclutter >/dev/null 2>&1; then
    PKGS_TO_INSTALL+=(unclutter)
fi
if [[ "$MODE" == "service" ]]; then
    HAS_X=0
    if command -v Xorg >/dev/null 2>&1 || command -v xinit >/dev/null 2>&1; then
        HAS_X=1
    fi
    if [[ "$HAS_X" -eq 0 ]]; then
        echo "[kiosk-install] no X detected — adding minimal X stack"
        PKGS_TO_INSTALL+=(xserver-xorg xinit x11-xserver-utils openbox)
    fi
    # xserver-xorg-legacy provides the suid Xorg.wrap that lets a non-root user
    # start X (our needs_root_rights=yes + allowed_users=anybody below). On Pi OS
    # Bookworm — the default on Pi 5 — X is rootless by default and this package
    # isn't pulled in, so the kiosk service fails to start X without it.
    if [[ ! -f /usr/lib/xorg/Xorg.wrap ]] && ! dpkg -s xserver-xorg-legacy >/dev/null 2>&1; then
        PKGS_TO_INSTALL+=(xserver-xorg-legacy)
    fi
    if ! command -v xauth >/dev/null 2>&1; then
        PKGS_TO_INSTALL+=(xauth)
    fi
fi
# Autostart mode: wlr-randr rotates the Wayland output (labwc/wlroots).
if [[ "$MODE" == "autostart" ]] && ! command -v wlr-randr >/dev/null 2>&1; then
    PKGS_TO_INSTALL+=(wlr-randr)
fi

if [[ "${#PKGS_TO_INSTALL[@]}" -gt 0 ]]; then
    echo "[kiosk-install] apt installing: ${PKGS_TO_INSTALL[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${PKGS_TO_INSTALL[@]}"
else
    echo "[kiosk-install] all required packages already present"
fi

# On-screen keyboard so a touchscreen kiosk can type (login, terminal, WiFi
# passphrases). Installed best-effort — a missing package must never block the
# kiosk. The wrapper only launches it when it actually detects a touchscreen.
#   - autostart/Wayland (Pi OS Bookworm desktop) -> squeekboard (focus-following)
#   - service/X (Pi OS Lite)                      -> matchbox-keyboard (lightweight)
OSK_PKG=""
if [[ "$MODE" == "autostart" ]]; then
    command -v squeekboard >/dev/null 2>&1 || OSK_PKG="squeekboard"
else
    command -v matchbox-keyboard >/dev/null 2>&1 || OSK_PKG="matchbox-keyboard"
fi
if [[ -n "$OSK_PKG" ]]; then
    echo "[kiosk-install] installing on-screen keyboard: $OSK_PKG (best-effort, for touchscreens)"
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$OSK_PKG" \
        || echo "[kiosk-install] WARN: could not install $OSK_PKG — touch keyboard unavailable"
fi

# Kiosk escape hatch (floating ✕ touch button + Ctrl+Alt+Q hotkey). Needed on
# handhelds like the Hackberry Pi CM5 whose keyboard has no easy Ctrl/F-keys, so
# Chromium's --kiosk would otherwise trap you in the dashboard. python3-tk draws
# the touch button; xbindkeys binds the hotkey on X. Best-effort — a miss just
# leaves that affordance off (the wrapper auto-enables it only for touchscreens).
HATCH_PKGS=()
python3 -c 'import tkinter' >/dev/null 2>&1 || HATCH_PKGS+=(python3-tk)
command -v xbindkeys >/dev/null 2>&1 || HATCH_PKGS+=(xbindkeys)
if [[ "${#HATCH_PKGS[@]}" -gt 0 ]]; then
    echo "[kiosk-install] installing kiosk escape-hatch deps: ${HATCH_PKGS[*]} (best-effort)"
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${HATCH_PKGS[@]}" \
        || echo "[kiosk-install] WARN: could not install ${HATCH_PKGS[*]} — the ✕/Ctrl+Alt+Q exit may be limited"
fi

# Re-detect browser after install
if [[ -z "$BROWSER_BIN" ]]; then
    for bin in chromium-browser chromium firefox-esr; do
        if command -v "$bin" >/dev/null 2>&1; then
            BROWSER_BIN="$bin"
            break
        fi
    done
fi
if [[ -z "$BROWSER_BIN" ]]; then
    echo "[kiosk-install] FATAL: no browser available after install" >&2
    exit 1
fi
echo "[kiosk-install] browser: $BROWSER_BIN"

# Install wrapper script (used by both modes)
install -m 0755 "$WRAPPER_SRC" "$WRAPPER_DST"
echo "[kiosk-install] wrapper installed -> $WRAPPER_DST"

# Ensure /var/log/ragnar is writable by the kiosk user
install -d -m 0775 /var/log/ragnar
if id -u "$KIOSK_USER" >/dev/null 2>&1; then
    chgrp "$KIOSK_USER" /var/log/ragnar 2>/dev/null || true
    chmod g+w /var/log/ragnar 2>/dev/null || true
fi

KIOSK_HOME="$(getent passwd "$KIOSK_USER" | cut -d: -f6)"
if [[ -z "$KIOSK_HOME" ]]; then
    echo "[kiosk-install] FATAL: could not resolve home dir for $KIOSK_USER" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# MODE: autostart  (coexist with existing desktop session)
# ---------------------------------------------------------------------------
if [[ "$MODE" == "autostart" ]]; then
    # Remove any old systemd-service-based install — they are mutually
    # exclusive on a given image.
    if [[ -f "$SERVICE_FILE" ]]; then
        echo "[kiosk-install] removing legacy systemd unit (mode is now autostart)"
        systemctl disable --now ragnar-kiosk.service 2>/dev/null || true
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload || true
    fi
    if [[ -f "$AUTOLOGIN_DROPIN" ]]; then
        # If we wrote a tty1 autologin override before, drop it — the
        # desktop's display manager handles login now.
        rm -f "$AUTOLOGIN_DROPIN"
        rmdir --ignore-fail-on-non-empty "$AUTOLOGIN_DROPIN_DIR" 2>/dev/null || true
        systemctl daemon-reload || true
        echo "[kiosk-install] removed legacy tty1 autologin override"
    fi

    AUTOSTART_DIR="$KIOSK_HOME/.config/autostart"
    AUTOSTART_FILE="$KIOSK_HOME/$AUTOSTART_REL"
    install -d -o "$KIOSK_USER" -g "$KIOSK_USER" -m 0755 \
        "$KIOSK_HOME/.config" "$AUTOSTART_DIR"
    cat > "$AUTOSTART_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=Ragnar Kiosk
Comment=Ragnar on-screen UI
Exec=env RAGNAR_REPO=$REPO_ROOT $WRAPPER_DST
X-GNOME-Autostart-enabled=true
NoDisplay=true
Terminal=false
EOF
    chown "$KIOSK_USER:$KIOSK_USER" "$AUTOSTART_FILE"
    chmod 0644 "$AUTOSTART_FILE"
    echo "[kiosk-install] autostart entry installed -> $AUTOSTART_FILE"
    echo "[kiosk-install] mode: $MODE  user: $KIOSK_USER  browser: $BROWSER_BIN"
    echo "[kiosk-install] done. Kiosk will launch on next login. To start now without logging out, ask the user to run:"
    echo "                  $WRAPPER_DST &"
    exit 0
fi

# ---------------------------------------------------------------------------
# MODE: service  (Pi OS Lite — install systemd + Xorg path)
# ---------------------------------------------------------------------------

# Set up tty1 autologin for the kiosk user
mkdir -p "$AUTOLOGIN_DROPIN_DIR"
cat > "$AUTOLOGIN_DROPIN" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin $KIOSK_USER --noclear %I \$TERM
EOF
echo "[kiosk-install] tty1 autologin configured for $KIOSK_USER"

# Write the systemd unit
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Ragnar on-screen kiosk (Chromium fullscreen)
After=network-online.target ragnar.service
Wants=network-online.target
# Cap the restart loop: if it fails 5 times in 2 minutes, stop and stay stopped
# instead of hammering (a broken kiosk should surface, not spin 89 times).
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User=$KIOSK_USER
PAMName=login
TTYPath=/dev/tty7
StandardInput=tty
StandardOutput=journal
StandardError=journal
Environment=HOME=$KIOSK_HOME
Environment=RAGNAR_REPO=$REPO_ROOT
Environment=RAGNAR_BROWSER=$BROWSER_BIN
# Clear a STALE X lock only. Guarded on no X running, because deleting the lock
# and socket of a live desktop session would disrupt that session while still
# leaving our own X unable to bind :0.
ExecStartPre=+/bin/sh -c 'pgrep -x Xorg >/dev/null 2>&1 || pgrep -x X >/dev/null 2>&1 || { rm -f /tmp/.X0-lock; rm -rf /tmp/.X11-unix/X0; }'
ExecStart=$WRAPPER_DST
Restart=on-failure
# 10s (not 5) so a dying Xorg releases the VT/DRM master before the next start.
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
echo "[kiosk-install] systemd unit installed -> $SERVICE_FILE"

# Let the kiosk escape hatch stop the unit in service mode (autostart mode kills
# the browser directly and needs no sudo). Scoped to exactly this one command so
# the ✕ button / Ctrl+Alt+Q can close a service-mode kiosk instead of it just
# respawning. Validated before install so a malformed rule can't wedge sudo.
KIOSK_SUDOERS="/etc/sudoers.d/ragnar-kiosk"
KIOSK_SUDOERS_TMP="$(mktemp)"
printf '%s ALL=(root) NOPASSWD: /bin/systemctl stop ragnar-kiosk.service, /usr/bin/systemctl stop ragnar-kiosk.service\n' \
    "$KIOSK_USER" > "$KIOSK_SUDOERS_TMP"
if visudo -c -f "$KIOSK_SUDOERS_TMP" >/dev/null 2>&1; then
    install -m 0440 "$KIOSK_SUDOERS_TMP" "$KIOSK_SUDOERS"
    echo "[kiosk-install] escape-hatch sudoers installed -> $KIOSK_SUDOERS"
else
    echo "[kiosk-install] WARN: sudoers validation failed — service-mode ✕/Ctrl+Alt+Q may only respawn the kiosk"
fi
rm -f "$KIOSK_SUDOERS_TMP"

systemctl daemon-reload

# Allow non-root X startup
mkdir -p /etc/X11
if [[ ! -f /etc/X11/Xwrapper.config ]]; then
    cat > /etc/X11/Xwrapper.config <<'XWRAP'
allowed_users=anybody
needs_root_rights=yes
XWRAP
    echo "[kiosk-install] Xwrapper.config created"
else
    if grep -q '^allowed_users=' /etc/X11/Xwrapper.config; then
        sed -i 's/^allowed_users=.*/allowed_users=anybody/' /etc/X11/Xwrapper.config
    else
        echo 'allowed_users=anybody' >> /etc/X11/Xwrapper.config
    fi
    if grep -q '^needs_root_rights=' /etc/X11/Xwrapper.config; then
        sed -i 's/^needs_root_rights=.*/needs_root_rights=yes/' /etc/X11/Xwrapper.config
    else
        echo 'needs_root_rights=yes' >> /etc/X11/Xwrapper.config
    fi
    echo "[kiosk-install] Xwrapper.config updated"
fi

# Pre-create Xorg log dir for the kiosk user
install -d -o "$KIOSK_USER" -g "$KIOSK_USER" -m 0755 \
    "$KIOSK_HOME/.local" "$KIOSK_HOME/.local/share" "$KIOSK_HOME/.local/share/xorg"

echo "[kiosk-install] done. Enable with: sudo systemctl enable --now ragnar-kiosk.service"
