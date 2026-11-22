#!/bin/bash
# cardputer_takeover.sh — hand a stock CardputerZero's LCD and keyboard to Ragnar.
#
#   sudo scripts/cardputer_takeover.sh apply    take the LCD and keyboard over
#   sudo scripts/cardputer_takeover.sh revert   give them back to APPLaunch
#   sudo scripts/cardputer_takeover.sh status   report the current state
#
# M5Stack's image runs APPLaunch, which draws on the LCD and grabs the keyboard
# exclusively, so Ragnar cannot use either while it runs. Stopping it is not
# enough: the image's fb_load bridge only refreshes the LCD while a process
# running the APPLaunch binary exists. So, as other full-screen software on this
# board does:
#
#   * the APPLaunch binary is moved to <binary>.real and replaced by a link to
#     sleep, run as "sleep infinity" through a user-unit override;
#   * the kernel console is taken off the LCD (console=tty1 removed, fbcon=map:99
#     added, getty@tty1 disabled) so it cannot draw over Ragnar. cmdline.txt is
#     backed up first, and the cmdline change needs a reboot to apply.
#
# Everything is reversible with "revert". Exits without changes on any board that
# is not a CardputerZero, so it is safe to call from shared install paths.

set -u

ROOT="${RAGNAR_CARDPUTER_ROOT:-}"     # alternate root, for testing
APPLAUNCH_BIN="$ROOT/usr/share/APPLaunch/bin/M5CardputerZero-APPLaunch"
SLEEP_BIN="${RAGNAR_CARDPUTER_SLEEP:-/usr/bin/sleep}"
SYS_GRAPHICS="$ROOT/sys/class/graphics"
VTCON_BIND="$ROOT/sys/class/vtconsole/vtcon1/bind"

log() { echo "[cardputer] $*"; }

cmdline_file() {
    local f
    for f in "$ROOT/boot/firmware/cmdline.txt" "$ROOT/boot/cmdline.txt"; do
        [ -f "$f" ] && { echo "$f"; return 0; }
    done
    return 1
}

lcd_present() {
    grep -qsE 'st7789v_m5st|panel-mipi-dbi' "$SYS_GRAPHICS"/fb*/name
}

launcher_present() {
    [ -e "$APPLAUNCH_BIN" ] || [ -L "$APPLAUNCH_BIN" ] || [ -e "${APPLAUNCH_BIN}.real" ]
}

is_cardputer() {
    launcher_present || lcd_present
}

# The launcher is a user unit owned by the image's default account (uid 1000).
launcher_user() { getent passwd 1000 | cut -d: -f1; }

user_systemctl() {
    local user
    user="$(launcher_user)"
    [ -n "$user" ] || return 0
    sudo -u "$user" XDG_RUNTIME_DIR=/run/user/1000 systemctl --user "$@" 2>/dev/null || true
}

override_file() {
    local home
    home="$(getent passwd 1000 | cut -d: -f6)"
    echo "$ROOT$home/.config/systemd/user/APPLaunch.service.d/override.conf"
}

apply_launcher() {
    launcher_present || { log "APPLaunch not installed — nothing to replace"; return 0; }
    user_systemctl stop APPLaunch.service
    if [ -e "$APPLAUNCH_BIN" ] && [ ! -L "$APPLAUNCH_BIN" ]; then
        mv "$APPLAUNCH_BIN" "${APPLAUNCH_BIN}.real" \
            || { log "could not move the APPLaunch binary aside"; return 1; }
    fi
    ln -sf "$SLEEP_BIN" "$APPLAUNCH_BIN" || return 1

    local override user
    override="$(override_file)"
    mkdir -p "$(dirname "$override")"
    cat > "$override" <<EOF
[Service]
ExecStart=
ExecStart=/usr/share/APPLaunch/bin/M5CardputerZero-APPLaunch infinity
EOF
    user="$(launcher_user)"
    [ -n "$user" ] && chown -R "$user:$user" "$(dirname "$(dirname "$override")")" 2>/dev/null
    user_systemctl daemon-reload
    user_systemctl enable APPLaunch.service
    user_systemctl start APPLaunch.service
    log "APPLaunch replaced (original kept at ${APPLAUNCH_BIN}.real)"
}

revert_launcher() {
    [ -e "${APPLAUNCH_BIN}.real" ] || { log "no saved APPLaunch binary — nothing to restore"; return 0; }
    user_systemctl stop APPLaunch.service
    rm -f "$APPLAUNCH_BIN"
    mv "${APPLAUNCH_BIN}.real" "$APPLAUNCH_BIN" || return 1
    rm -f "$(override_file)"
    user_systemctl daemon-reload
    user_systemctl start APPLaunch.service
    log "APPLaunch restored"
}

apply_console() {
    local cmdline
    if cmdline="$(cmdline_file)"; then
        [ -f "$cmdline.ragnar-bak" ] || cp "$cmdline" "$cmdline.ragnar-bak"
        sed -i 's/ console=tty1//g' "$cmdline"
        grep -q 'fbcon=map:99' "$cmdline" || sed -i '1 s/$/ fbcon=map:99/' "$cmdline"
    else
        log "cmdline.txt not found — kernel console left on the LCD"
    fi
    systemctl stop getty@tty1.service 2>/dev/null || true
    systemctl disable getty@tty1.service 2>/dev/null || true
    [ -w "$VTCON_BIND" ] && echo 0 > "$VTCON_BIND" 2>/dev/null
    log "kernel console taken off the LCD (a reboot makes this permanent)"
}

revert_console() {
    local cmdline
    if cmdline="$(cmdline_file)" && [ -f "$cmdline.ragnar-bak" ]; then
        mv "$cmdline.ragnar-bak" "$cmdline"
    fi
    systemctl enable getty@tty1.service 2>/dev/null || true
    log "kernel console restored (reboot to apply)"
}

status() {
    if ! is_cardputer; then
        echo "not a CardputerZero"
    elif [ -L "$APPLAUNCH_BIN" ]; then
        echo "takeover applied"
    elif [ -e "$APPLAUNCH_BIN" ]; then
        echo "stock launcher active"
    else
        echo "no launcher installed"
    fi
}

case "${1:-}" in
    apply|revert)
        if [ "$(id -u)" -ne 0 ] && [ -z "$ROOT" ]; then
            echo "run as root" >&2; exit 1
        fi
        if ! is_cardputer; then
            log "not a CardputerZero — no changes made"
            exit 0
        fi
        if [ "$1" = apply ]; then
            apply_launcher || exit 1
            apply_console
        else
            revert_launcher || exit 1
            revert_console
        fi
        ;;
    status)
        status
        ;;
    *)
        echo "usage: $0 apply|revert|status" >&2
        exit 2
        ;;
esac
