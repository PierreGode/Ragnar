#!/bin/bash
# cardputer_hardware.sh — one-time setup for the M5Stack CardputerZero's
# camera and expansion header ("Cap" modules). Called by install_ragnar.sh and
# update_ragnar.sh on a CardputerZero; safe to run again, and a no-op elsewhere.
#
#   sudo scripts/cardputer_hardware.sh            camera tools + overlay, checks
#   sudo scripts/cardputer_hardware.sh camera     the camera part only
#   sudo scripts/cardputer_hardware.sh gnss       give the UART to the Cap's GNSS
#                                                 receiver (stops the serial login
#                                                 prompt now; console= leaves
#                                                 cmdline.txt, backup kept)
#   sudo scripts/cardputer_hardware.sh gnss-undo  put the serial console back
#   sudo scripts/cardputer_hardware.sh nfc        also enable the NFC reader's
#                                                 SPI chip-select (needs a reboot)
#   scripts/cardputer_hardware.sh status          what is set up
#
# Plain setup never edits cmdline.txt: it only says when the serial console is
# on the GNSS UART. Ragnar frees the port by itself when it finds the LoRa +
# GNSS Cap fitted (setting cardputer_free_gnss_uart), or run `gnss` here.

set -u

ROOT="${RAGNAR_CARDPUTER_ROOT:-}"        # alternate root, for testing
EXT5V="$ROOT/sys/class/leds/ext_5v_out/brightness"
NFC_OVERLAY="spi0-spidev2-gpio22-overlay"

SELF_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { echo "[cardputer-hw] $*"; }

config_file() {
    local f
    for f in "$ROOT/boot/firmware/config.txt" "$ROOT/boot/config.txt"; do
        [ -f "$f" ] && { echo "$f"; return 0; }
    done
    return 1
}

cmdline_file() {
    local f
    for f in "$ROOT/boot/firmware/cmdline.txt" "$ROOT/boot/cmdline.txt"; do
        [ -f "$f" ] && { echo "$f"; return 0; }
    done
    return 1
}

# M5Stack's image shows itself through its device tree (the Cap rail, the LCD
# framebuffer). On plain Raspberry Pi OS none of that exists, and the only sign
# is Ragnar's own display setting, so ask Ragnar as well.
is_cardputer() {
    [ -e "$EXT5V" ] || grep -qsi cardputer "$ROOT/proc/device-tree/model" \
        || grep -qsE 'st7789v_m5st' "$ROOT/sys/class/graphics"/fb*/name \
        || { [ -z "$ROOT" ] && python3 -c "
import sys
sys.path.insert(0, '$SELF_REPO')
import cardputer_caps as c
sys.exit(0 if c.is_cardputer_zero(c.saved_config()) else 1)" >/dev/null 2>&1; }
}

camera_tools() {
    if command -v rpicam-still >/dev/null 2>&1 || command -v libcamera-still >/dev/null 2>&1; then
        log "camera tools present"
        return 0
    fi
    log "installing camera tools (rpicam-apps)"
    apt-get install -y rpicam-apps-lite >/dev/null 2>&1 \
        || apt-get install -y rpicam-apps >/dev/null 2>&1 \
        || log "could not install rpicam-apps — the Camera panel will stay hidden"
}

serial_console_check() {
    local cmdline
    cmdline="$(cmdline_file)" || return 0
    if grep -qE 'console=(serial0|ttyS0)' "$cmdline"; then
        log "the serial console is on the UART the Cap's GNSS receiver uses."
        log "Ragnar frees it when the LoRa + GNSS Cap is fitted; to do it now: sudo $0 gnss"
        return 1
    fi
    return 0
}

# Radio settings Ragnar wrote for meshtasticd earlier are brought up to date
# (an older version named a chip-select pin the daemon could not claim).
refresh_lora_config() {
    local conf="$ROOT/etc/meshtasticd/config.d/ragnar-cardputerzero-cap-lora.yaml"
    local dropin="$ROOT/etc/systemd/system/meshtasticd.service.d/ragnar-cap.conf"
    local changed=0
    [ -f "$conf" ] || return 0
    if ! python3 "$REPO/cardputer_caps.py" --meshtasticd-config | cmp -s - "$conf"; then
        python3 "$REPO/cardputer_caps.py" --meshtasticd-config > "$conf"
        changed=1
    fi
    # The power step must run as root ("+"): as the service's own user it
    # cannot read Ragnar's folder, and the daemon then never starts.
    if [ -f "$dropin" ] && grep -q '^ExecStartPre=/' "$dropin"; then
        sed -i 's|^ExecStartPre=/|ExecStartPre=+/|' "$dropin"
        changed=1
    fi
    if [ "$changed" = 1 ]; then
        if [ -z "$ROOT" ]; then
            systemctl daemon-reload 2>/dev/null || true
            systemctl reset-failed meshtasticd.service 2>/dev/null || true
            systemctl restart meshtasticd.service 2>/dev/null || true
        fi
        log "updated the LoRa Cap's meshtasticd settings"
    fi
}

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The camera is not auto-detected on this board: M5Stack's image turns
# camera_auto_detect off and loads the imx219 overlay by name.
camera_overlay() {
    local config
    config="$(config_file)" || { log "config.txt not found"; return 1; }
    if grep -qE '^[[:space:]]*dtoverlay=imx219\b' "$config"; then
        log "camera overlay already enabled"
        return 0
    fi
    [ -f "$config.ragnar-bak" ] || cp "$config" "$config.ragnar-bak"
    sed -i 's/^[[:space:]]*camera_auto_detect=1/camera_auto_detect=0/' "$config"
    grep -qE '^[[:space:]]*camera_auto_detect=' "$config" \
        || printf '\n# Ragnar: the CardputerZero camera is loaded by name\ncamera_auto_detect=0\n' >> "$config"
    printf '\n# Ragnar: CardputerZero built-in camera (IMX219)\n[all]\ndtoverlay=imx219\n' >> "$config"
    log "camera overlay enabled (dtoverlay=imx219) — reboot to apply"
}

enable_nfc() {
    local config
    config="$(config_file)" || { log "config.txt not found"; return 1; }
    if grep -qE "^dtoverlay=${NFC_OVERLAY}\b" "$config"; then
        log "NFC chip-select overlay already enabled"
        return 0
    fi
    if [ ! -e "$ROOT/boot/firmware/overlays/${NFC_OVERLAY}.dtbo" ] \
        && [ ! -e "$ROOT/boot/overlays/${NFC_OVERLAY}.dtbo" ]; then
        log "overlay ${NFC_OVERLAY}.dtbo is not on this image — it ships with M5Stack's image"
        return 1
    fi
    [ -f "$config.ragnar-bak" ] || cp "$config" "$config.ragnar-bak"
    printf '\n# Ragnar: SPI0 CS2 on GPIO22 for the Cap NFC reader\ndtoverlay=%s\n' "$NFC_OVERLAY" >> "$config"
    log "NFC chip-select overlay enabled — reboot to apply"
}

status() {
    if ! is_cardputer; then
        echo "not a CardputerZero"
        return 0
    fi
    if [ -e "$EXT5V" ]; then
        echo "cap power rail: $(cat "$EXT5V")"
    else
        # Plain Raspberry Pi OS has no control file; Ragnar switches the rail
        # through the board's I/O expander instead.
        echo "cap power rail: switched by Ragnar (sudo python3 cardputer_caps.py shows it)"
    fi
    local config
    echo "camera tools: $(command -v rpicam-still libcamera-still 2>/dev/null | head -1 || true)"
    if config="$(config_file)" && grep -qE '^[[:space:]]*dtoverlay=imx219\b' "$config"; then
        echo "camera overlay: enabled"
    else
        echo "camera overlay: not enabled"
    fi
    local config
    if config="$(config_file)" && grep -qE "^dtoverlay=${NFC_OVERLAY}\b" "$config"; then
        echo "nfc overlay: enabled"
    else
        echo "nfc overlay: not enabled"
    fi
    serial_console_check >/dev/null && echo "serial console: clear of the UART" \
        || echo "serial console: on the GNSS UART"
}

case "${1:-setup}" in
    setup)
        is_cardputer || { log "not a CardputerZero — nothing to do"; exit 0; }
        camera_tools
        camera_overlay || true
        serial_console_check || true
        refresh_lora_config
        ;;
    camera)
        is_cardputer || { log "not a CardputerZero — nothing to do"; exit 0; }
        camera_tools
        camera_overlay
        ;;
    gnss)
        is_cardputer || { log "not a CardputerZero — nothing to do"; exit 0; }
        python3 "$REPO/cardputer_caps.py" --free-gnss-uart
        ;;
    gnss-undo)
        python3 "$REPO/cardputer_caps.py" --restore-serial-console
        ;;
    nfc)
        is_cardputer || { log "not a CardputerZero — nothing to do"; exit 0; }
        camera_tools
        enable_nfc
        ;;
    status) status ;;
    *) echo "usage: $0 [setup|camera|gnss|gnss-undo|nfc|status]"; exit 2 ;;
esac
