#!/bin/bash
# cardputer_hardware.sh — one-time setup for the M5Stack CardputerZero's
# camera and expansion header ("Cap" modules). Called by install_ragnar.sh and
# update_ragnar.sh on a CardputerZero; safe to run again, and a no-op elsewhere.
#
#   sudo scripts/cardputer_hardware.sh            camera tools + checks
#   sudo scripts/cardputer_hardware.sh nfc        also enable the NFC reader's
#                                                 SPI chip-select (needs a reboot)
#   scripts/cardputer_hardware.sh status          what is set up
#
# What it does NOT do: it never edits cmdline.txt. If the serial console is on
# the UART the GNSS receiver uses, it says so and prints the fix.

set -u

ROOT="${RAGNAR_CARDPUTER_ROOT:-}"        # alternate root, for testing
EXT5V="$ROOT/sys/class/leds/ext_5v_out/brightness"
NFC_OVERLAY="spi0-spidev2-gpio22-overlay"

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

is_cardputer() {
    [ -e "$EXT5V" ] || grep -qsi cardputer "$ROOT/proc/device-tree/model" \
        || grep -qsE 'st7789v_m5st' "$ROOT/sys/class/graphics"/fb*/name
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
        log "to free it: sudo sed -i 's/ console=serial0,[0-9]*//; s/ console=ttyS0,[0-9]*//' $cmdline && sudo reboot"
        return 1
    fi
    return 0
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
    echo "cap power rail: $([ -e "$EXT5V" ] && cat "$EXT5V" || echo missing)"
    echo "camera tools: $(command -v rpicam-still libcamera-still 2>/dev/null | head -1 || true)"
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
        serial_console_check || true
        ;;
    nfc)
        is_cardputer || { log "not a CardputerZero — nothing to do"; exit 0; }
        camera_tools
        enable_nfc
        ;;
    status) status ;;
    *) echo "usage: $0 [setup|nfc|status]"; exit 2 ;;
esac
