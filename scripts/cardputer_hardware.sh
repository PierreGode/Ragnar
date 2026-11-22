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
#   sudo scripts/cardputer_hardware.sh boot-screen      picture on the LCD early in boot
#   sudo scripts/cardputer_hardware.sh boot-screen-off  remove it (stays off across updates)
#   scripts/cardputer_hardware.sh status          what is set up
#   sudo scripts/cardputer_hardware.sh image      for building the CardputerZero OS
#                                                 image: no board to ask, so write
#                                                 everything the board needs
#
# Plain setup never edits cmdline.txt: it only says when the serial console is
# on the GNSS UART. Ragnar frees the port by itself when it finds the LoRa +
# GNSS Cap fitted (setting cardputer_free_gnss_uart), or run `gnss` here.

set -u

ROOT="${RAGNAR_CARDPUTER_ROOT:-}"        # alternate root, for testing
EXT5V="$ROOT/sys/class/leds/ext_5v_out/brightness"
NFC_OVERLAY="spi0-spidev2-gpio22-overlay"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# A picture on the LCD early in boot, long before the Ragnar service starts
# (ragnar_splash.py). The unit is not ordered before anything and cannot hold
# the boot up: it draws once and exits, and gives up quietly without a panel.
boot_screen_unit() {
    cat <<UNIT
# Written by Ragnar (scripts/cardputer_hardware.sh). Remove with:
#   sudo scripts/cardputer_hardware.sh boot-screen-off
[Unit]
Description=Ragnar boot screen (CardputerZero LCD)
DefaultDependencies=no
After=systemd-modules-load.service systemd-udev-trigger.service local-fs.target
ConditionPathExists=$REPO/ragnar_splash.py

[Service]
Type=simple
ExecStart=/usr/bin/python3 $REPO/ragnar_splash.py --boot --wait 20
TimeoutStartSec=40
Nice=5

[Install]
WantedBy=basic.target
UNIT
}

install_boot_screen() {
    local unit="$ROOT/etc/systemd/system/ragnar-splash.service"
    local wants="$ROOT/etc/systemd/system/basic.target.wants"
    [ -f "$REPO/ragnar_splash.py" ] || return 0
    [ -f "$ROOT/etc/ragnar-splash-optout" ] && return 0
    mkdir -p "$(dirname "$unit")"
    if [ "$(boot_screen_unit)" != "$(cat "$unit" 2>/dev/null)" ]; then
        boot_screen_unit > "$unit"
        log "boot screen installed (ragnar-splash.service)"
    fi
    if [ -z "$ROOT" ]; then
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable ragnar-splash.service >/dev/null 2>&1 || true
    fi
    # systemd may not answer (an alternate root, or an image-build chroot).
    if [ ! -e "$wants/ragnar-splash.service" ]; then
        mkdir -p "$wants" && ln -sf ../ragnar-splash.service "$wants/ragnar-splash.service"
    fi
}

remove_boot_screen() {
    [ -n "$ROOT" ] || systemctl disable ragnar-splash.service >/dev/null 2>&1 || true
    rm -f "$ROOT/etc/systemd/system/ragnar-splash.service" \
          "$ROOT/etc/systemd/system/basic.target.wants/ragnar-splash.service"
    mkdir -p "$ROOT/etc" && : > "$ROOT/etc/ragnar-splash-optout"
    [ -n "$ROOT" ] || systemctl daemon-reload 2>/dev/null || true
    log "boot screen removed (updates will not put it back; 'boot-screen' does)"
}

# With the LoRa + GNSS Cap fitted, set the Cap up as a Meshtastic node: install
# meshtasticd (from Meshtastic's package repository) and write its settings.
# Skipped when it is already set up, when another Cap or none is fitted, and
# when the owner removed it (cardputer_lora_meshtastic.sh remove).
install_lora_daemon() {
    [ -f "$ROOT/etc/meshtasticd/config.d/ragnar-cardputerzero-cap-lora.yaml" ] && return 0
    [ -f "$ROOT/etc/ragnar-meshtasticd-optout" ] && return 0
    local cap="${RAGNAR_CARDPUTER_CAP-$(python3 "$REPO/cardputer_caps.py" --cap 2>/dev/null)}"
    [ "$cap" = "lora_gnss" ] || return 0
    log "LoRa Cap fitted: setting it up as a Meshtastic node (meshtasticd)"
    bash "$REPO/scripts/cardputer_lora_meshtastic.sh" install \
        || log "Meshtastic was not set up. Try again from System -> CardputerZero hardware -> Set up Meshtastic"
}

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
sys.path.insert(0, '$REPO')
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

# ── Building the CardputerZero OS image ─────────────────────────────────────
# There is no board in an image build, so nothing can be detected: everything
# the board needs is written out. The parts that depend on what is plugged in
# (the LoRa Cap) are finished on the device's first boot, which runs `setup`
# (scripts/ragnar-firstboot.sh, on seeing IMAGE_MARK).
IMAGE_MARK="$ROOT/etc/ragnar-cardputer-image"

# The LCD is on SPI, its reset and backlight (and the keyboard, battery gauge
# and Cap detection) on I2C, and the Cap's GNSS receiver on the UART.
bus_params() {
    local config line
    config="$(config_file)" || { log "config.txt not found"; return 1; }
    for line in dtparam=spi=on dtparam=i2c_arm=on enable_uart=1; do
        grep -qE "^[[:space:]]*${line}\b" "$config" && continue
        grep -q '^# Ragnar: CardputerZero buses' "$config" \
            || printf '\n# Ragnar: CardputerZero buses (LCD, keyboard, battery, Cap GNSS)\n[all]\n' >> "$config"
        echo "$line" >> "$config"
    done
    mkdir -p "$ROOT/etc/modules-load.d"
    echo i2c-dev > "$ROOT/etc/modules-load.d/ragnar-cardputer.conf"
    log "SPI, I2C and the UART switched on in config.txt"
}

# The same result as `gnss`, without a running system to talk to.
free_uart_offline() {
    local cmdline
    if cmdline="$(cmdline_file)" && grep -qE 'console=(serial0|ttyS0)' "$cmdline"; then
        sed -i -E 's/[[:space:]]*console=(serial0|ttyS0)(,[^[:space:]]*)?//g; s/^[[:space:]]+//' "$cmdline"
        log "serial console taken off the GNSS UART"
    fi
    mkdir -p "$ROOT/etc/systemd/system"
    ln -sf /dev/null "$ROOT/etc/systemd/system/serial-getty@ttyS0.service"
}

build_image() {
    [ -n "$ROOT" ] || camera_tools
    bus_params || true
    camera_overlay || true
    free_uart_offline
    rm -f "$ROOT/etc/ragnar-splash-optout"
    install_boot_screen || true
    # meshtasticd is put on the image so that a LoRa Cap works without
    # internet; it stays off until first boot finds the Cap.
    [ -n "$ROOT" ] || bash "$REPO/scripts/cardputer_lora_meshtastic.sh" package \
        || log "meshtasticd is not on the image; it is downloaded when a LoRa Cap is fitted"
    mkdir -p "$ROOT/etc" && : > "$IMAGE_MARK"
    log "CardputerZero image prepared"
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
        install_boot_screen || true
        install_lora_daemon || true
        refresh_lora_config
        ;;
    camera)
        is_cardputer || { log "not a CardputerZero — nothing to do"; exit 0; }
        camera_tools
        camera_overlay
        ;;
    image)
        build_image
        ;;
    gnss)
        is_cardputer || { log "not a CardputerZero — nothing to do"; exit 0; }
        python3 "$REPO/cardputer_caps.py" --free-gnss-uart
        ;;
    boot-screen)
        is_cardputer || { log "not a CardputerZero — nothing to do"; exit 0; }
        rm -f "$ROOT/etc/ragnar-splash-optout"
        install_boot_screen
        ;;
    boot-screen-off)
        remove_boot_screen
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
    *) echo "usage: $0 [setup|camera|gnss|gnss-undo|nfc|boot-screen|boot-screen-off|image|status]"; exit 2 ;;
esac
