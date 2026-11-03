#!/bin/bash
# installhead.sh - add (or change) a screen on an existing Ragnar install.
#
# A headless/server install ("No display") leaves the unit unable to drive any
# screen, even if one is plugged in later:
#   * ragnar.service runs headlessRagnar.py with RAGNAR_HEADLESS=1, so the
#     Display thread (and the 1.44" HAT's key/joystick listener) never starts;
#   * the display driver dependencies (spidev, smbus2, gpiozero/lgpio, luma)
#     were skipped;
#   * epd_type was never written to config/shared_config.json;
#   * SPI/I2C may not be enabled and the wipe_epd.py pre-start hook is missing.
# Picking a screen in Config -> Display can't fix that, because the headless
# entrypoint never draws anything. This script fixes all of it for the chosen
# screen, then restarts Ragnar. It can also switch a display install back to
# headless.
#
# Usage:
#   sudo ./installhead.sh             # interactive menu
#   sudo ./installhead.sh st7735s     # non-interactive, by epd_type name
#   sudo ./installhead.sh headless    # revert to headless (web UI only)

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

ragnar_USER="ragnar"
ragnar_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_JSON="$ragnar_PATH/config/shared_config.json"
RAGNAR_UNIT="/etc/systemd/system/ragnar.service"
NEEDS_REBOOT=false

info() { echo -e "${BLUE}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[x]${NC} $*"; exit 1; }

# epd_type -> label. Order is the menu order; keys must match DISPLAY_PROFILES
# in shared.py.
DISPLAYS=(
    "st7735s|ST7735S      1.44\" LCD HAT + joystick 128x128 (Waveshare)"
    "epd2in13_V4|epd2in13_V4  2.13\" e-Paper V4 122x250"
    "epd2in13_V3|epd2in13_V3  2.13\" e-Paper V3 122x250"
    "epd2in13_V2|epd2in13_V2  2.13\" e-Paper V2 122x250"
    "epd2in13|epd2in13     2.13\" e-Paper V1 122x250"
    "epd2in13b_V4|epd2in13b_V4 2.13\" e-Paper B V4 122x250"
    "epd2in7_V2|epd2in7_V2   2.7\"  e-Paper V2 176x264"
    "epd2in7|epd2in7      2.7\"  e-Paper V1 176x264"
    "epd2in9_V2|epd2in9_V2   2.9\"  e-Paper 128x296"
    "epd3in7|epd3in7      3.7\"  e-Paper 280x480"
    "epd4in26|epd4in26     4.26\" e-Paper 800x480"
    "gc9a01|GC9A01       1.28\" round TFT 240x240"
    "st7789v2|ST7789V3     1.9\" M5Stack CardputerZero 320x170"
    "ili9486|ILI9486/9488 3.5\" SPI TFT 320x480"
    "whisplay|Whisplay     1.69\" ST7789 240x280 (PiSugar HAT)"
    "ssd1306|SSD1306      0.96\" OLED 128x64 (I2C)"
    "lcd1602|LCD1602      16x2 character LCD (I2C)"
    "max7219_8panel|MAX7219      8 panels 64x8 LED matrix"
    "max7219_4panel|MAX7219      4 panels 32x8 LED matrix"
    "headless|No display   revert to headless (web UI only)"
)

[ "$(id -u)" -eq 0 ] || die "Run as root: sudo $0 $*"
[ -f "$ragnar_PATH/Ragnar.py" ] || die "Ragnar.py not found next to this script ($ragnar_PATH)"
[ -f "$RAGNAR_UNIT" ] || die "$RAGNAR_UNIT not found — run install_ragnar.sh first"

valid_choice() {
    local want="$1" entry
    for entry in "${DISPLAYS[@]}"; do
        [ "${entry%%|*}" = "$want" ] && return 0
    done
    return 1
}

current_epd_type() {
    python3 - "$CONFIG_JSON" <<'PY' 2>/dev/null
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("epd_type", ""))
except Exception:
    print("")
PY
}

select_display() {
    local cur mode i entry choice
    cur="$(current_epd_type)"
    if grep -q 'headlessRagnar\.py' "$RAGNAR_UNIT"; then
        mode="headless"
    else
        mode="display (${cur:-default})"
    fi
    echo -e "\n${CYAN}Ragnar screen setup${NC}  —  current mode: ${YELLOW}${mode}${NC}\n"
    i=1
    for entry in "${DISPLAYS[@]}"; do
        printf "  %2d) %s\n" "$i" "${entry#*|}"
        i=$((i + 1))
    done
    echo ""
    while true; do
        read -r -p "Select your screen (1-${#DISPLAYS[@]}): " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#DISPLAYS[@]}" ]; then
            SELECTED="${DISPLAYS[$((choice - 1))]%%|*}"
            return
        fi
        echo -e "${RED}Invalid choice.${NC}"
    done
}

boot_config() {
    local c
    for c in /boot/firmware/config.txt /boot/config.txt; do
        [ -f "$c" ] && { echo "$c"; return; }
    done
}

# Enable an interface (spi|i2c). raspi-config returns 0 for "enabled".
enable_interface() {
    local iface="$1" cfg param
    if command -v raspi-config >/dev/null 2>&1; then
        if [ "$(raspi-config nonint get_$iface 2>/dev/null)" = "0" ]; then
            ok "${iface^^} already enabled"
            return
        fi
        raspi-config nonint do_$iface 0 && ok "Enabled ${iface^^}" && NEEDS_REBOOT=true
        return
    fi
    cfg="$(boot_config)"
    [ -n "$cfg" ] || { warn "No raspi-config or config.txt — enable ${iface^^} manually"; return; }
    [ "$iface" = "i2c" ] && param="i2c_arm" || param="spi"
    if grep -q "^dtparam=${param}=on" "$cfg"; then
        ok "${iface^^} already enabled"
    else
        echo "dtparam=${param}=on" >> "$cfg"
        ok "Enabled ${iface^^} in $cfg"
        NEEDS_REBOOT=true
    fi
}

pip_install() {
    pip3 install --break-system-packages "$@" >/dev/null 2>&1
}

py_has() {
    (python3 -c "import $1" >/dev/null 2>&1) 2>/dev/null
}

install_deps() {
    local disp="$1"
    info "Installing display dependencies..."

    py_has PIL || { pip_install "Pillow>=10.0.0" || apt-get install -y python3-pil >/dev/null 2>&1; }

    # GPIO: every GPIO-driven screen (and the 1.44" HAT's keys + joystick) uses
    # gpiozero; on a Pi 5 gpiozero needs the lgpio pin factory.
    if ! py_has gpiozero || ! py_has lgpio; then
        apt-get install -y python3-gpiozero python3-lgpio >/dev/null 2>&1 \
            || pip_install gpiozero lgpio
    fi
    py_has gpiozero && ok "gpiozero available" || warn "gpiozero missing — buttons/joystick will not work"
    py_has lgpio || warn "lgpio missing (required on Pi 5)"

    case "$disp" in
        ssd1306|lcd1602)
            py_has smbus2 || pip_install smbus2
            py_has smbus2 && ok "smbus2 available" || warn "smbus2 failed to install"
            ;;
        max7219_*)
            py_has spidev || pip_install spidev
            py_has luma.led_matrix || pip_install luma.led_matrix luma.core
            py_has luma.led_matrix && ok "luma.led_matrix available" || warn "luma.led_matrix failed to install"
            ;;
        *)
            py_has spidev || pip_install spidev
            py_has spidev && ok "spidev available" || warn "spidev failed to install — SPI screens will not work"
            ;;
    esac

    [ -f "$ragnar_PATH/resources/waveshare_epd/${disp}.py" ] \
        || [ -f "$ragnar_PATH/resources/waveshare_epd/${disp%_*panel}.py" ] \
        || warn "Driver resources/waveshare_epd/${disp}.py not found"
}

write_epd_type() {
    local disp="$1"
    mkdir -p "$(dirname "$CONFIG_JSON")"
    python3 - "$CONFIG_JSON" "$disp" <<'PY' || die "Could not write $CONFIG_JSON"
import json, os, sys
path, disp = sys.argv[1], sys.argv[2]
cfg = {}
if os.path.exists(path):
    try:
        with open(path) as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
cfg["epd_type"] = disp
with open(path, "w") as f:
    json.dump(cfg, f, indent=4)
PY
    chown "$ragnar_USER:$ragnar_USER" "$CONFIG_JSON" 2>/dev/null || true
    ok "epd_type = $disp  ($CONFIG_JSON)"
}

# Point ragnar.service at the display entrypoint. Edits the existing unit in
# place so anything else install/update added to it is preserved.
set_unit_display() {
    cp "$RAGNAR_UNIT" "${RAGNAR_UNIT}.bak"
    sed -i 's#headlessRagnar\.py#Ragnar.py#' "$RAGNAR_UNIT"
    sed -i '/^Environment=RAGNAR_HEADLESS=1/d' "$RAGNAR_UNIT"
    if ! grep -q 'wipe_epd\.py' "$RAGNAR_UNIT"; then
        sed -i "/^ExecStart=/i ExecStartPre=-/usr/bin/python3 -OO $ragnar_PATH/wipe_epd.py" "$RAGNAR_UNIT"
    fi
    ok "ragnar.service -> Ragnar.py (display mode)"
}

set_unit_headless() {
    cp "$RAGNAR_UNIT" "${RAGNAR_UNIT}.bak"
    sed -i '/wipe_epd\.py/d' "$RAGNAR_UNIT"
    sed -i 's#^\(ExecStart=.*/\)Ragnar\.py#\1headlessRagnar.py#' "$RAGNAR_UNIT"
    grep -q '^Environment=RAGNAR_HEADLESS=1' "$RAGNAR_UNIT" \
        || sed -i '/^ExecStart=/i Environment=RAGNAR_HEADLESS=1' "$RAGNAR_UNIT"
    ok "ragnar.service -> headlessRagnar.py (headless mode)"
}

add_groups() {
    local grp groups=()
    for grp in spi gpio i2c; do
        getent group "$grp" >/dev/null 2>&1 && groups+=("$grp")
    done
    if [ ${#groups[@]} -gt 0 ]; then
        usermod -a -G "$(IFS=,; echo "${groups[*]}")" "$ragnar_USER" 2>/dev/null \
            && ok "$ragnar_USER in groups: ${groups[*]}"
    fi
}

# ── main ──────────────────────────────────────────────────────────────────────
SELECTED="${1:-}"
if [ -n "$SELECTED" ]; then
    valid_choice "$SELECTED" || die "Unknown screen '$SELECTED'. Valid: $(printf '%s ' "${DISPLAYS[@]%%|*}")"
else
    select_display
fi

systemctl stop ragnar.service 2>/dev/null || true

if [ "$SELECTED" = "headless" ]; then
    set_unit_headless
else
    info "Setting up screen: $SELECTED"
    case "$SELECTED" in
        ssd1306|lcd1602) enable_interface i2c ;;
        *)               enable_interface spi ;;
    esac
    install_deps "$SELECTED"
    add_groups
    write_epd_type "$SELECTED"
    set_unit_display
fi

systemctl daemon-reload

if [ "$NEEDS_REBOOT" = true ]; then
    echo ""
    warn "An interface was just enabled — a reboot is required before the screen works."
    read -r -p "Reboot now? (y/n): " rb
    if [[ "$rb" =~ ^[Yy]$ ]]; then
        reboot
        exit 0
    fi
    warn "Reboot later with: sudo reboot"
fi

systemctl restart ragnar.service
sleep 3
if systemctl is-active --quiet ragnar.service; then
    ok "ragnar.service running"
else
    warn "ragnar.service is not running — check: sudo journalctl -u ragnar.service -n 50"
fi

if [ "$SELECTED" = "st7789v2" ]; then
    bash "$ragnar_PATH/scripts/cardputer_takeover.sh" apply
    warn "Reboot to take the kernel console off the CardputerZero LCD."
fi

if [ "$SELECTED" = "st7735s" ]; then
    echo ""
    echo -e "${CYAN}1.44\" LCD HAT controls:${NC} joystick = pages, press = autoscroll,"
    echo "  KEY1 = network diagnostics, KEY2 = rotate, KEY3 = next page (hold = restart)."
fi
echo ""
ok "Done. You can switch screens later with: sudo $ragnar_PATH/installhead.sh"
