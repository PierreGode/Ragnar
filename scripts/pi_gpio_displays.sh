#!/bin/bash
# Make GPIO-attached displays (e-Paper, SPI TFTs, I2C OLEDs) usable on a
# Raspberry Pi whose OS is not Raspberry Pi OS.
#
# Raspberry Pi OS ships everything the display drivers need. A Kali base (the
# Ragnar OS "Ulfberht" edition) ships none of it, so a screen stayed dark:
#   1. no raspi-config, so SPI/I2C were never switched on in config.txt
#   2. no spidev / gpiozero / smbus2 Python modules
#   3. no lgpio, the only gpiozero backend that works on a Pi 5, and no
#      package for it (it is built from source here)
#   4. gpiozero opens the Pi 5 header as /dev/gpiochip4, an alias Raspberry Pi
#      OS adds with a udev rule; without it: "can not open gpiochip"
#
# Idempotent and safe to run on every install and update: each step is skipped
# when already satisfied, and on Raspberry Pi OS the whole script is a no-op.
# It never fails the caller (always exits 0); problems are reported as warnings.
#
# Usage: pi_gpio_displays.sh [--image-build]
#   --image-build   running in an image-build chroot: the target is a Pi by
#                   construction, there is no live udev and no live hardware.
#                   Same as RAGNAR_IMAGE_BUILD=1.
#   RAGNAR_FORCE_PI=1 treats the host as a Pi (chroot /proc is the build host's).
#
# Exit status is always 0. Prints "REBOOT_REQUIRED" on its last line when
# config.txt was changed and the interfaces only appear after a reboot.

IMAGE_BUILD=false
[ "${RAGNAR_IMAGE_BUILD:-0}" = "1" ] && IMAGE_BUILD=true
[ "$1" = "--image-build" ] && IMAGE_BUILD=true

# Pinned lg release (https://github.com/joan2937/lg) for the source build.
LG_TAG="v0.2.2"
LG_COMMIT="b959a17d723360e85648316757b02dbea9902feb"
LGPIO_PIP="lgpio==0.2.2.0"
UDEV_RULE="/etc/udev/rules.d/99-ragnar-pi5-gpiochip4.rules"

ok()   { echo "  [ok] $*"; }
info() { echo "  [..] $*"; }
warn() { echo "  [!!] $*"; }

is_pi() {
    [ "$IMAGE_BUILD" = true ] && return 0
    [ "${RAGNAR_FORCE_PI:-0}" = "1" ] && return 0
    grep -qai "Raspberry Pi" /proc/device-tree/model 2>/dev/null && return 0
    grep -qi "Raspberry Pi" /proc/cpuinfo 2>/dev/null
}

has_mod() { (python3 -c "import $1" >/dev/null 2>&1) 2>/dev/null; }

apt_install() {
    command -v apt-get >/dev/null 2>&1 || return 1
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null 2>&1
}

pip_install() {
    pip3 install --break-system-packages "$@" >/dev/null 2>&1 \
        || pip3 install "$@" >/dev/null 2>&1
}

# ── 1. SPI / I2C in config.txt (only where raspi-config cannot do it) ────────
REBOOT_REQUIRED=false

boot_config() {
    local f
    for f in /boot/firmware/config.txt /boot/config.txt; do
        [ -f "$f" ] && { echo "$f"; return 0; }
    done
    return 1
}

# enable_dtparam <file> <param>   e.g. enable_dtparam config.txt spi
# Returns 0 if the file now enables it, 1 on failure. Sets REBOOT_REQUIRED
# when it had to change the file.
enable_dtparam() {
    local cfg="$1" param="$2"
    # Already on (also as part of a comma list: dtparam=i2c_arm=on,spi=on).
    grep -qE "^[[:space:]]*dtparam=([^#]*,)?${param}=on([,[:space:]]|$)" "$cfg" && return 0
    if grep -qE "^[[:space:]]*#[[:space:]]*dtparam=${param}=on[[:space:]]*$" "$cfg"; then
        # Uncomment the stock line (first match only).
        sed -i "0,/^[[:space:]]*#[[:space:]]*dtparam=${param}=on[[:space:]]*$/s//dtparam=${param}=on/" "$cfg" || return 1
    else
        # Append under [all] so it is not swallowed by a trailing [cm5]/[pi4]
        # style conditional section.
        printf '\n[all]\n# Enabled by Ragnar for GPIO displays\ndtparam=%s=on\n' "$param" >> "$cfg" || return 1
    fi
    REBOOT_REQUIRED=true
    return 0
}

enable_interfaces() {
    if command -v raspi-config >/dev/null 2>&1; then
        ok "raspi-config present — SPI/I2C are managed by it"
        return
    fi
    local cfg
    cfg="$(boot_config)" || { warn "no config.txt found — cannot enable SPI/I2C"; return; }
    [ -f "${cfg}.ragnar-bak" ] || cp -p "$cfg" "${cfg}.ragnar-bak" 2>/dev/null
    local p
    for p in spi i2c_arm; do
        if enable_dtparam "$cfg" "$p"; then
            ok "dtparam=${p}=on set in $cfg"
        else
            warn "could not set dtparam=${p}=on in $cfg"
        fi
    done
    # Changed the file but the bus is already live (or there is no live
    # hardware to speak of): nothing to reboot for.
    if [ "$IMAGE_BUILD" = true ] || { [ -e /dev/spidev0.0 ] && ls /dev/i2c-1 >/dev/null 2>&1; }; then
        REBOOT_REQUIRED=false
    fi
}

# ── 2. Python modules the drivers import ────────────────────────────────────
ensure_mod() {   # <import name> <apt package> <pip package>
    has_mod "$1" && { ok "python module $1 present"; return 0; }
    apt_install "$2"; has_mod "$1" && { ok "python module $1 installed ($2)"; return 0; }
    pip_install "$3"; has_mod "$1" && { ok "python module $1 installed (pip $3)"; return 0; }
    warn "python module $1 could not be installed"
    return 1
}

# ── 3. lgpio: packaged → wheel → pinned source build ────────────────────────
# Newer toolchains need two nudges: GCC 15 defaults to C23, which rejects lg's
# K&R-style callback prototypes, and SWIG 4.4+ no longer defines the Python 2
# PyInt_/PyString_ aliases the lgpio interface file still uses.
LG_STD="-std=gnu17"
LG_PY_ALIASES="-DPyInt_FromLong=PyLong_FromLong -DPyInt_AsLong=PyLong_AsLong -DPyInt_Check=PyLong_Check -DPyString_FromString=PyUnicode_FromString"

_build_lgpio() {   # <scratch dir>
    local tmp="$1"
    if [ ! -e /usr/local/lib/liblgpio.so.1 ] && [ ! -e /usr/lib/liblgpio.so.1 ]; then
        git clone -q --depth 1 --branch "$LG_TAG" https://github.com/joan2937/lg "$tmp/lg" 2>/dev/null \
            || { warn "could not download the lg source"; return 1; }
        local got
        got="$(git -C "$tmp/lg" rev-parse HEAD 2>/dev/null)"
        if [ "$got" != "$LG_COMMIT" ]; then
            warn "lg source is not the pinned commit (got ${got:-none}) — refusing to build it"
            return 1
        fi
        make -C "$tmp/lg" -j"$(nproc 2>/dev/null || echo 1)" \
            CFLAGS="-O3 -Wall -pthread -fpic $LG_STD" liblgpio.so >"$tmp/make.log" 2>&1 \
            || { warn "liblgpio failed to compile: $(grep -m1 -i 'error' "$tmp/make.log")"; return 1; }
        install -m 0755 -d /usr/local/include /usr/local/lib \
            && install -m 0644 "$tmp/lg/lgpio.h" /usr/local/include/ \
            && install -m 0755 "$tmp/lg/liblgpio.so.1" /usr/local/lib/ \
            && ln -fs liblgpio.so.1 /usr/local/lib/liblgpio.so \
            || { warn "could not install liblgpio into /usr/local"; return 1; }
        ldconfig 2>/dev/null
    fi

    # The Python binding: plain first, then with the compatibility flags.
    CFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib" \
        pip_install --no-binary lgpio "$LGPIO_PIP"
    has_mod lgpio && return 0
    CFLAGS="$LG_STD $LG_PY_ALIASES -I/usr/local/include" LDFLAGS="-L/usr/local/lib" \
        pip_install --no-binary lgpio "$LGPIO_PIP"
    has_mod lgpio
}

build_lgpio_from_source() {
    info "building lgpio from source (lg ${LG_TAG}) — this takes a few minutes"
    apt_install build-essential swig python3-dev python3-setuptools git
    command -v gcc >/dev/null 2>&1 && command -v make >/dev/null 2>&1 \
        && command -v swig >/dev/null 2>&1 && command -v git >/dev/null 2>&1 \
        || { warn "build tools missing (gcc/make/swig/git) — cannot build lgpio"; return 1; }
    local tmp rc
    tmp="$(mktemp -d /tmp/ragnar-lg.XXXXXX)" || return 1
    _build_lgpio "$tmp"; rc=$?
    rm -rf "$tmp"
    return $rc
}

ensure_lgpio() {
    has_mod lgpio && { ok "python module lgpio present"; return 0; }
    apt_install python3-lgpio
    has_mod lgpio && { ok "python module lgpio installed (python3-lgpio)"; return 0; }
    pip_install --only-binary :all: "$LGPIO_PIP"
    has_mod lgpio && { ok "python module lgpio installed (wheel)"; return 0; }
    if build_lgpio_from_source; then
        ok "python module lgpio built from source"
        return 0
    fi
    warn "lgpio unavailable — GPIO displays will not work on a Raspberry Pi 5"
    return 1
}

# ── 4. /dev/gpiochip4 alias for the Pi 5 header ─────────────────────────────
# Matches only the RP1 GPIO controller (the Pi 5 / CM5 / Pi 500 40-pin header)
# and only when the kernel numbers it gpiochip0, so it does nothing on any
# other board or on older kernels where RP1 really is gpiochip4.
ensure_gpiochip4_alias() {
    local want='SUBSYSTEM=="gpio", KERNEL=="gpiochip0", KERNELS=="1f000d0000.gpio", SYMLINK+="gpiochip4"'
    if [ -f "$UDEV_RULE" ] && grep -qxF "$want" "$UDEV_RULE"; then
        ok "gpiochip4 alias rule present"
    else
        mkdir -p "$(dirname "$UDEV_RULE")" 2>/dev/null
        if printf '# Ragnar: gpiozero opens the Raspberry Pi 5 header as gpiochip4\n%s\n' "$want" > "$UDEV_RULE"; then
            ok "gpiochip4 alias rule installed"
        else
            warn "could not write $UDEV_RULE"
            return
        fi
    fi
    [ "$IMAGE_BUILD" = true ] && return
    if command -v udevadm >/dev/null 2>&1; then
        udevadm control --reload >/dev/null 2>&1
        udevadm trigger --subsystem-match=gpio --action=add >/dev/null 2>&1
        udevadm settle --timeout=5 >/dev/null 2>&1
    fi
}

# Live check on real Pi 5 hardware: can the backend gpiozero will pick
# actually open the header?
verify_pi5_gpio() {
    [ "$IMAGE_BUILD" = true ] && return
    grep -qaE 'Raspberry Pi (5|500|Compute Module 5)' /proc/device-tree/model 2>/dev/null || return
    if python3 -c "import lgpio; lgpio.gpiochip_close(lgpio.gpiochip_open(4))" >/dev/null 2>&1; then
        ok "Pi 5 GPIO header opens through lgpio (gpiochip4)"
    else
        warn "Pi 5 GPIO header cannot be opened through lgpio yet — displays stay dark"
    fi
}

main() {
    if ! is_pi; then
        ok "not a Raspberry Pi — no GPIO displays to prepare"
        return
    fi
    if [ "$(id -u)" != "0" ]; then
        warn "must run as root — skipped"
        return
    fi
    enable_interfaces
    ensure_mod spidev   python3-spidev   spidev
    ensure_mod smbus2   python3-smbus2   smbus2
    ensure_mod gpiozero python3-gpiozero gpiozero
    ensure_lgpio
    ensure_gpiochip4_alias
    verify_pi5_gpio
    if [ "$REBOOT_REQUIRED" = true ]; then
        warn "SPI/I2C were just enabled in config.txt — reboot for the display to work"
        echo "REBOOT_REQUIRED"
    fi
}

# Sourced (by the tests) → define the functions only.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main
    exit 0
fi
