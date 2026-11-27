#!/bin/bash
#
# ensure_zram_swap.sh
#
# Make sure the box has compressed swap in RAM (zram) and that it is actually
# switched on - not just configured.
#
# Why: the installer has always written /etc/systemd/zram-generator.conf.d/
# override.conf (zram0 = twice the RAM), but that file is only read by the
# systemd-zram-generator package. Raspberry Pi OS trixie ships it (via
# rpi-swap), so swap works there. Kali (and so Ulfberht) and plain Debian do not,
# so the file did nothing and a 512 MB Pi Zero 2 W ran with no swap at all. Under
# memory pressure such a box stalls for many seconds re-reading program code from
# the SD card, the 15 s hardware watchdog fires, and it reboots every few minutes.
#
# Called from install_ragnar.sh, update_ragnar.sh and scripts/post_update.sh (the
# in-app Update button), so new installs and existing ones are both healed.
# Idempotent and never fatal: every problem is a warning and the exit code is 0.
#
# Usage: sudo scripts/ensure_zram_swap.sh [--no-start]
#   --no-start  write the config and install the package, but do not touch the
#               running system (image builds run in a chroot with no systemd)
#
# Opt out: RAGNAR_ZRAM=0 in the environment, or create /etc/ragnar/zram.disabled
# (the file also covers the in-app updater, which does not see your shell's env).

set -u

NO_START=0
[ "${1:-}" = "--no-start" ] && NO_START=1

CONF_DIR="${RAGNAR_ZRAM_CONF_DIR:-/etc/systemd/zram-generator.conf.d}"
CONF_FILE="$CONF_DIR/override.conf"

say()  { echo "  [zram] $*"; }

zram_swap_active() {
    grep -q '^/dev/zram' /proc/swaps 2>/dev/null
}

zram_swap_size() {
    awk '/^\/dev\/zram/ { printf "%d MB", $3 / 1024; exit }' /proc/swaps 2>/dev/null
}

generator_installed() {
    dpkg-query -W -f='${Status}' systemd-zram-generator 2>/dev/null | grep -q 'install ok installed'
}

if [ "${RAGNAR_ZRAM:-1}" = "0" ] || [ -f /etc/ragnar/zram.disabled ]; then
    say "skipped (opted out: RAGNAR_ZRAM=0 or /etc/ragnar/zram.disabled)"
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    say "needs root - skipped"
    exit 0
fi

# A container cannot manage swap; the host owns it.
if command -v systemd-detect-virt >/dev/null 2>&1 \
        && systemd-detect-virt --container >/dev/null 2>&1; then
    say "running in a container - swap is the host's job, skipped"
    exit 0
fi

# zram-tools (zramswap.service) is another way to run zram. Two managers would
# fight over /dev/zram0, so respect the one the operator chose.
if dpkg-query -W -f='${Status}' zram-tools 2>/dev/null | grep -q 'install ok installed'; then
    say "zram-tools is installed - leaving swap to it"
    exit 0
fi

# 1. The config. Written only when missing, so an edited file is kept.
if [ ! -f "$CONF_FILE" ]; then
    if mkdir -p "$CONF_DIR" && printf '[zram0]\nzram-size = ram * 2\n' > "$CONF_FILE"; then
        say "wrote $CONF_FILE (zram0 = ram * 2)"
    else
        say "WARNING: could not write $CONF_FILE"
        exit 0
    fi
fi

# Already have zram swap (Raspberry Pi OS trixie via rpi-swap, or a previous
# run): nothing more to do. A size change in the config applies on next boot.
if [ "$NO_START" = "0" ] && zram_swap_active; then
    say "zram swap already active ($(zram_swap_size))"
    exit 0
fi

# 2. The generator that reads it.
BOOTSTRAP_DEV=""
if ! generator_installed; then
    if ! command -v apt-get >/dev/null 2>&1; then
        say "WARNING: no apt-get - install systemd-zram-generator by hand for swap"
        exit 0
    fi

    # The boxes that need this most cannot run apt safely: a 512 MB board with
    # no swap stalls while apt loads its package cache, the hardware watchdog
    # resets it mid-install and dpkg is left half-configured. So switch on a
    # zram swap right now with the kernel module and util-linux's zramctl (no
    # package needed), then install the generator so zram also comes back on
    # every later boot. The generator takes over from this device on reboot.
    if [ "$NO_START" = "0" ] && ! grep -q . <(tail -n +2 /proc/swaps 2>/dev/null) \
            && command -v zramctl >/dev/null 2>&1 && modprobe zram 2>/dev/null; then
        mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
        if [ -n "$mem_kb" ] && BOOTSTRAP_DEV=$(zramctl --find --size "$((mem_kb * 2))K" 2>/dev/null) \
                && mkswap "$BOOTSTRAP_DEV" >/dev/null 2>&1 \
                && swapon -p 100 "$BOOTSTRAP_DEV" 2>/dev/null; then
            say "zram swap switched on now ($BOOTSTRAP_DEV, $(zram_swap_size)) so the install below cannot run out of memory"
        else
            [ -n "$BOOTSTRAP_DEV" ] && zramctl --reset "$BOOTSTRAP_DEV" >/dev/null 2>&1
            BOOTSTRAP_DEV=""
        fi
    fi

    # An interrupted earlier dpkg run blocks every apt call.
    if [ -n "$(dpkg --audit 2>/dev/null)" ]; then
        say "repairing an interrupted dpkg run first"
        DEBIAN_FRONTEND=noninteractive dpkg --configure -a >/dev/null 2>&1 || true
    fi

    say "installing systemd-zram-generator"
    # Judge by the package state, not apt's exit code: apt also reports
    # failures of *other* packages it had to finish configuring (a half-done
    # upgrade), and then exits non-zero although the generator went in fine.
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd-zram-generator >/dev/null 2>&1 || true
    if ! generator_installed; then
        # A stale package list is the usual reason; refresh once and retry.
        apt-get update >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            systemd-zram-generator >/dev/null 2>&1 || true
        if ! generator_installed; then
            if [ -n "$BOOTSTRAP_DEV" ]; then
                say "WARNING: could not install systemd-zram-generator - zram swap is on for this boot only"
            else
                say "WARNING: could not install systemd-zram-generator - no swap until it is installed"
            fi
            exit 0
        fi
    fi
    say "systemd-zram-generator installed"
fi

# 3. Switch it on now instead of waiting for the next boot.
if [ "$NO_START" = "1" ] || [ ! -d /run/systemd/system ]; then
    say "configured - zram swap starts on the next boot"
    exit 0
fi

# The bootstrap device from step 2 already gives swap; starting the generator's
# unit now would fight it for the same device. The generator owns it from the
# next boot.
if [ -n "$BOOTSTRAP_DEV" ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    say "zram swap active ($(zram_swap_size)); systemd-zram-generator manages it from the next boot"
    exit 0
fi

systemctl daemon-reload >/dev/null 2>&1 || true
systemctl start dev-zram0.swap >/dev/null 2>&1 || true

if zram_swap_active; then
    say "zram swap active ($(zram_swap_size))"
else
    say "WARNING: zram swap did not start now - it should come up on the next boot"
fi
exit 0
