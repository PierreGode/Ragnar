#!/bin/bash
#
# hg_hat_setup.sh
#
# System pieces for the HackerGadgets Pwnagotchi HAT, installed only when the
# HAT answers on I2C. Idempotent and never fatal (exit 0 on every path).
#
#   1. RTC: dtoverlay=i2c-rtc,pcf85063a in config.txt (applies after a reboot).
#      The kernel then does the rest: loading the driver sets the system clock
#      from the RTC, and once NTP has synchronised the clock the kernel writes
#      it back to the RTC (CONFIG_RTC_HCTOSYS / CONFIG_RTC_SYSTOHC).
#   2. Power-off hook in /usr/lib/systemd/system-shutdown/: after a clean
#      power-off, with the file systems already read-only, the HAT is told to
#      switch its output off, so the SD card is safe and the halted Pi does not
#      drain the battery. Reboots are left alone.
#
# Run by install_ragnar.sh, update_ragnar.sh, scripts/post_update.sh, and by
# Ragnar itself (hg_hat.py) the first time it sees the HAT, which covers a fresh
# install where I2C only comes up after the installer's reboot.
#
# Opt out: create /etc/ragnar/hg_hat.disabled

set -u

REPO="$(cd "$(dirname "$0")/.." && pwd -P)"
SRC="$REPO/scripts/hg_hat"

say() { echo "  [hg-hat] $*"; }

[ -f /etc/ragnar/hg_hat.disabled ] && { say "skipped (/etc/ragnar/hg_hat.disabled)"; exit 0; }
[ "$(id -u)" -eq 0 ] || { say "needs root - skipped"; exit 0; }
if command -v systemd-detect-virt >/dev/null 2>&1 \
        && systemd-detect-virt --container >/dev/null 2>&1; then
    exit 0
fi

# The HAT's controller (0x50) must answer with its identity and a sane block.
modprobe i2c-dev 2>/dev/null || true
if ! python3 -I "$REPO/hg_hat.py" --detect >/dev/null 2>&1; then
    say "HackerGadgets Pwnagotchi HAT not detected - nothing to do"
    exit 0
fi
say "HackerGadgets Pwnagotchi HAT detected"

install_if_changed() {   # install_if_changed <mode> <src> <dst>
    local mode="$1" src="$2" dst="$3"
    [ -f "$src" ] || { say "WARNING: $src missing"; return 1; }
    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
        return 1
    fi
    mkdir -p "$(dirname "$dst")"
    install -m "$mode" "$src" "$dst" && say "installed $dst"
}

# 1a. RTC overlay. Left alone when any i2c-rtc overlay is already configured.
BOOT_CFG=""
for c in /boot/firmware/config.txt /boot/config.txt; do
    [ -f "$c" ] && { BOOT_CFG="$c"; break; }
done
if [ -n "$BOOT_CFG" ]; then
    if grep -qE '^[[:space:]]*dtoverlay=i2c-rtc' "$BOOT_CFG"; then
        say "RTC overlay already configured in $BOOT_CFG"
    else
        cp "$BOOT_CFG" "${BOOT_CFG}.ragnar-$(date +%Y%m%d-%H%M%S)"
        printf '\n[all]\n# Ragnar: HackerGadgets Pwnagotchi HAT RTC (PCF85063A at 0x51)\ndtoverlay=i2c-rtc,pcf85063a\n' >> "$BOOT_CFG"
        say "added dtoverlay=i2c-rtc,pcf85063a to $BOOT_CFG (the RTC works after the next reboot)"
    fi
else
    say "WARNING: no config.txt found - RTC overlay not added"
fi

# 2. Power-off hook.
install_if_changed 0755 "$SRC/ragnar-hg-hat-poweroff" \
    /usr/lib/systemd/system-shutdown/ragnar-hg-hat-poweroff

say "done"
exit 0
