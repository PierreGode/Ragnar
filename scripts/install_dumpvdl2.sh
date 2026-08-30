#!/usr/bin/env bash
# Ragnar: build dumpvdl2 (VDL Mode 2 / ATN decoder) + libacars from source —
# neither is packaged in Debian/Pi OS apt. libacars gives CPDLC + ADS-C decode;
# dumpvdl2 links against it. Installs to /usr/local/bin/dumpvdl2. Idempotent.
#
# On failure this prints the REAL build output (cmake/compiler errors), so a
# user can tell whether it's their Pi (missing dep, no internet, out of RAM) or
# the package. Every step logs to $LOG and the tail is echoed when a step fails.
set -u
command -v dumpvdl2 >/dev/null 2>&1 && { echo "dumpvdl2 already installed"; exit 0; }

LOG="$(mktemp /tmp/ragnar-dumpvdl2-build.XXXXXX.log)"
say(){ echo ">> $*"; }
fail(){ echo "ERROR: $*"; echo "----- last build output -------------------------------------"; tail -n 40 "$LOG" 2>/dev/null; echo "-------------------------------------------------------------"; exit 1; }

# dumpvdl2 links libacars from /usr/local — make sure this build (and the final
# binary) can find it regardless of the distro's default search paths.
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/local/lib/aarch64-linux-gnu/pkgconfig:${PKG_CONFIG_PATH:-}"
export LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH:-}"

export DEBIAN_FRONTEND=noninteractive
# Wait at most 90s for the dpkg lock instead of hanging forever if another apt /
# unattended-upgrades run holds it (a common "the install just froze").
APT_OPTS="-o DPkg::Lock::Timeout=90"
say "Installing build dependencies via apt…"
apt-get $APT_OPTS update >>"$LOG" 2>&1 || echo ">> apt-get update failed (stale mirror / offline?) — continuing, deps may already be present"
# Required to BUILD dumpvdl2: git/cmake/compiler, GLib (dumpvdl2 links glib-2.0 —
# the usual missing dep on a minimal Pi), librtlsdr (SDR), libjansson (JSON
# output). libacars pulls libxml2/zlib. All non-recommends to stay lean.
if ! apt-get $APT_OPTS install -y --no-install-recommends \
        git build-essential cmake pkg-config \
        libglib2.0-dev librtlsdr-dev libusb-1.0-0-dev \
        zlib1g-dev libxml2-dev libjansson-dev >>"$LOG" 2>&1; then
    fail "could not install build dependencies (need internet + apt). Try: sudo apt-get update"
fi
command -v cmake >/dev/null 2>&1 || fail "cmake missing after apt install"
command -v git   >/dev/null 2>&1 || fail "git missing after apt install"

JOBS="$(nproc 2>/dev/null || echo 2)"

# make with the parallel job count, and if that fails (the usual cause on a
# small Pi is the OOM killer killing cc1 mid-compile) retry single-threaded,
# which needs far less RAM. Returns non-zero only if -j1 also fails.
make_build(){  # $1 = build dir
    make -C "$1" -j"$JOBS" >>"$LOG" 2>&1 && return 0
    echo ">> parallel build failed — retrying single-threaded (low-RAM Pi?)…"
    make -C "$1" -j1 >>"$LOG" 2>&1
}

# --- libacars (CPDLC / ADS-C application-layer decode) ---------------------
if ! pkg-config --exists libacars-2 2>/dev/null && ! ldconfig -p 2>/dev/null | grep -q libacars; then
    LA="$(mktemp -d /tmp/ragnar-libacars.XXXXXX)"
    say "Building libacars (CPDLC/ADS-C decode)…"
    git clone --depth 1 https://github.com/szpajder/libacars "$LA" >>"$LOG" 2>&1 \
        || fail "git clone of libacars failed (no internet?)"
    mkdir -p "$LA/build"
    if ! ( cd "$LA/build" && cmake .. >>"$LOG" 2>&1 ) || ! make_build "$LA/build" \
         || ! ( make -C "$LA/build" install >>"$LOG" 2>&1 ); then
        rm -rf "$LA"; fail "libacars build failed (see output above — if it was killed mid-compile the Pi ran out of RAM: add a swap file and retry)"
    fi
    rm -rf "$LA"
    ldconfig 2>/dev/null || true
    say "libacars installed"
else
    say "libacars already present — reusing"
fi

# --- dumpvdl2 --------------------------------------------------------------
SRC="$(mktemp -d /tmp/ragnar-dumpvdl2.XXXXXX)"
say "Building dumpvdl2…"
git clone --depth 1 https://github.com/szpajder/dumpvdl2 "$SRC" >>"$LOG" 2>&1 \
    || { rm -rf "$SRC"; fail "git clone of dumpvdl2 failed (no internet?)"; }
mkdir -p "$SRC/build"
if ! ( cd "$SRC/build" && cmake .. >>"$LOG" 2>&1 ) || ! make_build "$SRC/build"; then
    rm -rf "$SRC"; fail "dumpvdl2 build failed (see output above — if it was killed mid-compile the Pi ran out of RAM: add a swap file and retry)"
fi
BIN="$(find "$SRC/build" -maxdepth 2 -name dumpvdl2 -type f | head -1)"
if [ -z "${BIN:-}" ] || [ ! -x "$BIN" ]; then
    rm -rf "$SRC"; fail "source build did not produce a dumpvdl2 binary"
fi
install -m 0755 "$BIN" /usr/local/bin/dumpvdl2
rm -rf "$SRC"
ldconfig 2>/dev/null || true

# Verify it runs and links libacars (so CPDLC/ADS-C + JSON output actually work).
VER="$(/usr/local/bin/dumpvdl2 --version 2>&1 | head -1)"
say "Installed /usr/local/bin/dumpvdl2 — $VER"
case "$VER" in
    *libacars*) : ;;  # good: CPDLC/ADS-C decode present
    *) echo ">> WARNING: dumpvdl2 reports no libacars — CPDLC/ADS-C won't decode. Rerun after 'sudo ldconfig'." ;;
esac
rm -f "$LOG"
exit 0
