#!/usr/bin/env bash
# Ragnar: build dumpvdl2 (VDL Mode 2 / ATN decoder) + libacars from source —
# neither is packaged in Debian/Pi OS apt. libacars gives CPDLC + ADS-C decode;
# dumpvdl2 links against it. Installs to /usr/local/bin/dumpvdl2. Idempotent.
set -u
command -v dumpvdl2 >/dev/null 2>&1 && { echo "dumpvdl2 already installed"; exit 0; }
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null 2>&1 || true
if ! apt-get install -y --no-install-recommends \
        git build-essential cmake pkg-config \
        librtlsdr-dev libusb-1.0-0-dev zlib1g-dev libxml2-dev libjansson-dev >/dev/null 2>&1; then
    echo "ERROR: could not install build dependencies (need internet + apt)"; exit 1
fi

JOBS="$(nproc 2>/dev/null || echo 2)"

# --- libacars (CPDLC / ADS-C application-layer decode) ---------------------
if ! ldconfig -p 2>/dev/null | grep -q libacars; then
    LA="$(mktemp -d /tmp/ragnar-libacars.XXXXXX)"
    trap 'rm -rf "$LA"' EXIT
    if ! git clone --depth 1 https://github.com/szpajder/libacars "$LA" >/dev/null 2>&1; then
        echo "ERROR: git clone of libacars failed (no internet?)"; exit 1
    fi
    mkdir -p "$LA/build"
    if ! ( cd "$LA/build" && cmake .. >/dev/null 2>&1 && make -j"$JOBS" >/dev/null 2>&1 && make install >/dev/null 2>&1 ); then
        echo "ERROR: libacars build failed"; exit 1
    fi
    ldconfig 2>/dev/null || true
    echo "Built and installed libacars (CPDLC/ADS-C decode)"
fi

# --- dumpvdl2 --------------------------------------------------------------
SRC="$(mktemp -d /tmp/ragnar-dumpvdl2.XXXXXX)"
trap 'rm -rf "$SRC"' EXIT
if ! git clone --depth 1 https://github.com/szpajder/dumpvdl2 "$SRC" >/dev/null 2>&1; then
    echo "ERROR: git clone of dumpvdl2 failed (no internet?)"; exit 1
fi
mkdir -p "$SRC/build"
if ( cd "$SRC/build" && cmake .. >/dev/null 2>&1 && make -j"$JOBS" >/dev/null 2>&1 ); then
    BIN="$(find "$SRC/build" -maxdepth 2 -name dumpvdl2 -type f | head -1)"
fi
if [ -n "${BIN:-}" ] && [ -x "$BIN" ]; then
    install -m 0755 "$BIN" /usr/local/bin/dumpvdl2
    ldconfig 2>/dev/null || true
    echo "Built and installed /usr/local/bin/dumpvdl2 from source"
    exit 0
fi
echo "ERROR: source build did not produce a dumpvdl2 binary"
exit 1
