#!/usr/bin/env bash
# Ragnar: build acarsdec (ACARS VHF decoder) from source — it isn't packaged in
# Debian/Pi OS apt. Installs to /usr/local/bin/acarsdec. Idempotent.
set -u
command -v acarsdec >/dev/null 2>&1 && { echo "acarsdec already installed"; exit 0; }
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null 2>&1 || true
if ! apt-get install -y --no-install-recommends \
        git build-essential cmake pkg-config librtlsdr-dev libusb-1.0-0-dev >/dev/null 2>&1; then
    echo "ERROR: could not install build dependencies (need internet + apt)"; exit 1
fi
SRC="$(mktemp -d /tmp/ragnar-acarsdec.XXXXXX)"
trap 'rm -rf "$SRC"' EXIT
if ! git clone --depth 1 https://github.com/TLeconte/acarsdec "$SRC" >/dev/null 2>&1; then
    echo "ERROR: git clone of acarsdec failed (no internet?)"; exit 1
fi
# acarsdec uses cmake (newer) or a plain Makefile (older). Try cmake first.
if [ -f "$SRC/CMakeLists.txt" ]; then
    mkdir -p "$SRC/build"
    if ( cd "$SRC/build" && cmake -Drtl=ON .. >/dev/null 2>&1 && make -j"$(nproc 2>/dev/null || echo 2)" >/dev/null 2>&1 ); then
        BIN="$(find "$SRC/build" -maxdepth 2 -name acarsdec -type f | head -1)"
    fi
fi
if [ -z "${BIN:-}" ] && [ -f "$SRC/Makefile" ]; then
    make -C "$SRC" -j"$(nproc 2>/dev/null || echo 2)" rtl >/dev/null 2>&1 || make -C "$SRC" >/dev/null 2>&1 || true
    [ -x "$SRC/acarsdec" ] && BIN="$SRC/acarsdec"
fi
if [ -n "${BIN:-}" ] && [ -x "$BIN" ]; then
    install -m 0755 "$BIN" /usr/local/bin/acarsdec
    echo "Built and installed /usr/local/bin/acarsdec from source"
    exit 0
fi
echo "ERROR: source build did not produce an acarsdec binary"
exit 1
