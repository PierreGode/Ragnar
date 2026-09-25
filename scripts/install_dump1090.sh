#!/usr/bin/env bash
# Ragnar: install a dump1090 (ADS-B decoder) that provides the SBS stream on TCP
# 30003. dump1090-fa lives only in FlightAware's apt repo and dump1090-mutability
# was dropped after Debian buster, so on current Raspberry Pi OS / Debian apt
# usually "can't find the package". This script tries apt first, then builds a
# known-good fork from source into /usr/local/bin/dump1090. Idempotent.
set -u

have_dump() { command -v dump1090-fa >/dev/null 2>&1 || command -v dump1090-mutability >/dev/null 2>&1 || command -v dump1090 >/dev/null 2>&1; }

if have_dump; then
    echo "dump1090 already installed: $(command -v dump1090-fa dump1090-mutability dump1090 2>/dev/null | head -1)"
    exit 0
fi

export DEBIAN_FRONTEND=noninteractive

# 1) apt fast path (works where a distro actually packages it)
for pkg in dump1090-fa dump1090-mutability dump1090; do
    if apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1 && have_dump; then
        echo "Installed $pkg via apt"
        exit 0
    fi
done

# 2) build FlightAware's dump1090 from source (self-contained, no third-party repo)
echo "apt could not find a dump1090 package; building from source…"
apt-get update >/dev/null 2>&1 || true
if ! apt-get install -y --no-install-recommends \
        git build-essential pkg-config libusb-1.0-0-dev librtlsdr-dev libncurses-dev >/dev/null 2>&1; then
    echo "ERROR: could not install build dependencies (need internet + apt)"; exit 1
fi

SRC="$(mktemp -d /tmp/ragnar-dump1090.XXXXXX)"
trap 'rm -rf "$SRC"' EXIT
if ! git clone --depth 1 https://github.com/flightaware/dump1090 "$SRC" >/dev/null 2>&1; then
    echo "ERROR: git clone of flightaware/dump1090 failed (no internet?)"; exit 1
fi

# Build just the receiver binary with the RTL-SDR backend (skip bladeRF/HackRF/LimeSDR).
if ! make -C "$SRC" -j"$(nproc 2>/dev/null || echo 2)" RTLSDR=yes BLADERF=no HACKRF=no LIMESDR=no dump1090 >/dev/null 2>&1; then
    # fall back to the default target if the specific one isn't named that way
    make -C "$SRC" -j"$(nproc 2>/dev/null || echo 2)" RTLSDR=yes BLADERF=no HACKRF=no LIMESDR=no >/dev/null 2>&1 || true
fi

if [ -x "$SRC/dump1090" ]; then
    install -m 0755 "$SRC/dump1090" /usr/local/bin/dump1090
    echo "Built and installed /usr/local/bin/dump1090 from source"
    exit 0
fi

echo "ERROR: source build did not produce a dump1090 binary"
exit 1
