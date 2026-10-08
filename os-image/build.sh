#!/bin/bash
#
# build.sh — build the "Ragnar OS" Raspberry Pi image with pi-gen.
#
# Produces a Raspberry Pi OS (64-bit) Lite image with Ragnar preinstalled and
# enabled, ready to flash with Raspberry Pi Imager. Device-specific setup (SSH
# host keys, TLS cert, optional display/hostname/mesh) happens on first boot via
# scripts/ragnar-firstboot.sh.
#
# Usage:
#   sudo ./os-image/build.sh                 # build using docker (recommended)
#   sudo PIGEN_NATIVE=1 ./os-image/build.sh  # build natively (needs pi-gen deps)
#
# Environment overrides:
#   PIGEN_DIR        where to clone pi-gen        (default: ./os-image/.pi-gen)
#   PIGEN_REF        pi-gen git ref to pin        (default: arm64 stable branch)
#   RAGNAR_REPO_URL      Ragnar repo to clone into the image
#   RAGNAR_REPO_BRANCH   branch to bake           (default: main)
#   DEPLOY_DIR       where the .img.xz lands      (default: pi-gen/deploy)
#
# The build needs ~10 GB free disk and internet (debootstrap + apt + pip).

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

PIGEN_DIR="${PIGEN_DIR:-$HERE/.pi-gen}"
PIGEN_REPO="https://github.com/RPi-Distro/pi-gen.git"
# Pin to a known-good arm64 branch. pi-gen builds arm64 from the 'arm64' branch.
PIGEN_REF="${PIGEN_REF:-arm64}"

export RAGNAR_REPO_URL="${RAGNAR_REPO_URL:-https://github.com/PierreGode/Ragnar.git}"
export RAGNAR_REPO_BRANCH="${RAGNAR_REPO_BRANCH:-main}"

if [ "$(id -u)" -ne 0 ]; then
    echo "This build must run as root (pi-gen uses chroot/loop devices)." >&2
    echo "Re-run with: sudo $0" >&2
    exit 1
fi

echo "=== Ragnar OS image build ==="
echo "    pi-gen:  $PIGEN_DIR ($PIGEN_REF)"
echo "    ragnar:  $RAGNAR_REPO_URL ($RAGNAR_REPO_BRANCH)"

# 1) Fetch / update pi-gen -----------------------------------------------------
if [ ! -d "$PIGEN_DIR/.git" ]; then
    echo ">>> Cloning pi-gen..."
    git clone --branch "$PIGEN_REF" --depth 1 "$PIGEN_REPO" "$PIGEN_DIR"
else
    echo ">>> Updating pi-gen..."
    git -C "$PIGEN_DIR" fetch --depth 1 origin "$PIGEN_REF"
    git -C "$PIGEN_DIR" reset --hard FETCH_HEAD
fi

# 2) Inject our stage + config -------------------------------------------------
echo ">>> Injecting Ragnar stage..."
rm -rf "$PIGEN_DIR/stage-ragnar"
cp -a "$HERE/stage-ragnar" "$PIGEN_DIR/stage-ragnar"
cp -a "$HERE/config" "$PIGEN_DIR/config"

# Only our stage should export an image; stage2 provides the base rootfs only.
touch "$PIGEN_DIR/stage2/SKIP_IMAGES"
# Don't let pi-gen build the desktop stages even if present.
[ -d "$PIGEN_DIR/stage3" ] && touch "$PIGEN_DIR/stage3/SKIP" "$PIGEN_DIR/stage3/SKIP_IMAGES"
[ -d "$PIGEN_DIR/stage4" ] && touch "$PIGEN_DIR/stage4/SKIP" "$PIGEN_DIR/stage4/SKIP_IMAGES"
[ -d "$PIGEN_DIR/stage5" ] && touch "$PIGEN_DIR/stage5/SKIP" "$PIGEN_DIR/stage5/SKIP_IMAGES"

# 3) Build ---------------------------------------------------------------------
cd "$PIGEN_DIR"
if [ "${PIGEN_NATIVE:-0}" = "1" ]; then
    echo ">>> Building natively (./build.sh)..."
    ./build.sh -c config
else
    echo ">>> Building in docker (./build-docker.sh)..."
    # PRESERVE_CONTAINER lets a failed build be retried without starting over.
    CONFIG_FILE="$PIGEN_DIR/config" PRESERVE_CONTAINER=1 ./build-docker.sh
fi

# 4) Report --------------------------------------------------------------------
DEPLOY_DIR="${DEPLOY_DIR:-$PIGEN_DIR/deploy}"
echo ""
echo "=== Build complete ==="
echo "Images in: $DEPLOY_DIR"
ls -lh "$DEPLOY_DIR"/*.img.xz 2>/dev/null || \
    echo "(no .img.xz found — check the build log above)"
