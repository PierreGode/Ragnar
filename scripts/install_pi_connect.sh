#!/bin/bash
#
# install_pi_connect.sh — install Raspberry Pi Connect (rpi-connect-lite).
#
# Ragnar integrates Pi Connect as a backup way in (Mesh tab: status + sign-in,
# see mesh_manager.pi_connect_*), but that relies on the `rpi-connect` binary
# being present. Pi Connect ships only from Raspberry Pi's own apt repo, which:
#   * isn't present on non-Raspberry-Pi-OS images (e.g. the Kali/Ulfberht base), and
#   * is signed with a key modern apt (Kali's sqv) REJECTS — the binding
#     signature uses SHA1, disallowed since 2026-02 — so `apt update` fails:
#     "The repository ... is not signed". Adding the repo therefore does NOT work
#     on Kali, and mixing a foreign repo into Kali risks later apt conflicts.
#
# So: prefer apt where the package is already available (Raspberry Pi OS), else
# download the .deb DIRECTLY from the archive over HTTPS and verify its SHA256
# before installing — no foreign repo is ever added. rpi-connect-lite's only
# Depends are init-system-helpers + dbus-user-session, already present on any
# systemd box, so `apt-get install -y ./file` resolves cleanly.
#
# Pi Connect targets Raspberry Pi hardware → ARM only (arm64/armhf); a no-op
# elsewhere. Idempotent and safe to re-run: provisioning calls it on every
# update, and it exits immediately once rpi-connect is installed. Never exits
# non-zero (a missing optional feature must not fail an update).
#
# Sign-in stays interactive via the Mesh tab (needs a Raspberry Pi account);
# this script only ensures the binary is present.

set -u

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
[ -t 1 ] || { GREEN=''; YELLOW=''; NC=''; }

say()  { echo -e "$1"; }
warn() { echo -e "${YELLOW}$1${NC}"; }

if [ "$(id -u)" -ne 0 ]; then
    warn "install_pi_connect.sh must run as root - skipping."
    exit 0
fi

if command -v rpi-connect >/dev/null 2>&1; then
    say "${GREEN}✓${NC} Raspberry Pi Connect already installed ($(rpi-connect --version 2>/dev/null | head -1))"
    exit 0
fi

ARCH="$(dpkg --print-architecture 2>/dev/null || echo unknown)"
case "$ARCH" in
    arm64|armhf) ;;
    *) say "Raspberry Pi Connect is ARM-only; skipping on ${ARCH}."; exit 0 ;;
esac

say "Installing Raspberry Pi Connect (rpi-connect-lite)..."

# 1) Raspberry Pi OS already carries the repo — let apt do it the normal way.
if apt-get install -y rpi-connect-lite >/dev/null 2>&1; then
    say "${GREEN}✓${NC} Installed rpi-connect-lite via apt."
    command -v rpi-connect >/dev/null 2>&1 && exit 0
fi

# 2) Elsewhere (Kali/Ulfberht, …): fetch + verify + install the .deb directly.
BASE="https://archive.raspberrypi.com/debian"
# Match the Debian base so the (tiny) dependency set lines up. Kali rolling and
# Debian testing/sid are trixie-era; bookworm is the stable fallback.
suite="trixie"
if [ -r /etc/os-release ]; then
    code="$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-}")"
    [ "$code" = "bookworm" ] && suite="bookworm"
fi
debmaj="$(cut -d. -f1 /etc/debian_version 2>/dev/null)"
[ "$debmaj" = "12" ] && suite="bookworm"

tmp="$(mktemp -d /tmp/piconnect.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

fetch_and_install() {
    local st="$1"
    local meta fn sha
    meta="$(curl -fsSL "${BASE}/dists/${st}/main/binary-${ARCH}/Packages.gz" 2>/dev/null | zcat 2>/dev/null \
            | awk '/^Package: rpi-connect-lite$/{f=1} f{print} f&&/^$/{exit}')"
    fn="$(printf '%s\n' "$meta" | awk '/^Filename:/{print $2; exit}')"
    sha="$(printf '%s\n' "$meta" | awk '/^SHA256:/{print $2; exit}')"
    [ -n "$fn" ] && [ -n "$sha" ] || return 1
    curl -fsSL -o "$tmp/rpi-connect-lite.deb" "${BASE}/${fn}" || return 1
    echo "${sha}  ${tmp}/rpi-connect-lite.deb" | sha256sum -c - >/dev/null 2>&1 || {
        warn "Pi Connect: checksum mismatch — refusing to install."; return 1; }
    apt-get install -y "$tmp/rpi-connect-lite.deb" >/dev/null 2>&1 || return 1
    return 0
}

if fetch_and_install "$suite" || { [ "$suite" != "bookworm" ] && fetch_and_install "bookworm"; }; then
    if command -v rpi-connect >/dev/null 2>&1; then
        say "${GREEN}✓${NC} Installed Raspberry Pi Connect ($(rpi-connect --version 2>/dev/null | head -1)). Sign in from the Mesh tab."
        exit 0
    fi
fi

warn "Could not install Raspberry Pi Connect automatically. It stays optional; Ragnar will keep showing it as not installed."
exit 0
