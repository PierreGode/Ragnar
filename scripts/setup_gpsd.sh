#!/bin/bash
# setup_gpsd.sh
# Configure gpsd so the Ragnar wardriving stack (and Kismet) consume GPS via the
# gpsd socket on localhost:2947 instead of opening the raw serial port. gps_manager
# already prefers gpsd when it is running.
#
# Two deliberate choices:
#   * DEVICES is pinned to the detected USB GPS (any NMEA puck — detection is
#     generic, not tied to a single VID:PID).
#   * USBAUTO="false" so gpsd's udev hotplug never seizes a companion ESP32
#     (Piglet/Huginn) /dev/ttyACM* port.
#
# Idempotent and best-effort: safe to re-run after swapping the GPS.

set -u

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARNING]${NC} $1"; }
err()   { echo -e "${RED}[ERROR]${NC} $1"; }

# Writing /etc/default/gpsd and managing services needs root.
if [[ $EUID -ne 0 ]]; then
    err "setup_gpsd.sh must be run as root (use sudo)"
    exit 1
fi

# gpsd itself is installed by the wardriving installer. If it's missing, bail
# softly so callers can stay best-effort.
if ! command -v gpsd >/dev/null 2>&1; then
    warn "gpsd not installed; skipping gpsd configuration"
    exit 0
fi

# Repo dir = parent of this script's dir (this script lives in scripts/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Stop gpsd before probing so (a) the serial port is free for the NMEA probe and
# (b) the detector doesn't just return the 'gpsd' sentinel for an already-running
# daemon — which would otherwise get written back as a bogus DEVICES="gpsd".
systemctl stop gpsd.socket >/dev/null 2>&1 || true
systemctl stop gpsd        >/dev/null 2>&1 || true

# Detect the GPS generically using Ragnar's own detector (keyword match on
# /dev/serial/by-id, then an NMEA probe on any non-Espressif serial). Works for
# any USB GPS, not just the u-blox 7. Empty if nothing is plugged in right now.
GPS_DEV=""
if command -v python3 >/dev/null 2>&1; then
    GPS_DEV="$(cd "$REPO_DIR" && python3 -c "from gps_manager import detect_gps_device; print(detect_gps_device() or '')" 2>/dev/null | tr -d '[:space:]')"
fi
# Guard: never pin the gpsd sentinel as a real device.
[[ "$GPS_DEV" == "gpsd" ]] && GPS_DEV=""

# Prefer a stable /dev/serial/by-id symlink so DEVICES survives a replug.
resolve_by_id() {
    local target_real link
    target_real="$(readlink -f "$1" 2>/dev/null)"
    [[ -z "$target_real" ]] && return 1
    if [[ -d /dev/serial/by-id ]]; then
        for link in /dev/serial/by-id/*; do
            [[ -e "$link" ]] || continue
            if [[ "$(readlink -f "$link")" == "$target_real" ]]; then
                echo "$link"; return 0
            fi
        done
    fi
    return 1
}

DEVICES_LINE=""
if [[ -n "$GPS_DEV" ]]; then
    if BYID="$(resolve_by_id "$GPS_DEV")"; then
        DEVICES_LINE="$BYID"
        info "GPS detected: $GPS_DEV -> $BYID"
    else
        DEVICES_LINE="$GPS_DEV"
        info "GPS detected: $GPS_DEV (no by-id symlink; pinning raw path)"
    fi
else
    warn "No USB GPS detected right now; writing gpsd config with empty DEVICES."
    warn "Re-run this script (or just start wardriving) once the GPS is plugged in."
fi

# Write /etc/default/gpsd. GPSD_OPTIONS="-n" makes gpsd poll the receiver before
# any client connects, so satellites-in-view/SNR are available while still
# searching for a fix.
info "Writing /etc/default/gpsd"
cat > /etc/default/gpsd <<EOF
# Managed by Ragnar scripts/setup_gpsd.sh — pins gpsd to the detected USB GPS.
# USBAUTO is intentionally false so gpsd never grabs a companion ESP32
# (Piglet/Huginn) /dev/ttyACM* port. Re-run setup_gpsd.sh after swapping the GPS.
START_DAEMON="true"
USBAUTO="false"
DEVICES="$DEVICES_LINE"
GPSD_OPTIONS="-n"
EOF

# Enable + (re)start. Tolerate socket-activated-only installs where gpsd.service
# is pulled in by gpsd.socket.
systemctl enable gpsd.socket  >/dev/null 2>&1 || true
systemctl enable gpsd.service >/dev/null 2>&1 || true
systemctl restart gpsd.socket >/dev/null 2>&1 || systemctl restart gpsd >/dev/null 2>&1 || true
systemctl restart gpsd.service >/dev/null 2>&1 || true

ok "gpsd configured. Verify live signal with:  cgps   or   gpsmon"
