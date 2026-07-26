#!/bin/bash
# gps_diag.sh
# One-shot GPS diagnostic: answers "is the receiver actually getting a fix, or is
# Ragnar failing to parse one?" — the two causes of a permanent "Searching...".
#
# It briefly stops ragnar/gpsd to read the raw serial port (nothing else can hold
# it open while we sample), captures ~10 s of NMEA, then restarts ragnar. Output
# is deliberately compact so it can be pasted into a chat/issue without the
# terminal pager chopping lines.
#
# Usage:  sudo bash scripts/gps_diag.sh
#
# Reading the result:
#   * GGA fix quality >= 1, or RMC status 'A'  -> the receiver HAS a fix. If
#     Ragnar still shows "Searching", that is a parsing/plumbing bug worth
#     reporting with this output attached.
#   * GGA fix quality 0, or RMC status 'V'     -> the receiver has NO fix. That
#     is antenna/sky view, not software: a cold start needs a clear view of the
#     sky and can take several minutes.
#   * No sentences at all                      -> wrong device, wrong baud, or
#     something else is holding the port.

set -u

SECONDS_TO_SAMPLE="${1:-10}"
RAW=/tmp/ragnar_nmea.raw
OUT=/tmp/ragnar_gpsdiag.txt

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo: sudo bash scripts/gps_diag.sh" >&2
    exit 1
fi

# Pick the GPS device: prefer an explicit arg, else the first tty that is not an
# Espressif companion (a Piglet/Huginn ESP32 also shows up as /dev/ttyACM*).
pick_device() {
    for dev in /dev/ttyACM* /dev/ttyUSB*; do
        [ -e "$dev" ] || continue
        # Skip Espressif VID (303a) — that's a companion board, not a GPS.
        if udevadm info -q property -n "$dev" 2>/dev/null | grep -qi 'ID_VENDOR_ID=303a'; then
            continue
        fi
        echo "$dev"
        return
    done
}

GPSDEV="${GPSDEV:-$(pick_device)}"

# What IS this device? A silent /dev/ttyACM0 is very often not a GPS at all —
# an ESP32 companion, an LTE modem, or an Arduino enumerate the same way.
describe_device() {
    local dev="$1"
    [ -n "$dev" ] || return
    udevadm info -q property -n "$dev" 2>/dev/null | grep -E \
        '^(ID_VENDOR_ID|ID_MODEL_ID|ID_VENDOR|ID_MODEL|ID_SERIAL|ID_USB_DRIVER)=' \
        | sed 's/^/  /'
}

# Who is holding the port open? Anything still attached explains total silence.
port_holders() {
    local dev="$1"
    [ -n "$dev" ] || return
    if command -v fuser >/dev/null 2>&1; then
        fuser -v "$dev" 2>&1 | sed 's/^/  /' | head -8
    elif command -v lsof >/dev/null 2>&1; then
        lsof "$dev" 2>/dev/null | sed 's/^/  /' | head -8
    else
        echo "  (install psmisc or lsof to check)"
    fi
}

# Stop anything holding the serial port, sample, then bring ragnar back up.
systemctl stop ragnar >/dev/null 2>&1
systemctl stop gpsd.socket gpsd >/dev/null 2>&1
sleep 1
: > "$RAW"

# Probe across the common GPS baud rates and keep the best capture. On a CDC-ACM
# device baud is usually a no-op, but ttyUSB bridges (FTDI/PL2303/CP210x) care,
# and a mismatch yields either silence or binary garbage. We score by NMEA
# sentences found, falling back to raw byte count so a receiver stuck in u-blox
# UBX *binary* mode still registers as "talking" — counting lines alone reports
# a chatty binary stream as "0 lines", which is what sent us down this path.
BEST_BAUD=""
BEST_NMEA=0
BEST_BYTES=0
BAUD_REPORT=""
if [ -n "${GPSDEV:-}" ]; then
    for baud in 9600 4800 38400 57600 115200; do
        stty -F "$GPSDEV" "$baud" raw -echo -crtscts 2>/dev/null || true
        tmp=$(mktemp)
        timeout 3 cat "$GPSDEV" > "$tmp" 2>/dev/null || true
        bytes=$(wc -c < "$tmp" | tr -d ' ')
        nmea=$(grep -ac '^\$G' "$tmp" 2>/dev/null || true); nmea=${nmea:-0}
        BAUD_REPORT="${BAUD_REPORT}  ${baud}: ${bytes} bytes, ${nmea} NMEA sentences\n"
        if [ "$nmea" -gt "$BEST_NMEA" ] 2>/dev/null || \
           { [ "$BEST_NMEA" -eq 0 ] 2>/dev/null && [ "$bytes" -gt "$BEST_BYTES" ] 2>/dev/null; }; then
            BEST_BAUD="$baud"; BEST_NMEA="$nmea"; BEST_BYTES="$bytes"
            cp "$tmp" "$RAW"
        fi
        rm -f "$tmp"
    done
    # Longer capture at whichever baud looked best, for the fix verdict.
    if [ "$BEST_NMEA" -gt 0 ] 2>/dev/null; then
        stty -F "$GPSDEV" "$BEST_BAUD" raw -echo -crtscts 2>/dev/null || true
        timeout "$SECONDS_TO_SAMPLE" cat "$GPSDEV" > "$RAW" 2>/dev/null || true
    fi
fi
systemctl start ragnar >/dev/null 2>&1

{
    echo "=== Ragnar GPS diagnostic ==="
    echo "commit    : $(git -C "$(dirname "$0")/.." log --oneline -1 2>/dev/null || echo unknown)"
    echo "gps device: ${GPSDEV:-NONE FOUND}"
    echo "tty list  : $(ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null | tr '\n' ' ' || echo none)"
    echo "sampled   : $(wc -c < "$RAW" | tr -d ' ') bytes, $(wc -l < "$RAW") lines"
    echo "--- device identity ---"
    describe_device "${GPSDEV:-}"
    echo
    echo "--- baud probe (bytes / NMEA sentences per rate) ---"
    printf "%b" "${BAUD_REPORT:-  (no device probed)\n}"
    echo

    if [ ! -s "$RAW" ]; then
        echo "NO DATA on ${GPSDEV:-<no device>} at any baud rate — the port is"
        echo "open but the device sends nothing at all."
        echo
        echo "--- who is holding the port ---"
        port_holders "${GPSDEV:-}"
        echo
        echo "Most likely, in order:"
        echo "  1. This is NOT a GPS. Check 'device identity' above — an ESP32"
        echo "     companion, LTE modem or Arduino also enumerates as ttyACM0."
        echo "     A u-blox/GPS puck usually names itself in ID_VENDOR/ID_MODEL."
        echo "  2. The receiver has no power / no antenna connection. Many pucks"
        echo "     show a blinking LED only once they are transmitting."
        echo "  3. It needs DTR asserted before it will talk. Test with:"
        echo "       sudo stty -F ${GPSDEV:-/dev/ttyACM0} 9600 raw -echo"
        echo "       sudo cat ${GPSDEV:-/dev/ttyACM0}"
        echo "  4. Wrong tty — if several are listed above, retry pinning one:"
        echo "       sudo GPSDEV=/dev/ttyUSB0 bash scripts/gps_diag.sh"
        exit 0
    fi

    # Bytes arrived but no NMEA: binary mode or wrong baud. Show the raw bytes —
    # UBX frames start b5 62, garbage looks like random high bytes.
    if [ "$BEST_NMEA" -eq 0 ] 2>/dev/null; then
        echo "DATA IS ARRIVING (${BEST_BYTES} bytes at ${BEST_BAUD} baud) BUT NO NMEA."
        echo
        echo "--- first bytes (hex) ---"
        head -c 128 "$RAW" | od -A x -t x1z | head -8
        echo
        echo "If frames start with 'b5 62' the receiver is in u-blox UBX BINARY"
        echo "mode and must be switched to NMEA (u-center, or a UBX-CFG-PRT"
        echo "message). If the bytes look random, the baud rate is wrong."
        exit 0
    fi

    echo "--- sentence types seen ---"
    awk -F, '/^\$/ {print $1}' "$RAW" | sort | uniq -c | sort -rn | head -12
    echo

    echo "--- sample GGA (field 6 = fix quality: 0=no fix, 1=GPS, 2=DGPS) ---"
    grep -m3 'GGA' "$RAW" || echo "(no GGA sentences)"
    echo
    echo "--- sample RMC (field 2 = status: A=valid fix, V=void) ---"
    grep -m3 'RMC' "$RAW" || echo "(no RMC sentences)"
    echo

    # Machine-readable verdict so the answer doesn't depend on eyeballing fields.
    gga_fix=$(awk -F, '/GGA/ && $7 ~ /^[0-9]+$/ {if ($7+0 > m) m=$7+0} END {print m+0}' "$RAW")
    # grep -c exits 1 when the count is 0, so guard with `|| true` rather than a
    # `|| echo 0` fallback — the latter appends a second line to the count.
    rmc_a=$(grep -c 'RMC,[^,]*,A,' "$RAW" 2>/dev/null || true)
    rmc_a=${rmc_a:-0}
    echo "--- verdict ---"
    echo "best GGA fix quality : $gga_fix"
    echo "RMC sentences w/ 'A' : $rmc_a"
    if [ "$gga_fix" -ge 1 ] 2>/dev/null || [ "$rmc_a" -ge 1 ] 2>/dev/null; then
        echo "RECEIVER HAS A FIX. If Ragnar still shows 'Searching', it is a"
        echo "software/parsing issue — report this output."
    else
        echo "RECEIVER HAS NO FIX (searching). This is antenna / sky view, not"
        echo "software. Give it a clear view of the sky; a cold start can take"
        echo "several minutes."
    fi
} 2>&1 | tee "$OUT"

echo
echo "Saved to $OUT — paste that file's contents to share the result."
