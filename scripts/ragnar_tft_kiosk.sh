#!/bin/bash
# Ragnar TFT kiosk runner — MODE-AWARE.
#
# Ragnar and its built-in Pwnagotchi mode never run at the same time: switching
# to Pwnagotchi stops ragnar.service (so :8000 goes down) and brings up the
# Pwnagotchi web UI on :8080, and switching back does the reverse. A kiosk hard-
# wired to http://localhost:8000 therefore shows a dead "can't connect" page the
# whole time you're in Pwnagotchi mode.
#
# This runner points Chromium at whichever UI is actually serving right now and
# relaunches it when you switch modes, so the on-screen display always mirrors
# the active mode with no manual intervention:
#     Ragnar mode      -> http://localhost:8000/?kiosk=1
#     Pwnagotchi mode  -> http://localhost:8080/
#
# It expects an X server to already be running (DISPLAY set) and a touch matrix /
# unclutter already applied — the kiosk-tft.service ExecStart does that, then
# execs this script. Runs as the kiosk user.
#
# Tunables (env, all optional):
#   RAGNAR_BROWSER            chromium binary (default: autodetect chromium/chromium-browser)
#   RAGNAR_TFT_RAGNAR_URL     default http://localhost:8000
#   RAGNAR_TFT_PWN_URL        default http://localhost:8080
#   RAGNAR_TFT_RAGNAR_SCALE   Chromium device scale for Ragnar (default 0.5 — dense dashboard)
#   RAGNAR_TFT_PWN_SCALE      Chromium device scale for Pwnagotchi (default 1.0 — mostly the face)
#   RAGNAR_TFT_POLL           seconds between mode checks (default 5)
#   RAGNAR_TFT_STABLE         consecutive equal reads a mode must hold before we switch
#                             to it (default 2 -> ~POLL*2s). Debounces boot-time flapping,
#                             where both modes' ports come and go while the box settles.

set -u

: "${DISPLAY:=:1}"
export DISPLAY

BROWSER="${RAGNAR_BROWSER:-}"
if [ -z "$BROWSER" ]; then
    for b in chromium chromium-browser; do
        command -v "$b" >/dev/null 2>&1 && { BROWSER="$b"; break; }
    done
fi
if [ -z "$BROWSER" ]; then
    echo "[tft-kiosk] FATAL: no chromium binary found" >&2
    exit 1
fi

RAGNAR_URL="${RAGNAR_TFT_RAGNAR_URL:-http://localhost:8000}"
PWN_URL="${RAGNAR_TFT_PWN_URL:-http://localhost:8080}"
RAGNAR_SCALE="${RAGNAR_TFT_RAGNAR_SCALE:-0.5}"
PWN_SCALE="${RAGNAR_TFT_PWN_SCALE:-1.0}"
POLL="${RAGNAR_TFT_POLL:-5}"
STABLE="${RAGNAR_TFT_STABLE:-2}"

PROFILE="${HOME:-/home/ragnar}/.config/ragnar-tft-chromium"
mkdir -p "$PROFILE" 2>/dev/null || true

# Same hardened flags the TFT kiosk has always used, minus the fixed URL/scale
# (those are chosen per mode below).
BASE_ARGS=(
    --no-sandbox
    --kiosk
    --noerrdialogs
    --disable-infobars
    --disable-session-crashed-bubble
    --disable-restore-session-state
    --disable-features=TranslateUI,Translate
    --disable-pinch
    --overscroll-history-navigation=0
    --disable-gpu
    --touch-events=enabled
    --no-first-run
    --check-for-update-interval=31536000
    --disable-dev-shm-usage
    --password-store=basic
    --user-data-dir="$PROFILE"
)

# Which UI is live right now? Prefer Ragnar; fall back to Pwnagotchi. Prints
# "<url>|<scale>", or "|" when neither answers (mid-switch — keep the last view).
pick_target() {
    if curl -fsS --max-time 2 -o /dev/null "${RAGNAR_URL}/" 2>/dev/null; then
        echo "${RAGNAR_URL}/?kiosk=1|${RAGNAR_SCALE}"
    elif curl -fsS --max-time 2 -o /dev/null "${PWN_URL}/" 2>/dev/null; then
        echo "${PWN_URL}/|${PWN_SCALE}"
    else
        echo "|"
    fi
}

launch() {
    local url="$1" scale="$2"
    # A crash/kill leaves the "restore pages?" state + a singleton lock behind;
    # clearing both keeps a relaunch from stalling or nagging over the kiosk.
    local prefs="$PROFILE/Default/Preferences"
    [ -f "$prefs" ] && sed -i \
        's/"exit_type":"[^"]*"/"exit_type":"Normal"/;s/"exited_cleanly":false/"exited_cleanly":true/' \
        "$prefs" 2>/dev/null || true
    rm -f "$PROFILE"/SingletonLock "$PROFILE"/SingletonSocket "$PROFILE"/SingletonCookie 2>/dev/null || true
    "$BROWSER" "${BASE_ARGS[@]}" --force-device-scale-factor="$scale" --app="$url" >/dev/null 2>&1 &
}

_term() { pkill -f "user-data-dir=$PROFILE" 2>/dev/null || true; exit 0; }
trap _term TERM INT

echo "[tft-kiosk] mode-aware runner: DISPLAY=$DISPLAY browser=$BROWSER ragnar=$RAGNAR_URL pwn=$PWN_URL"

# CUR  = what Chromium is currently showing
# CAND = the target seen on the last poll; CANDN = how many polls in a row
# We only (re)launch once a target has held for STABLE consecutive polls, so the
# port flapping while the box picks a mode at boot can't thrash Chromium (which
# was hammering X into the service's restart limit).
CUR=""; CAND=""; CANDN=0
while true; do
    sel="$(pick_target)"
    url="${sel%|*}"
    scale="${sel#*|}"
    if [ -n "$url" ]; then
        if [ "$sel" = "$CAND" ]; then CANDN=$((CANDN + 1)); else CAND="$sel"; CANDN=1; fi
        if [ "$sel" != "$CUR" ] && [ "$CANDN" -ge "$STABLE" ]; then
            echo "[tft-kiosk] $(date -Iseconds) -> $url (scale $scale)"
            pkill -f "user-data-dir=$PROFILE" 2>/dev/null || true
            sleep 1
            launch "$url" "$scale"
            CUR="$sel"
        fi
    fi
    sleep "$POLL"
done
