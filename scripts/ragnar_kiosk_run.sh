#!/bin/bash
# Ragnar kiosk wrapper — auto-detects environment:
#   * Already inside a Wayland/X session (autostart mode): just launch
#     chromium in --kiosk pointed at the configured URL.
#   * No session present (systemd service mode on Pi OS Lite): spawn our
#     own Xorg on vt7, xauth cookie, openbox WM, then chromium.
#
# Reads live config from the running Ragnar instance via /api/config so
# rotation / URL changes only require re-running the wrapper.

set -euo pipefail

REPO_ROOT="${RAGNAR_REPO:-$(cd "$(dirname "$0")/.." && pwd -P 2>/dev/null || echo /opt/ragnar)}"
CONFIG_API="http://127.0.0.1:8000/api/config"
BROWSER="${RAGNAR_BROWSER:-chromium-browser}"
if ! command -v "$BROWSER" >/dev/null 2>&1; then
    for bin in chromium-browser chromium firefox-esr; do
        if command -v "$bin" >/dev/null 2>&1; then BROWSER="$bin"; break; fi
    done
fi

LOG_DIR="${RAGNAR_KIOSK_LOG_DIR:-/var/log/ragnar}"
mkdir -p "$LOG_DIR" 2>/dev/null || true
WRAPPER_LOG="$LOG_DIR/kiosk-wrapper.log"
if : > >(tee -a "$WRAPPER_LOG" 2>/dev/null) 2>/dev/null; then
    exec > >(tee -a "$WRAPPER_LOG") 2>&1
fi
echo "[kiosk-run] start $(date -Iseconds) user=$(id -un) HOME=${HOME:-unset} DISPLAY=${DISPLAY:-unset} WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-unset} XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-unset}"

# Pi model + RAM — used to tune Chromium for low-memory boards (Pi Zero 2 W has
# only 512 MB, where Chromium OOM-crashes without the low-end flags below).
PI_MODEL="$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo unknown)"
MEM_KB="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
MEM_MB=$(( MEM_KB / 1024 ))
LOW_MEM=0
[[ "$MEM_MB" -gt 0 && "$MEM_MB" -le 1024 ]] && LOW_MEM=1
echo "[kiosk-run] board: ${PI_MODEL} | RAM: ${MEM_MB}MB | low_mem=${LOW_MEM}"

# Default config values (mirror shared.py defaults)
KIOSK_URL="http://localhost:8000"
KIOSK_ROTATION="0"
KIOSK_HIDE_CURSOR="true"
WARDRIVING_ENABLED="false"

if command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    cfg="$(curl -fsS --max-time 5 "$CONFIG_API" 2>/dev/null || true)"
    if [[ -n "$cfg" ]]; then
        parsed="$(printf '%s' "$cfg" | python3 -c '
import json, shlex, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
print("KIOSK_URL=" + shlex.quote(str(d.get("kiosk_url", "http://localhost:8000"))))
print("KIOSK_ROTATION=" + shlex.quote(str(d.get("kiosk_rotation", 0))))
print("KIOSK_HIDE_CURSOR=" + ("true" if d.get("kiosk_hide_cursor", True) else "false"))
print("KIOSK_HANDHELD=" + ("true" if d.get("kiosk_handheld", False) else "false"))
print("KIOSK_SCALE_CFG=" + shlex.quote(str(d.get("kiosk_scale", "") or "")))
print("WARDRIVING_ENABLED=" + ("true" if d.get("wardriving_enabled", False) else "false"))
' 2>/dev/null || true)"
        if [[ -n "$parsed" ]]; then eval "$parsed"; fi
    fi
fi

QS_SEP="?"
if [[ "$KIOSK_URL" == *"?"* ]]; then QS_SEP="&"; fi
FINAL_URL="${KIOSK_URL}${QS_SEP}kiosk=1"
if [[ "$WARDRIVING_ENABLED" == "true" ]]; then
    FINAL_URL="${FINAL_URL}#wardriving"
fi
echo "[kiosk-run] target URL: $FINAL_URL"

# Per-kiosk chromium profile so we don't trip "restore tabs" prompts.
PROFILE_DIR="$HOME/.config/ragnar-kiosk-chromium"
mkdir -p "$PROFILE_DIR" 2>/dev/null || true

# After a power-cut the Pi never shuts Chromium down cleanly, so it shows the
# "Restore pages? Chrome didn't shut down correctly" banner over the kiosk —
# the #1 kiosk complaint. Rewrite the last-session exit state to clean so the
# banner never appears. (--disable-session-crashed-bubble alone isn't reliable
# across Chromium versions; this is.)
PREFS="$PROFILE_DIR/Default/Preferences"
if [[ -f "$PREFS" ]]; then
    sed -i 's/"exit_type":"[^"]*"/"exit_type":"Normal"/; s/"exited_cleanly":false/"exited_cleanly":true/' "$PREFS" 2>/dev/null || true
fi
# A crash/kill leaves Chromium's singleton lock behind, which makes the *next*
# launch abort immediately — exactly what turns one failure into a restart loop.
# Clear the stale locks so a restart can actually come up.
rm -f "$PROFILE_DIR"/Singleton{Lock,Socket,Cookie} 2>/dev/null || true

# Chromium flags. Kept identical across both launch modes (session + own-X) by
# building the array once here and reusing it below.
CHROMIUM_ARGS=(
    --kiosk
    --noerrdialogs
    --disable-infobars
    --disable-translate
    --disable-features=TranslateUI,Translate
    --disable-session-crashed-bubble
    --disable-pinch
    --overscroll-history-navigation=0
    --no-first-run
    --check-for-update-interval=31536000
    --disable-dev-shm-usage
    --password-store=basic
    --user-data-dir="$PROFILE_DIR"
    --app="$FINAL_URL"
)

# Low-memory boards (Pi Zero 2 W, 512 MB): trim Chromium's footprint so it
# doesn't get OOM-killed to a black screen. Harmless on bigger Pis but only
# applied where it matters.
if [[ "$LOW_MEM" -eq 1 ]]; then
    CHROMIUM_ARGS+=(
        --enable-low-end-device-mode
        --renderer-process-limit=1
        --disable-gpu-shader-disk-cache
        --disable-features=TranslateUI,Translate,CalculateNativeWinOcclusion
    )
    echo "[kiosk-run] low-memory board — applied Chromium low-end flags"
fi

# Small square panels (e.g. the Hackberry Pi CM5's 720x720 4" TFT) read better
# with a Chromium device scale factor for bigger text/touch targets. Explicit
# RAGNAR_KIOSK_SCALE wins; otherwise the handheld config scale (Settings → Kiosk)
# applies when handheld mode is on. Unset = native rendering (unchanged default).
SCALE_EFF="${RAGNAR_KIOSK_SCALE:-}"
if [[ -z "$SCALE_EFF" && "${KIOSK_HANDHELD:-false}" == "true" && -n "${KIOSK_SCALE_CFG:-}" ]]; then
    SCALE_EFF="$KIOSK_SCALE_CFG"
fi
if [[ -n "$SCALE_EFF" ]]; then
    # Numeric-only (guards the awk range check below against injection), 0.5-3.0.
    if [[ "$SCALE_EFF" =~ ^[0-9]+(\.[0-9]+)?$ ]] && awk "BEGIN{exit !($SCALE_EFF>=0.5 && $SCALE_EFF<=3.0)}"; then
        CHROMIUM_ARGS+=( --force-device-scale-factor="$SCALE_EFF" )
        echo "[kiosk-run] device scale factor: $SCALE_EFF"
    else
        echo "[kiosk-run] WARN: ignoring invalid kiosk scale '$SCALE_EFF' (want a number 0.5-3.0)"
    fi
fi

# Input detection: decide (a) whether to force Chromium touch events, and
# (b) whether to launch an on-screen keyboard. The OSK is wanted for a touch
# screen OR a keyboardless setup — a mouse-only HDMI kiosk still needs a way to
# type (login, terminal, WiFi passphrase), clicked with the mouse. Touch DOM
# events are only forced when an actual touchscreen is present.
#   RAGNAR_KIOSK_TOUCH=on|off|auto  overrides touch detection (default auto)
#   RAGNAR_KIOSK_OSK=on|off|auto    overrides the on-screen keyboard (default auto)
TOUCH_MODE="${RAGNAR_KIOSK_TOUCH:-auto}"
OSK_MODE="${RAGNAR_KIOSK_OSK:-auto}"
TOUCH_PRESENT=0
KBD_PRESENT=0
if command -v udevadm >/dev/null 2>&1; then
    for dev in /dev/input/event*; do
        [[ -e "$dev" ]] || continue
        props="$(udevadm info --query=property --name="$dev" 2>/dev/null || true)"
        grep -q '^ID_INPUT_TOUCHSCREEN=1' <<<"$props" && TOUCH_PRESENT=1
        grep -q '^ID_INPUT_KEYBOARD=1'    <<<"$props" && KBD_PRESENT=1
    done
fi
# Device-name fallback if udev didn't classify a touchscreen.
if [[ "$TOUCH_PRESENT" -eq 0 ]] && grep -qi 'touch' /proc/bus/input/devices 2>/dev/null; then
    TOUCH_PRESENT=1
fi
case "$TOUCH_MODE" in on) TOUCH_PRESENT=1 ;; off) TOUCH_PRESENT=0 ;; esac

# On-screen keyboard wanted for a touchscreen or a keyboardless (mouse-only) box.
OSK_WANTED=0
case "$OSK_MODE" in
    on)  OSK_WANTED=1 ;;
    off) OSK_WANTED=0 ;;
    *)   { [[ "$TOUCH_PRESENT" -eq 1 ]] || [[ "$KBD_PRESENT" -eq 0 ]]; } && OSK_WANTED=1 ;;
esac

if [[ "$TOUCH_PRESENT" -eq 1 ]]; then
    # Force touch event support in the DOM (Chromium usually auto-detects, but
    # this makes tap/scroll reliable across versions and headless X starts).
    CHROMIUM_ARGS+=( --touch-events=enabled )
fi
echo "[kiosk-run] input: touchscreen=$TOUCH_PRESENT keyboard=$KBD_PRESENT -> touch_events=$TOUCH_PRESENT osk=$OSK_WANTED (touch=$TOUCH_MODE osk=$OSK_MODE)"

# Escape hatch. Chromium runs in --kiosk (locked full-screen). On a normal HDMI
# appliance with a full keyboard that's fine (Alt+F4 etc.), but on a handheld like
# the Hackberry Pi CM5 — BlackBerry keyboard, no obvious Ctrl/F-keys — it would
# trap you in the dashboard. When enabled we float a touch ✕ button in a corner
# and (on X) bind Ctrl+Alt+Q, both running ragnar_kiosk_exit.sh to close the kiosk.
#   RAGNAR_KIOSK_EXIT=on|off|auto   (default auto = on when a touchscreen is present)
#   RAGNAR_KIOSK_EXIT_CORNER=ne|nw|se|sw  (default se — clear of Ragnar's top menu)
# RAGNAR_KIOSK_EXIT env wins; otherwise auto = on for a touchscreen OR when
# handheld mode is set in Settings → Kiosk (the Hackberry CM5 case).
EXIT_MODE="${RAGNAR_KIOSK_EXIT:-auto}"
EXIT_HATCH=0
case "$EXIT_MODE" in
    on)  EXIT_HATCH=1 ;;
    off) EXIT_HATCH=0 ;;
    *)   { [[ "$TOUCH_PRESENT" -eq 1 ]] || [[ "${KIOSK_HANDHELD:-false}" == "true" ]]; } && EXIT_HATCH=1 ;;
esac
EXIT_CORNER="${RAGNAR_KIOSK_EXIT_CORNER:-se}"
# Resolve the exit scripts from the repo. In autostart mode the wrapper is run
# from its /usr/local/bin copy without RAGNAR_REPO, so REPO_ROOT can misresolve —
# fall back to the standard install path so the hatch still works after a bare
# `git pull` (older .desktop entries) without a kiosk re-install.
EXIT_SCRIPT_DIR="$REPO_ROOT/scripts"
if [[ ! -x "$EXIT_SCRIPT_DIR/ragnar_kiosk_exit.sh" && -x /home/ragnar/Ragnar/scripts/ragnar_kiosk_exit.sh ]]; then
    EXIT_SCRIPT_DIR="/home/ragnar/Ragnar/scripts"
fi
EXIT_SCRIPT="$EXIT_SCRIPT_DIR/ragnar_kiosk_exit.sh"
EXIT_BUTTON_PY="$EXIT_SCRIPT_DIR/ragnar_kiosk_exit_button.py"
echo "[kiosk-run] escape hatch: enabled=$EXIT_HATCH (mode=$EXIT_MODE corner=$EXIT_CORNER)"

# Launch the escape-hatch bits (best-effort, backgrounded — never blocks the
# kiosk). Reused by both launch modes below.
launch_exit_hatch() {
    [[ "$EXIT_HATCH" -eq 1 ]] || return 0
    [[ -x "$EXIT_SCRIPT" ]] || return 0
    # Global Ctrl+Alt+Q hotkey — X sessions only (xbindkeys can't grab keys under
    # Wayland). The touch ✕ button below is the reliable escape either way.
    if [[ -z "${WAYLAND_DISPLAY:-}" && -n "${DISPLAY:-}" ]] && command -v xbindkeys >/dev/null 2>&1; then
        local xbk; xbk="$(mktemp --tmpdir ragnar-kiosk-xbk-XXXXXX 2>/dev/null || echo /tmp/ragnar-kiosk-xbk)"
        printf '"%s"\n  control+alt + q\n' "$EXIT_SCRIPT" > "$xbk"
        echo "[kiosk-run] binding Ctrl+Alt+Q -> kiosk exit"
        xbindkeys -n -f "$xbk" >/dev/null 2>&1 &
    fi
    # Floating touch ✕ button (tkinter; works under X and XWayland).
    if command -v python3 >/dev/null 2>&1 && python3 -c 'import tkinter' >/dev/null 2>&1; then
        echo "[kiosk-run] launching on-screen exit button ($EXIT_CORNER)"
        KIOSK_EXIT_SCRIPT="$EXIT_SCRIPT" KIOSK_EXIT_CORNER="$EXIT_CORNER" \
        KIOSK_PROFILE="$PROFILE_DIR" \
            python3 "$EXIT_BUTTON_PY" >/dev/null 2>&1 &
    else
        echo "[kiosk-run] WARN: exit button wanted but python3-tk missing — Ctrl+Alt+Q (X only) still works"
    fi
}

# Launch an on-screen keyboard when wanted. Best-effort and backgrounded — never
# blocks or fails the kiosk. Wayland uses squeekboard (follows text-input focus);
# X uses matchbox-keyboard / onboard (both fully clickable with a mouse).
launch_osk() {
    [[ "${OSK_WANTED:-0}" -eq 1 ]] || return 0
    local sess="${1:-x}"
    if [[ "$sess" == "wayland" ]] && command -v squeekboard >/dev/null 2>&1; then
        echo "[kiosk-run] starting squeekboard (Wayland on-screen keyboard)"
        squeekboard >/dev/null 2>&1 &
    elif command -v matchbox-keyboard >/dev/null 2>&1; then
        echo "[kiosk-run] starting matchbox-keyboard (on-screen keyboard)"
        matchbox-keyboard >/dev/null 2>&1 &
    elif command -v onboard >/dev/null 2>&1; then
        echo "[kiosk-run] starting onboard (on-screen keyboard)"
        onboard >/dev/null 2>&1 &
    else
        echo "[kiosk-run] WARN: on-screen keyboard wanted but none installed (matchbox-keyboard/squeekboard)"
    fi
}

# Wait for Ragnar's web server to actually answer (max 60s).
for i in $(seq 1 60); do
    if curl -fsS --max-time 2 "$KIOSK_URL" >/dev/null 2>&1; then break; fi
    sleep 1
done

# ---------------------------------------------------------------------------
# MODE A: existing session — just launch chromium into it.
# Triggered when WAYLAND_DISPLAY or DISPLAY is already set (XDG autostart
# always sets these for us; the user can also invoke manually from a
# terminal inside their session).
# ---------------------------------------------------------------------------
if [[ -n "${WAYLAND_DISPLAY:-}" || -n "${DISPLAY:-}" ]]; then
    echo "[kiosk-run] running inside existing session — launching chromium directly"

    # Apply rotation via wlr-randr (labwc/wlroots) or xrandr (X session).
    case "$KIOSK_ROTATION" in
        90|180|270)
            if [[ -n "${WAYLAND_DISPLAY:-}" ]] && command -v wlr-randr >/dev/null 2>&1; then
                # wlr-randr's --transform takes: normal|90|180|270|flipped|flipped-90|...
                OUTPUT="$(wlr-randr 2>/dev/null | awk '/^[^ ]/ {print $1; exit}')"
                if [[ -n "$OUTPUT" ]]; then
                    echo "[kiosk-run] wlr-randr: rotating $OUTPUT to $KIOSK_ROTATION"
                    wlr-randr --output "$OUTPUT" --transform "$KIOSK_ROTATION" 2>&1 || true
                fi
            elif [[ -n "${DISPLAY:-}" ]] && command -v xrandr >/dev/null 2>&1; then
                case "$KIOSK_ROTATION" in
                    90) XROT=left ;; 180) XROT=inverted ;; 270) XROT=right ;;
                esac
                PRIMARY="$(xrandr --query 2>/dev/null | awk '/ connected/ {print $1; exit}')"
                if [[ -n "$PRIMARY" ]]; then
                    echo "[kiosk-run] xrandr: rotating $PRIMARY to $XROT"
                    xrandr --output "$PRIMARY" --rotate "$XROT" 2>&1 || true
                fi
            else
                echo "[kiosk-run] WARN: rotation requested but neither wlr-randr nor xrandr available"
            fi
            ;;
        *) : ;;  # 0 = no rotation
    esac

    if [[ -n "${WAYLAND_DISPLAY:-}" ]]; then launch_osk wayland; else launch_osk x; fi
    launch_exit_hatch
    exec "$BROWSER" "${CHROMIUM_ARGS[@]}"
fi

# ---------------------------------------------------------------------------
# MODE B: no session — start our own Xorg, then chromium under it.
# This is the Pi OS Lite / systemd-service path.
# ---------------------------------------------------------------------------
echo "[kiosk-run] no session env — spinning up own X server"

# We run as the (non-root) kiosk user, so starting X needs the suid Xorg.wrap.
# On Bookworm (Pi 5 default) it's absent unless xserver-xorg-legacy is installed,
# and X then exits immediately -> systemd restart loop with a bare status=1.
# Warn loudly so the journal actually says why.
if [[ "$(id -u)" -ne 0 && ! -e /usr/lib/xorg/Xorg.wrap && ! -e /usr/libexec/Xorg.wrap ]]; then
    echo "[kiosk-run] WARN: non-root X but Xorg.wrap is missing — X will likely fail." >&2
    echo "[kiosk-run] WARN: fix with: sudo apt-get install xserver-xorg-legacy" >&2
fi

XORG_LOG="$LOG_DIR/kiosk-Xorg.log"
mkdir -p "$HOME/.local/share/xorg" 2>/dev/null || true
# Where Xorg puts its log when we are NOT allowed to name one (see below). Which
# of these it picks depends on how it ended up privileged: started through the
# setuid Xorg.wrap it is really root and writes the system log, while a rootless
# X writes into the user's own directory. Check both, newest first, or a real X
# failure reads as "X never started".
xorg_own_log() {
    local newest=""
    local candidate
    for candidate in /var/log/Xorg.0.log "$HOME/.local/share/xorg/Xorg.0.log"; do
        [[ -s "$candidate" ]] || continue
        if [[ -z "$newest" || "$candidate" -nt "$newest" ]]; then
            newest="$candidate"
        fi
    done
    printf '%s' "$newest"
}
rm -f /tmp/.X0-lock 2>/dev/null || true
rm -f /tmp/.X11-unix/X0 2>/dev/null || true

export XAUTHORITY="$HOME/.Xauthority"
touch "$XAUTHORITY" 2>/dev/null || true
chmod 600 "$XAUTHORITY" 2>/dev/null || true
if command -v xauth >/dev/null 2>&1; then
    COOKIE=""
    if command -v mcookie >/dev/null 2>&1; then
        COOKIE="$(mcookie)"
    elif [[ -r /dev/urandom ]] && command -v xxd >/dev/null 2>&1; then
        COOKIE="$(head -c 16 /dev/urandom | xxd -p)"
    else
        COOKIE="$(od -An -tx1 -N16 /dev/urandom 2>/dev/null | tr -d ' \n')"
    fi
    if [[ -n "$COOKIE" ]]; then
        xauth -f "$XAUTHORITY" add ":0" . "$COOKIE" 2>/dev/null || true
    fi
fi

SESSION_SCRIPT="$(mktemp --tmpdir ragnar-kiosk-XXXXXX.sh)"
trap 'rm -f "$SESSION_SCRIPT"' EXIT
cat > "$SESSION_SCRIPT" <<EOF
#!/bin/bash
xset s off || true
xset s noblank || true
xset -dpms || true

case "$KIOSK_ROTATION" in
    90)  ROT=left ;;
    180) ROT=inverted ;;
    270) ROT=right ;;
    *)   ROT=normal ;;
esac
PRIMARY="\$(xrandr --query 2>/dev/null | awk '/ connected/ {print \$1; exit}')"
if [[ -n "\$PRIMARY" && "\$ROT" != "normal" ]]; then
    xrandr --output "\$PRIMARY" --rotate "\$ROT" || true
fi

# Plain openbox, deliberately not openbox-session. A kiosk wants a window
# manager, not a desktop: openbox-session additionally runs every XDG autostart
# entry on the box, which on a 512 MB Pi Zero 2 W is memory this cannot spare
# and which produced the alarming-looking
#   ERROR: openbox-xdg-autostart requires PyXDG to be installed
# in the kiosk log, pointing at a component the kiosk never needed.
if command -v openbox >/dev/null 2>&1; then
    openbox &
elif command -v openbox-session >/dev/null 2>&1; then
    openbox-session &
fi

if [[ "$KIOSK_HIDE_CURSOR" == "true" ]] && command -v unclutter >/dev/null 2>&1; then
    unclutter -idle 0 -root &
fi

# On-screen keyboard (this path is always X, so no squeekboard). Wanted for a
# touchscreen or a keyboardless mouse-only setup.
if [[ "$OSK_WANTED" -eq 1 ]]; then
    if command -v matchbox-keyboard >/dev/null 2>&1; then
        matchbox-keyboard >/dev/null 2>&1 &
    elif command -v onboard >/dev/null 2>&1; then
        onboard >/dev/null 2>&1 &
    fi
fi

# Kiosk escape hatch (floating ✕ button + Ctrl+Alt+Q). This path is always X, so
# both work. Values baked in by the parent; see launch_exit_hatch() there.
if [[ "$EXIT_HATCH" -eq 1 && -x "$EXIT_SCRIPT" ]]; then
    if command -v xbindkeys >/dev/null 2>&1; then
        XBK="\$(mktemp --tmpdir ragnar-kiosk-xbk-XXXXXX 2>/dev/null || echo /tmp/ragnar-kiosk-xbk)"
        printf '"%s"\n  control+alt + q\n' "$EXIT_SCRIPT" > "\$XBK"
        xbindkeys -n -f "\$XBK" >/dev/null 2>&1 &
    fi
    if command -v python3 >/dev/null 2>&1 && python3 -c 'import tkinter' >/dev/null 2>&1; then
        KIOSK_EXIT_SCRIPT="$EXIT_SCRIPT" KIOSK_EXIT_CORNER="$EXIT_CORNER" \
        KIOSK_PROFILE="$PROFILE_DIR" \
            python3 "$EXIT_BUTTON_PY" >/dev/null 2>&1 &
    fi
fi

# Same hardened Chromium flags as the session-mode launch (built by the parent).
$(declare -p CHROMIUM_ARGS)
exec "$BROWSER" "\${CHROMIUM_ARGS[@]}"
EOF
chmod +x "$SESSION_SCRIPT"

# Run X (rather than exec) so we can surface the real failure into the journal.
# A bare "Main process exited, status=1/FAILURE" restart loop is otherwise
# undebuggable remotely — here we tail the Xorg log on any non-signal exit.
_kiosk_term() { [[ -n "${XINIT_PID:-}" ]] && kill -TERM "$XINIT_PID" 2>/dev/null || true; }
trap _kiosk_term TERM INT

# Do not fight an X server that is already running.
#
# MODE A above only triggers when DISPLAY / WAYLAND_DISPLAY are set in the
# environment, and the systemd unit sets neither — so a service-mode run always
# reaches here and starts its own X on :0. On a box that has a desktop session
# (installed in service mode, then a desktop added; or session detection failed
# at install time) that display is already taken, and X dies with
#   (EE) Cannot establish any listening sockets -
#        Make sure an X server isn't already running
# on every restart until the start limit trips. That message never names the
# actual conflict, so the failure is undebuggable from the journal alone.
if pgrep -x Xorg >/dev/null 2>&1 || pgrep -x X >/dev/null 2>&1; then
    echo "[kiosk-run] ERROR: an X server is already running on this box, so the" >&2
    echo "[kiosk-run] kiosk cannot start its own on :0. This box wants AUTOSTART" >&2
    echo "[kiosk-run] mode (launch into the existing session), not service mode." >&2
    echo "[kiosk-run] Fix: disable the kiosk in Config -> Kiosk, then re-enable it" >&2
    echo "[kiosk-run] from inside the desktop session so the installer picks" >&2
    echo "[kiosk-run] autostart mode. Running X processes:" >&2
    pgrep -ax Xorg >&2 2>/dev/null || pgrep -ax X >&2 2>/dev/null || true
    exit 1
fi

# -logfile is REFUSED when Xorg runs with elevated privileges, and that is
# precisely how this path runs it: the service runs as a non-root user, so X
# only starts at all through the setuid Xorg.wrap that the installer puts there
# (xserver-xorg-legacy + needs_root_rights=yes). Under that wrapper Xorg aborts
# on sight of the flag —
#     Invalid argument -logfile with elevated privileges
# — before it opens anything, so the service died instantly with a bare
# status=1/FAILURE, no Xorg log was ever written to point at, and the restart
# loop then tripped the start limit. Let Xorg write its own log and copy that
# where the doctor expects it afterwards.
XORG_ARGS=(:0 vt7 -nolisten tcp -auth "$XAUTHORITY" -keeptty)
if [[ "$(id -u)" -eq 0 ]]; then
    # Genuine root: privileges are not "elevated", so naming the log is allowed.
    XORG_ARGS+=(-logfile "$XORG_LOG")
fi
xinit "$SESSION_SCRIPT" -- /usr/bin/X "${XORG_ARGS[@]}" &
XINIT_PID=$!
if wait "$XINIT_PID"; then rc=0; else rc=$?; fi
# Keep /var/log/ragnar/kiosk-Xorg.log as the one place to look, whichever log
# Xorg was actually allowed to write.
OWN_LOG="$(xorg_own_log)"
if [[ ! -s "$XORG_LOG" && -n "$OWN_LOG" ]]; then
    cp -f "$OWN_LOG" "$XORG_LOG" 2>/dev/null || true
fi
if [[ "$rc" -ne 0 && "$rc" -ne 143 && "$rc" -ne 130 ]]; then
    echo "[kiosk-run] X/xinit exited with code $rc — last Xorg log lines:" >&2
    tail -n 25 "$XORG_LOG" 2>/dev/null >&2 || true
    echo "[kiosk-run] full detail: $XORG_LOG and $WRAPPER_LOG" >&2
fi
exit "$rc"
