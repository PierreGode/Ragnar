#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Ragnar on-screen kiosk doctor
#
# Diagnoses why the kiosk shows nothing. It answers the questions the systemd
# journal cannot: the real detail lives in the wrapper and Xorg logs, and when
# the *installer* fails there is no unit at all, so `journalctl -u ragnar-kiosk`
# is empty and people paste unrelated boot lines instead.
#
# Usage:   sudo ./scripts/kiosk_doctor.sh
#
# Output is printed AND saved to /tmp/kiosk_doctor_<timestamp>.log
# Paste the whole log back.
# ---------------------------------------------------------------------------
set -u

if [ "$(id -u)" -ne 0 ]; then exec sudo -E bash "$0" "$@"; fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOG="/tmp/kiosk_doctor_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee "$LOG") 2>&1

SERVICE="ragnar-kiosk.service"
SERVICE_FILE="/etc/systemd/system/ragnar-kiosk.service"
WRAPPER="/usr/local/bin/ragnar-kiosk-run"
LOG_DIR="/var/log/ragnar"
AUTOSTART_REL=".config/autostart/ragnar-kiosk.desktop"
CONFIG_JSON="$REPO/config/shared_config.json"

FAILED=0
section() { echo; echo "===================== $* ====================="; }
check() {   # check <label> <0|1> [hint]
    if [ "$2" -eq 0 ]; then
        echo "  [PASS] $1"
    else
        FAILED=$((FAILED + 1))
        echo "  [FAIL] $1${3:+  -> $3}"
    fi
}

echo "Ragnar kiosk doctor — $(date)"
echo "repo: $REPO"

# ---------------------------------------------------------------------------
section "1. Install state"
# ---------------------------------------------------------------------------
MODE="not_installed"
AUTOSTART_FOUND=""
for home in /home/* /root; do
    [ -f "$home/$AUTOSTART_REL" ] && AUTOSTART_FOUND="$home/$AUTOSTART_REL"
done
if [ -n "$AUTOSTART_FOUND" ]; then
    MODE="autostart"
elif [ -f "$SERVICE_FILE" ]; then
    MODE="service"
fi
echo "  mode: $MODE"
[ -n "$AUTOSTART_FOUND" ] && echo "  autostart entry: $AUTOSTART_FOUND"

if [ "$MODE" = "not_installed" ]; then
    check "Kiosk is installed" 1 "enable it in Config -> Kiosk, or run: sudo bash $REPO/scripts/install_kiosk.sh"
    echo
    echo "  Nothing is installed, so there is no unit and 'journalctl -u ragnar-kiosk'"
    echo "  will be EMPTY. If enabling from the web UI did nothing, the installer"
    echo "  itself failed — look in the Ragnar log for lines tagged [kiosk]:"
    echo "      sudo journalctl -u ragnar | grep '\[kiosk\]' | tail -30"
else
    check "Kiosk is installed ($MODE mode)" 0
fi

check "Wrapper present ($WRAPPER)" "$([ -x "$WRAPPER" ] && echo 0 || echo 1)" \
      "re-run the kiosk installer"

# ---------------------------------------------------------------------------
section "2. Browser"
# ---------------------------------------------------------------------------
BROWSER=""
for bin in chromium-browser chromium firefox-esr; do
    if command -v "$bin" >/dev/null 2>&1; then BROWSER="$bin"; break; fi
done
if [ -n "$BROWSER" ]; then
    check "Browser found ($BROWSER)" 0
    echo "        $("$BROWSER" --version 2>/dev/null | head -1)"
else
    check "Browser found" 1 "sudo apt install -y chromium-browser   (or chromium)"
fi

# ---------------------------------------------------------------------------
section "3. X stack (service mode only)"
# ---------------------------------------------------------------------------
if [ "$MODE" = "service" ]; then
    check "Xorg present" "$(command -v X >/dev/null 2>&1 && echo 0 || echo 1)" \
          "sudo apt install -y xserver-xorg xinit"
    check "xinit present" "$(command -v xinit >/dev/null 2>&1 && echo 0 || echo 1)" \
          "sudo apt install -y xinit"
    check "openbox present" "$(command -v openbox >/dev/null 2>&1 && echo 0 || echo 1)" \
          "sudo apt install -y openbox"

    # The documented Pi 5 / Bookworm crash-loop cause: non-root X needs the
    # suid wrapper, which only ships with xserver-xorg-legacy.
    WRAP=""
    for p in /usr/lib/xorg/Xorg.wrap /usr/libexec/Xorg.wrap; do
        [ -e "$p" ] && WRAP="$p"
    done
    if [ -n "$WRAP" ]; then
        check "Xorg.wrap present ($WRAP)" 0
        if [ -u "$WRAP" ]; then
            check "Xorg.wrap is suid" 0
        else
            check "Xorg.wrap is suid" 1 "sudo chmod u+s $WRAP"
        fi
    else
        check "Xorg.wrap present" 1 "sudo apt install -y xserver-xorg-legacy  (the usual Pi 5 / Bookworm crash-loop cause)"
    fi

    if [ -f /etc/X11/Xwrapper.config ]; then
        echo "  /etc/X11/Xwrapper.config:"
        sed 's/^/        /' /etc/X11/Xwrapper.config
    else
        check "Xwrapper.config exists" 1 "re-run the kiosk installer (it writes allowed_users=anybody)"
    fi
elif [ "$MODE" = "autostart" ]; then
    echo "  (skipped — autostart mode launches inside the existing desktop session)"
else
    echo "  (skipped — nothing is installed yet, so no mode has been chosen)"
fi

# ---------------------------------------------------------------------------
section "4. Service state"
# ---------------------------------------------------------------------------
if [ "$MODE" = "service" ]; then
    echo "  is-enabled: $(systemctl is-enabled "$SERVICE" 2>&1)"
    echo "  is-active : $(systemctl is-active "$SERVICE" 2>&1)"
    systemctl --no-pager --full status "$SERVICE" 2>&1 | sed 's/^/        /' | head -20
    STATE="$(systemctl is-active "$SERVICE" 2>/dev/null)"
    check "Service is active" "$([ "$STATE" = "active" ] && echo 0 || echo 1)" \
          "see the journal and wrapper log below"
    # A tripped start limit stays stopped until reset — easy to miss.
    if systemctl show "$SERVICE" -p NRestarts 2>/dev/null | grep -qv 'NRestarts=0'; then
        echo "  $(systemctl show "$SERVICE" -p NRestarts 2>/dev/null)"
        echo "        (if it hit the 5-in-2min cap: sudo systemctl reset-failed $SERVICE)"
    fi
elif [ "$MODE" = "autostart" ]; then
    RUNNING=$(pgrep -f 'ragnar-kiosk-chromium' >/dev/null 2>&1 && echo 0 || echo 1)
    check "Kiosk chromium process running" "$RUNNING" \
          "log in to the desktop session, or toggle the kiosk off/on in Config"
else
    # Counting "chromium is not running" as a failure when nothing is installed
    # just adds a second [FAIL] for the one problem already reported above.
    echo "  (skipped — nothing is installed, so nothing should be running)"
fi

# ---------------------------------------------------------------------------
section "5. Kiosk unit journal (this unit only — no unrelated boot noise)"
# ---------------------------------------------------------------------------
if [ -f "$SERVICE_FILE" ]; then
    journalctl -u "$SERVICE" --no-pager -n 40 2>&1 | sed 's/^/  /'
else
    echo "  No unit installed, so this journal does not exist."
    echo "  Installer failures are logged by Ragnar itself instead:"
    journalctl -u ragnar --no-pager -n 200 2>/dev/null | grep -i '\[kiosk\]' | tail -20 | sed 's/^/  /' \
        || echo "  (no [kiosk] lines found in the ragnar unit journal)"
fi

# ---------------------------------------------------------------------------
section "6. Wrapper log — where the real detail is"
# ---------------------------------------------------------------------------
if [ -f "$LOG_DIR/kiosk-wrapper.log" ]; then
    echo "  $LOG_DIR/kiosk-wrapper.log (last 40 lines):"
    tail -40 "$LOG_DIR/kiosk-wrapper.log" | sed 's/^/  /'
else
    check "Wrapper log exists ($LOG_DIR/kiosk-wrapper.log)" 1 \
          "the wrapper never ran — the service failed before ExecStart, see section 5"
fi

# ---------------------------------------------------------------------------
section "7. Xorg log (service mode)"
# ---------------------------------------------------------------------------
# Xorg refuses -logfile under the setuid wrapper, so a non-root kiosk leaves its
# log in the user's own directory instead. Check both, or a real X failure looks
# like "X never started".
XORG_LOGS="$LOG_DIR/kiosk-Xorg.log"
for home in /home/* /root; do
    [ -f "$home/.local/share/xorg/Xorg.0.log" ] && XORG_LOGS="$XORG_LOGS $home/.local/share/xorg/Xorg.0.log"
done
FOUND_XORG_LOG=0
for xlog in $XORG_LOGS; do
    [ -f "$xlog" ] || continue
    FOUND_XORG_LOG=1
    echo "  errors from $xlog:"
    grep -E '\(EE\)|\(WW\).*fail|no screens found|elevated privileges' "$xlog" | tail -20 | sed 's/^/  /' \
        || echo "  (no (EE) lines — X did not report an error)"
done
[ "$FOUND_XORG_LOG" -eq 0 ] && echo "  (no Xorg log — either autostart mode, or X never started)"

# ---------------------------------------------------------------------------
section "8. Display / session context"
# ---------------------------------------------------------------------------
echo "  seats/sessions:"
loginctl list-sessions --no-pager 2>&1 | sed 's/^/        /'
echo "  DRM cards: $(ls /dev/dri/card* 2>/dev/null | tr '\n' ' ' || echo 'NONE — no display hardware detected')"
if [ -z "$(ls /dev/dri/card* 2>/dev/null)" ]; then
    check "Display hardware present (/dev/dri/card*)" 1 \
          "headless box: the kiosk needs a real display (HDMI/DSI) attached"
fi
echo "  model: $(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo unknown)"
echo "  RAM  : $(awk '/^MemTotal:/{printf "%d MB", $2/1024}' /proc/meminfo 2>/dev/null)"

# ---------------------------------------------------------------------------
section "9. Configured URL"
# ---------------------------------------------------------------------------
URL="http://localhost:8000"
if [ -f "$CONFIG_JSON" ]; then
    U="$(python3 -c "import json;print(json.load(open('$CONFIG_JSON')).get('kiosk_url',''))" 2>/dev/null)"
    [ -n "$U" ] && URL="$U"
fi
echo "  kiosk_url: $URL"
if command -v curl >/dev/null 2>&1; then
    CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$URL" 2>/dev/null)"
    check "Kiosk URL reachable (HTTP $CODE)" \
          "$([ "$CODE" = "200" ] || [ "$CODE" = "302" ] && echo 0 || echo 1)" \
          "chromium will show an error page; is ragnar.service up?"
fi

# ---------------------------------------------------------------------------
section "Summary"
# ---------------------------------------------------------------------------
if [ "$FAILED" -eq 0 ]; then
    echo "  No failed checks. If the screen is still blank, the answer is in the"
    echo "  wrapper log (section 6) or the Xorg log (section 7)."
else
    echo "  $FAILED check(s) failed — fix the [FAIL] lines above, then re-run."
fi
echo
echo "Full log saved to: $LOG"
echo "Paste that file when reporting the problem."
exit 0
