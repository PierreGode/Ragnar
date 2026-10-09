#!/bin/bash
#
# set_display_mode.sh — switch ragnar.service between HEADLESS and DISPLAY mode,
# and persist the chosen display driver. Single source of truth for the mode
# switch, used by:
#   * scripts/ragnar-firstboot.sh   (ragnar.conf  display= at first boot)
#   * the AP onboarding portal       (/api/wifi/connect  "display" field)
#   * the web UI                     (Config -> Display)
#
# Ragnar has two entrypoints by design: headlessRagnar.py (never touches the
# EPD/GPIO — SharedData() builds the display at import time) and Ragnar.py (full
# display mode). The mode therefore lives in the systemd unit's ExecStart, not
# in a runtime flag, so switching means rewriting the unit. Keeping that in one
# place stops the installer, firstboot and the web UI from drifting apart.
#
# Usage:
#   set_display_mode.sh headless            [--no-restart]
#   set_display_mode.sh display <epd_type>  [--no-restart]
#
# Rewrites /etc/systemd/system/ragnar.service to match install_ragnar.sh, writes
# epd_type + display_enabled into config/shared_config.json (and mirrors epd_type
# into shared.py's default), daemon-reloads, and restarts the service unless
# --no-restart is given. Idempotent and safe to re-run.

set -u

RAGNAR_USER="ragnar"
RAGNAR_PATH="${RAGNAR_PATH:-/home/${RAGNAR_USER}/Ragnar}"
UNIT="${RAGNAR_UNIT:-/etc/systemd/system/ragnar.service}"
LOG_TAG="ragnar-display-mode"

log() { logger -t "$LOG_TAG" -- "$*" 2>/dev/null; echo "[$LOG_TAG] $*"; }

MODE="${1:-}"
EPD=""
RESTART=1
# Parse remaining args: an epd_type (for display mode) and/or --no-restart.
shift || true
for arg in "$@"; do
    case "$arg" in
        --no-restart) RESTART=0 ;;
        *) [ -z "$EPD" ] && EPD="$arg" ;;
    esac
done

case "$MODE" in
    headless) ENTRYPOINT="headlessRagnar.py" ;;
    display)
        ENTRYPOINT="Ragnar.py"
        if [ -z "$EPD" ]; then
            log "display mode needs an epd_type (e.g. epd2in13_V4)"; exit 2
        fi
        ;;
    *)
        echo "usage: $0 headless|display [epd_type] [--no-restart]" >&2
        exit 2
        ;;
esac

if [ ! -f "$UNIT" ]; then
    log "ragnar.service unit not found at $UNIT — nothing to switch"; exit 1
fi

# ── Persist the display driver + mode into config ───────────────────────────
if [ "$MODE" = "display" ]; then
    CONF_JSON="$RAGNAR_PATH/config/shared_config.json"
    mkdir -p "$(dirname "$CONF_JSON")"
    python3 - "$CONF_JSON" "$EPD" <<'PY' 2>/dev/null || log "Could not write shared_config.json"
import json, os, sys
path, driver = sys.argv[1], sys.argv[2]
cfg = {}
if os.path.exists(path):
    try:
        with open(path) as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
cfg['epd_type'] = driver
cfg['display_enabled'] = True
with open(path, 'w') as f:
    json.dump(cfg, f, indent=4)
PY
    # Mirror into shared.py's default (used if the JSON is ever regenerated).
    [ -f "$RAGNAR_PATH/shared.py" ] && \
        sed -i "s/\"epd_type\": \"[^\"]*\"/\"epd_type\": \"$EPD\"/" "$RAGNAR_PATH/shared.py" 2>/dev/null || true
    chown -R "$RAGNAR_USER:$RAGNAR_USER" "$RAGNAR_PATH/config" 2>/dev/null || true
    log "Enabling display mode (driver '$EPD')"
else
    CONF_JSON="$RAGNAR_PATH/config/shared_config.json"
    if [ -f "$CONF_JSON" ]; then
        python3 - "$CONF_JSON" <<'PY' 2>/dev/null || true
import json, os, sys
path = sys.argv[1]
try:
    with open(path) as f:
        cfg = json.load(f)
except Exception:
    cfg = {}
cfg['display_enabled'] = False
with open(path, 'w') as f:
    json.dump(cfg, f, indent=4)
PY
        chown -R "$RAGNAR_USER:$RAGNAR_USER" "$RAGNAR_PATH/config" 2>/dev/null || true
    fi
    log "Enabling headless mode"
fi

# ── Rewrite the systemd unit (mirrors install_ragnar.sh's setup_services) ────
{
    cat <<EOF
[Unit]
Description=ragnar Service
After=network.target

[Service]
ExecStartPre=-/bin/bash -c '${RAGNAR_PATH}/kill_port_8000.sh; ip link set mon0 down >/dev/null 2>&1; iw dev mon0 del >/dev/null 2>&1; systemctl stop pwnagotchi 2>/dev/null; systemctl stop bettercap 2>/dev/null; true'
EOF
    if [ "$MODE" = "display" ]; then
        # Wipe the panel once on start, in a separate process (GPIO pins conflict
        # if shared with Display's EPDHelper). '-' so a failure never blocks start.
        echo "ExecStartPre=-/usr/bin/python3 -OO ${RAGNAR_PATH}/wipe_epd.py"
    else
        # Make headless explicit in the unit too (the entrypoint also sets it);
        # SharedData() inits the EPD at import, which would seize SPI0/GPIO.
        echo "Environment=RAGNAR_HEADLESS=1"
    fi
    cat <<EOF
ExecStart=/usr/bin/python3 -OO ${RAGNAR_PATH}/${ENTRYPOINT}
WorkingDirectory=${RAGNAR_PATH}
StandardOutput=inherit
StandardError=inherit
Restart=always
RestartSec=3
User=root
TimeoutStopSec=5
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
} > "$UNIT"

log "Wrote $UNIT (ExecStart -> $ENTRYPOINT)"

systemctl daemon-reload 2>/dev/null || true

if [ "$RESTART" = "1" ]; then
    log "Restarting ragnar.service"
    systemctl restart ragnar.service 2>/dev/null || \
        log "Could not restart ragnar.service (it will come up on next boot)"
else
    log "Service not restarted (--no-restart); change applies on next start"
fi
