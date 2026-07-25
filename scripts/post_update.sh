#!/bin/bash
#
# post_update.sh
#
# Everything the in-app Update button has to do *after* the new code is on
# disk, and then the service restart itself.
#
# Why this is a separate script instead of more code in webapp_modern.py:
#
#  * New commits can add Python dependencies. The web updater only ever pulled
#    code, so a box that updated from the Settings tab restarted into a service
#    that could not import its own modules - a crash loop with no web UI left to
#    fix it from. The CLI updater has always installed requirements; now both do.
#  * The restart has to happen after the dependency install, not two seconds
#    after the HTTP response, or the service comes back before the packages it
#    needs exist.
#  * Anything the service spawns lives in the service's own cgroup and is killed
#    the moment systemd restarts it. Launching this through `systemd-run` puts it
#    in a transient unit of its own so it survives the restart it triggers.
#
# Writes machine-readable progress to data/logs/post_update.json so the web UI
# can show what is happening while the service is down, and a full transcript to
# data/logs/post_update.log.
#
# Usage: post_update.sh [--deps] [--no-restart] [--repo <path>]
#   --deps        also install/upgrade Python requirements (pass when
#                 requirements.txt changed in the pull - it is slow)
#   --no-restart  do the work but leave the service alone

set -uo pipefail

REPO="/home/ragnar/Ragnar"
DO_DEPS=0
DO_RESTART=1

while [ $# -gt 0 ]; do
    case "$1" in
        --deps) DO_DEPS=1 ;;
        --no-restart) DO_RESTART=0 ;;
        --repo) shift; REPO="${1:-$REPO}" ;;
        *) echo "Unknown argument: $1" >&2 ;;
    esac
    shift
done

cd "$REPO" 2>/dev/null || { echo "post_update: $REPO not found" >&2; exit 1; }

LOG_DIR="$REPO/data/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/post_update.log"
STATUS_FILE="$LOG_DIR/post_update.json"

# Keep the log from growing without bound across hundreds of updates.
if [ -f "$LOG_FILE" ] && [ "$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)" -gt 1048576 ]; then
    mv -f "$LOG_FILE" "$LOG_FILE.1" 2>/dev/null || true
fi
exec >>"$LOG_FILE" 2>&1

STEP="starting"
FAILURES=""

status() {   # status <running|finished> [ok|failed]
    local state="$1" outcome="${2:-}"
    # Written atomically: the web UI polls this file and must never read a
    # half-written one.
    cat >"$STATUS_FILE.tmp" <<EOF
{
  "state": "$state",
  "outcome": "$outcome",
  "step": "$STEP",
  "deps": $DO_DEPS,
  "restart": $DO_RESTART,
  "failures": "$(echo "$FAILURES" | tr -d '"' | tr '\n' ' ')",
  "updated_at": "$(date -Is)"
}
EOF
    mv -f "$STATUS_FILE.tmp" "$STATUS_FILE" 2>/dev/null || true
}

step() {
    STEP="$1"
    echo "[$(date -Is)] == $STEP"
    status running
}

fail() {
    FAILURES="$FAILURES$1; "
    echo "[$(date -Is)] !! $1"
}

echo "[$(date -Is)] ===== post-update run (deps=$DO_DEPS restart=$DO_RESTART) ====="
status running

# --- Python dependencies ----------------------------------------------------
if [ "$DO_DEPS" = "1" ] && [ -f "$REPO/requirements.txt" ]; then
    step "python dependencies"
    PIP_ARGS="--break-system-packages"
    # Older pip (bookworm and earlier) does not know --break-system-packages.
    pip3 install --help 2>/dev/null | grep -q -- '--break-system-packages' || PIP_ARGS=""
    if ! pip3 install $PIP_ARGS --upgrade -r "$REPO/requirements.txt"; then
        # A single unsatisfiable pin makes pip install *nothing*, silently
        # leaving every dependency at its old version. Retry one at a time so
        # one bad package cannot block the rest.
        fail "batch dependency install failed - retrying package-by-package"
        while IFS= read -r req || [ -n "$req" ]; do
            req="${req%%#*}"
            req="$(echo "$req" | xargs)"
            [ -z "$req" ] && continue
            pip3 install $PIP_ARGS --upgrade "$req" || fail "could not install $req"
        done < "$REPO/requirements.txt"
    fi
fi

# --- data files -------------------------------------------------------------
if [ -f "$REPO/init_data_files.sh" ]; then
    step "data file templates"
    bash "$REPO/init_data_files.sh" || fail "init_data_files.sh reported errors"
fi

# --- system tools and radios ------------------------------------------------
if [ -f "$REPO/scripts/provision_network_tools.sh" ]; then
    step "network tools"
    bash "$REPO/scripts/provision_network_tools.sh" || fail "network tool provisioning reported errors"
fi

# --- permissions ------------------------------------------------------------
step "permissions"
chmod +x "$REPO"/*.sh "$REPO"/*.py 2>/dev/null || true
chmod +x "$REPO"/scripts/*.sh 2>/dev/null || true
if id ragnar >/dev/null 2>&1; then
    chown -R ragnar:ragnar "$REPO" 2>/dev/null || true
fi

# --- restart ----------------------------------------------------------------
if [ "$DO_RESTART" = "1" ]; then
    step "restart"
    if [ -n "$FAILURES" ]; then
        status finished failed
    else
        status finished ok
    fi
    echo "[$(date -Is)] restarting ragnar.service"
    systemctl restart ragnar.service || fail "systemctl restart ragnar failed"
    exit 0
fi

STEP="done"
if [ -n "$FAILURES" ]; then
    status finished failed
    exit 1
fi
status finished ok
exit 0
