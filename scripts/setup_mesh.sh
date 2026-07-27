#!/bin/bash
# setup_mesh.sh — install Tailscale and (optionally) join this unit to the
# Ragnar mesh.
#
# Called from both install_ragnar.sh and update_ragnar.sh, because most users
# only ever update: a fix that lands solely in the installer never reaches the
# fleet that already exists. Everything here is idempotent — re-running it on a
# unit that is already installed and joined is a no-op that exits 0.
#
# There are three ways a unit gets onto the mesh, and this script serves all of
# them:
#
#   1. Imaging / unattended. Set RAGNAR_MESH_AUTHKEY (plus optionally
#      RAGNAR_MESH_UNIT_ID, RAGNAR_MESH_LABEL, RAGNAR_MESH_ROUTES) in the
#      environment or in /boot/ragnar-mesh.conf. The unit joins on first boot
#      with nobody logged in — the technician plugs in power and ethernet and
#      walks away.
#   2. Interactive install. The installer prompts for an auth key.
#   3. Later, from the web UI. Ragnar Mesh tab → Join mesh. This script only
#      needs to have installed the binary for that path to work.
#
# Usage:
#   setup_mesh.sh install          # install the client only, never join
#   setup_mesh.sh provision        # install, then join if a key is available
#
# Exit codes: 0 success or nothing to do, 1 install failed, 2 join failed.

set -o pipefail

MESH_TAG="${RAGNAR_MESH_TAG:-tag:ragnar-mesh}"
BOOT_CONF="/boot/ragnar-mesh.conf"
BOOT_CONF_ALT="/boot/firmware/ragnar-mesh.conf"
RAGNAR_CONFIG="${RAGNAR_CONFIG:-/home/ragnar/Ragnar/config/shared_config.json}"

mesh_log() {
    local level="$1"; shift
    if declare -F log >/dev/null 2>&1; then
        log "$level" "$*"
    else
        echo "[$level] $*"
    fi
}

# ---------------------------------------------------------------------------
# Credentials from the boot partition
# ---------------------------------------------------------------------------
# Pi Imager can write arbitrary files to the boot partition, which is the only
# place a technician-free deployment can pick up a key. The file is read once
# and then shredded: an auth key on an SD card is a credential on physical
# media, and it has no reason to outlive the join it performs.
load_boot_config() {
    local conf=""
    [ -f "$BOOT_CONF" ] && conf="$BOOT_CONF"
    [ -f "$BOOT_CONF_ALT" ] && conf="$BOOT_CONF_ALT"
    [ -z "$conf" ] && return 0

    mesh_log "INFO" "Reading mesh provisioning from $conf"
    # shellcheck disable=SC1090
    . "$conf" 2>/dev/null || {
        mesh_log "WARNING" "Could not parse $conf — ignoring it"
        return 0
    }
    BOOT_CONF_USED="$conf"
}

shred_boot_config() {
    [ -z "$BOOT_CONF_USED" ] && return 0
    if command -v shred >/dev/null 2>&1; then
        shred -u "$BOOT_CONF_USED" 2>/dev/null
    fi
    rm -f "$BOOT_CONF_USED" 2>/dev/null
    mesh_log "INFO" "Removed $BOOT_CONF_USED after use (it held a credential)"
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install_tailscale() {
    if command -v tailscale >/dev/null 2>&1; then
        mesh_log "INFO" "Tailscale already installed ($(tailscale version 2>/dev/null | head -1))"
        return 0
    fi

    mesh_log "INFO" "Installing Tailscale..."
    # The vendor script handles Debian/Ubuntu/Raspbian across architectures and
    # is what Tailscale's own docs prescribe; reimplementing repo setup per
    # distro here would be a second thing to keep correct.
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL https://tailscale.com/install.sh | sh >/dev/null 2>&1
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- https://tailscale.com/install.sh | sh >/dev/null 2>&1
    else
        mesh_log "ERROR" "Neither curl nor wget is available — cannot install Tailscale"
        return 1
    fi

    if ! command -v tailscale >/dev/null 2>&1; then
        mesh_log "ERROR" "Tailscale installation failed"
        return 1
    fi

    systemctl enable --now tailscaled >/dev/null 2>&1
    mesh_log "SUCCESS" "Tailscale installed and tailscaled enabled"
    return 0
}

# ---------------------------------------------------------------------------
# Join
# ---------------------------------------------------------------------------
already_joined() {
    local state
    state=$(tailscale status --json 2>/dev/null | grep -o '"BackendState"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1)
    case "$state" in
        *Running*) return 0 ;;
        *) return 1 ;;
    esac
}

join_mesh() {
    local key="${RAGNAR_MESH_AUTHKEY:-}"
    [ -z "$key" ] && return 0          # nothing to do; UI path stays available

    if already_joined; then
        mesh_log "INFO" "This unit is already on a tailnet — not re-joining"
        return 0
    fi

    local hostname="${RAGNAR_MESH_HOSTNAME:-}"
    if [ -z "$hostname" ] && [ -n "${RAGNAR_MESH_LABEL:-}" ]; then
        # Tailscale hostnames are DNS labels: lowercase alphanumerics and dashes.
        hostname=$(echo "$RAGNAR_MESH_LABEL" | tr '[:upper:]' '[:lower:]' \
                   | sed 's/[^a-z0-9-]\+/-/g; s/^-*//; s/-*$//')
    fi

    local args=(up --authkey "$key" --advertise-tags "$MESH_TAG" --ssh)
    [ -n "$hostname" ] && args+=(--hostname "$hostname")
    [ -n "${RAGNAR_MESH_ROUTES:-}" ] && args+=(--advertise-routes "$RAGNAR_MESH_ROUTES")

    mesh_log "INFO" "Joining the mesh${hostname:+ as $hostname}..."
    if tailscale "${args[@]}" >/dev/null 2>&1; then
        mesh_log "SUCCESS" "Unit joined the mesh"
        return 0
    fi

    # Surface the real reason rather than a bare failure — an expired or
    # already-spent key is the overwhelmingly common cause and is fixable only
    # if the operator is told which it was.
    local err
    err=$(tailscale "${args[@]}" 2>&1 | tail -3)
    mesh_log "ERROR" "Joining the mesh failed: $err"
    return 2
}

# ---------------------------------------------------------------------------
# Ragnar config
# ---------------------------------------------------------------------------
# Written with python3 rather than sed so the JSON stays valid and existing keys
# are preserved. Absent config file means a fresh install that has not booted
# yet; Ragnar will write its defaults and the UI can set these later.
apply_ragnar_config() {
    [ ! -f "$RAGNAR_CONFIG" ] && return 0
    [ -z "${RAGNAR_MESH_AUTHKEY:-}${RAGNAR_MESH_UNIT_ID:-}${RAGNAR_MESH_LABEL:-}" ] && return 0

    python3 - "$RAGNAR_CONFIG" <<'PYEOF'
import json, os, sys

path = sys.argv[1]
try:
    with open(path) as fh:
        cfg = json.load(fh)
except Exception as exc:
    print(f"[WARNING] could not read {path}: {exc}")
    sys.exit(0)

changed = False
if os.environ.get('RAGNAR_MESH_AUTHKEY'):
    if not cfg.get('mesh_enabled'):
        cfg['mesh_enabled'] = True
        changed = True

unit_id = os.environ.get('RAGNAR_MESH_UNIT_ID')
if unit_id:
    try:
        value = int(unit_id)
        if value > 0 and cfg.get('mesh_unit_id') != value:
            cfg['mesh_unit_id'] = value
            changed = True
    except ValueError:
        print(f"[WARNING] RAGNAR_MESH_UNIT_ID={unit_id!r} is not a number — ignored")

label = os.environ.get('RAGNAR_MESH_LABEL')
if label and cfg.get('mesh_site_label') != label:
    cfg['mesh_site_label'] = label
    changed = True

tag = os.environ.get('RAGNAR_MESH_TAG')
if tag and cfg.get('mesh_tag') != tag:
    cfg['mesh_tag'] = tag
    changed = True

if changed:
    tmp = path + '.tmp'
    with open(tmp, 'w') as fh:
        json.dump(cfg, fh, indent=4)
    os.replace(tmp, path)
    print('[SUCCESS] mesh settings written to Ragnar config')
else:
    print('[INFO] mesh settings already current')
PYEOF
}

# ---------------------------------------------------------------------------
main() {
    local mode="${1:-install}"

    load_boot_config

    install_tailscale || return 1

    if [ "$mode" = "provision" ]; then
        apply_ragnar_config
        join_mesh
        local rc=$?
        # Only shred once the key has actually been used, successfully or not:
        # a retained key that already failed is still a live credential.
        shred_boot_config
        return $rc
    fi

    return 0
}

main "$@"
