#!/usr/bin/env bash
# install_sensing.sh — Provision Ragnar's WiFi-CSI sensing backend.
#
# Ragnar bundles the sensing-server engine so it runs standalone — no separate
# RuView checkout required. Hybrid strategy:
#   * arm64 (Raspberry Pi): install the prebuilt binary vendored at bin/sensing-server.
#   * other arches OR `--rebuild`: install Rust and compile from the pinned RuView source.
# Then it installs + starts a systemd service (ragnar-sensing.service) and steps
# aside any pre-existing external RuView unit so the ports don't clash.
#
# Safe to re-run (idempotent). All output is tee'd to the install log so the
# config page can stream progress.
set -euo pipefail

# ── Paths & constants ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAGNAR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENDORED_BIN="$RAGNAR_DIR/bin/sensing-server"
INSTALL_BIN="/usr/local/bin/ragnar-sensing-server"
UNIT_NAME="ragnar-sensing.service"
UNIT_PATH="/etc/systemd/system/$UNIT_NAME"
UI_PATH="$RAGNAR_DIR/web/rusense"
LOG_FILE="${SENSING_INSTALL_LOG:-$RAGNAR_DIR/data/sensing_install.log}"

# RuView source (only used for the build-from-source fallback). Pinned so a
# rebuild is reproducible and can't drift under us.
RUVIEW_REPO="${RUVIEW_REPO:-https://github.com/PierreGode/RuView.git}"
RUVIEW_PIN="${RUVIEW_PIN:-9452f774d42f3abe9124b8e643473c9100ee8777}"
RUVIEW_CRATE="wifi-densepose-sensing-server"

# Runtime tuning (matches the validated working deployment).
HTTP_PORT="${SENSING_HTTP_PORT:-3000}"
WS_PORT="${SENSING_WS_PORT:-3100}"
UDP_PORT="${SENSING_UDP_PORT:-5005}"
# UDP CSI-receiver bind address. Newer sensing-server (ADR-296) defaults the UDP
# data plane to loopback-only (127.0.0.1) and drops LAN senders unless the
# routable bind is opted into. Ragnar's ESP32 nodes send CSI from the LAN, so
# bind the routable address by default. Prefer a source allowlist
# (SENSING_UDP_ALLOW="192.168.1.0/24" — comma-separated CIDRs); with none set we
# fall back to --udp-insecure-lan, which reproduces the prior accept-any-source
# behavior (the appliance sits on a trusted local net; the UDP plane is
# unauthenticated either way). Set SENSING_UDP_BIND=127.0.0.1 to hard-disable.
UDP_BIND="${SENSING_UDP_BIND:-0.0.0.0}"
UDP_ALLOW="${SENSING_UDP_ALLOW:-}"
# Coarse Observatory localization: the per-room node geometry (metres),
# "x,y,z;x,y,z;..." ordered by ascending node_id from 1. When set, the blob
# drifts toward whichever node flares most above its own baseline. Unset =
# off (blob falls back to the centred field peak). SENSING_LOCALIZE_POWER
# sharpens the pull (default 2). Both are persisted as a drop-in so the
# config UI / manual edits can retune without a reinstall.
NODE_POSITIONS="${SENSING_NODE_POSITIONS:-}"
LOCALIZE_POWER="${SENSING_LOCALIZE_POWER:-2}"
TICK_MS="${SENSING_TICK_MS:-500}"
SOURCE="${SENSING_SOURCE:-esp32}"
RUN_USER="${SENSING_RUN_USER:-$(stat -c '%U' "$RAGNAR_DIR")}"

REBUILD=0
[ "${1:-}" = "--rebuild" ] && REBUILD=1

mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

log()  { echo "[install_sensing] $*"; }
fail() { echo "[install_sensing][ERROR] $*" >&2; exit 1; }
as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }
as_user() { local u="$1"; shift; if [ "$(id -un)" = "$u" ]; then "$@"; else sudo -u "$u" -H "$@"; fi; }

log "=== Ragnar sensing backend install $(date -u +%FT%TZ) ==="
log "Ragnar dir : $RAGNAR_DIR"
log "Run user   : $RUN_USER"
log "Arch       : $(uname -m)   rebuild=$REBUILD"

# ── 1. Obtain the binary ─────────────────────────────────────────────────────
ARCH="$(uname -m)"
if [ "$REBUILD" -eq 0 ] && [ "$ARCH" = "aarch64" ] && [ -x "$VENDORED_BIN" ]; then
    log "Using vendored prebuilt binary ($ARCH)."
    as_root install -m 0755 "$VENDORED_BIN" "$INSTALL_BIN"
else
    if [ "$REBUILD" -eq 1 ]; then
        log "Rebuild requested — compiling from source."
    else
        log "No prebuilt binary for arch '$ARCH' — compiling from source."
    fi

    # Ensure a Rust toolchain (install rustup for RUN_USER if missing).
    CARGO_BIN=""
    if command -v cargo >/dev/null 2>&1; then
        CARGO_BIN="$(command -v cargo)"
    elif [ -x "/home/$RUN_USER/.cargo/bin/cargo" ]; then
        CARGO_BIN="/home/$RUN_USER/.cargo/bin/cargo"
    else
        log "Installing Rust toolchain via rustup (user: $RUN_USER)…"
        as_user "$RUN_USER" bash -c \
            "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal"
        CARGO_BIN="/home/$RUN_USER/.cargo/bin/cargo"
    fi
    [ -x "$CARGO_BIN" ] || fail "cargo not available after toolchain setup"
    log "Using cargo: $CARGO_BIN"

    # Fetch pinned source (shallow) into a build cache owned by RUN_USER.
    SRC_DIR="/home/$RUN_USER/.cache/ragnar-sensing-src"
    if [ ! -d "$SRC_DIR/.git" ]; then
        as_user "$RUN_USER" git clone --filter=blob:none "$RUVIEW_REPO" "$SRC_DIR"
    fi
    as_user "$RUN_USER" git -C "$SRC_DIR" fetch --all --tags
    as_user "$RUN_USER" git -C "$SRC_DIR" checkout "$RUVIEW_PIN"

    log "Compiling $RUVIEW_CRATE (this can take a while on a Pi)…"
    as_user "$RUN_USER" bash -c \
        "cd '$SRC_DIR/v2' && '$CARGO_BIN' build --release --package '$RUVIEW_CRATE'"

    BUILT="$SRC_DIR/v2/target/release/sensing-server"
    [ -x "$BUILT" ] || fail "build did not produce $BUILT"
    # Refresh the vendored copy too so future installs are instant.
    as_root install -m 0755 "$BUILT" "$VENDORED_BIN"
    as_root install -m 0755 "$BUILT" "$INSTALL_BIN"
    log "Built and installed from source."
fi

"$INSTALL_BIN" --help >/dev/null 2>&1 || fail "$INSTALL_BIN failed to execute"
log "Binary installed at $INSTALL_BIN"

# ── 1b. Runtime data directories ─────────────────────────────────────────────
# The sensing-server writes recordings/models to data/ relative to its
# WorkingDirectory. git does not track empty directories, so on a fresh clone
# these don't exist and "recording create" fails with ENOENT (os error 2).
# Create them up front, owned by the run user. (The unit also recreates them on
# every start via ExecStartPre, so a deleted/replaced repo dir self-heals.)
as_root install -d -o "$RUN_USER" -g "$RUN_USER" \
    "$RAGNAR_DIR/data/recordings" "$RAGNAR_DIR/data/models"
# `install -d` fixes the dirs but not files inside them: root-run updates and
# backup-restores leave root-owned recordings/model files the server can then
# no longer overwrite (recording/start fails with "internal_error").
as_root chown -R "$RUN_USER:$RUN_USER" \
    "$RAGNAR_DIR/data/recordings" "$RAGNAR_DIR/data/models"
as_root chown -f "$RUN_USER:$RUN_USER" "$RAGNAR_DIR/data/adaptive_model.json" || true
log "Ensured data dirs: data/recordings, data/models (owner $RUN_USER)"

# ── 2. Step aside any external RuView unit (port conflict) ───────────────────
# Unconditional + "|| true": harmless if the unit is absent, and avoids a
# pipefail/SIGPIPE detection pitfall (grep -q closing the pipe early). This
# frees ports $HTTP_PORT/$WS_PORT/$UDP_PORT so our unit can bind them.
log "Stopping any pre-existing ruview-sensing.service to free the sensing ports."
as_root systemctl disable --now ruview-sensing.service 2>/dev/null || true

# ── 3. Install the systemd unit ──────────────────────────────────────────────
LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
HOSTNAME_SHORT="$(hostname)"
ALLOWED_HOSTS="${LAN_IP}:${HTTP_PORT},${LAN_IP},${HOSTNAME_SHORT}:${HTTP_PORT},${HOSTNAME_SHORT}.local:${HTTP_PORT}"

# Assemble the UDP bind flags (ADR-296). A loopback bind needs nothing; a
# routable bind needs either an explicit allowlist or the insecure-lan opt-in.
if [ "$UDP_BIND" = "127.0.0.1" ] || [ "$UDP_BIND" = "localhost" ]; then
    UDP_ARGS="--udp-bind $UDP_BIND"
elif [ -n "$UDP_ALLOW" ]; then
    UDP_ARGS="--udp-bind $UDP_BIND --udp-allow $UDP_ALLOW"
else
    UDP_ARGS="--udp-bind $UDP_BIND --udp-insecure-lan"
fi

log "Writing $UNIT_PATH (allowed hosts: $ALLOWED_HOSTS; udp: $UDP_ARGS)"
as_root tee "$UNIT_PATH" >/dev/null <<UNIT
[Unit]
Description=Ragnar WiFi-CSI sensing backend (bundled sensing-server)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
WorkingDirectory=$RAGNAR_DIR
# Recreate the data dirs and re-assert their ownership on every (re)start
# ('+' = run as root). Root-run updates/backup-restores leave root-owned
# files the server (User=$RUN_USER) can't overwrite — recording/start then
# fails with "internal_error" and the adaptive model can't be saved.
ExecStartPre=+/bin/sh -c 'mkdir -p $RAGNAR_DIR/data/recordings $RAGNAR_DIR/data/models && chown -R $RUN_USER:$RUN_USER $RAGNAR_DIR/data/recordings $RAGNAR_DIR/data/models; chown -f $RUN_USER:$RUN_USER $RAGNAR_DIR/data/adaptive_model.json; true'
Environment=RUST_LOG=info
Environment=SENSING_ALLOWED_HOSTS=$ALLOWED_HOSTS
# Presence floor: smoothed-motion (sm) threshold above which a node reports
# present (model-free — csi.rs raw.presence = sm > floor). 0.25 was tuned
# for the noisy AMOLED 2-node CSI (empty-room sm~0.15); clean headless
# DevKitC nodes sit near 0 empty and ~0.12 when a person moves, so 0.25
# gated real motion out. 0.10 sits between DevKitC empty (~0-0.085) and
# moving (~0.12-0.15). Tuning history: 0.10/0.13 too sensitive, 0.18 too high
# (missed the person) -> field-tested default balance is 0.15 with a 6-frame
# debounce. Narrow window = empty noise sits close to the motion signal.
# Override/retune per site via RUVIEW_PRESENCE_FLOOR / RUVIEW_DEBOUNCE_FRAMES.
Environment=RUVIEW_PRESENCE_FLOOR=0.15
Environment=RUVIEW_DEBOUNCE_FRAMES=6
Environment=RUVIEW_NODE_VOTE=0.80
Environment=RUVIEW_NONVOTING_NODES=1
# Multi-node fusion guard: WiFi/ESP-NOW-synced ESP32 nodes drift 10-150 ms
# (100 ms beacon + WiFi-MAC jitter), which blows past the engine's 60 ms default
# and makes fusion reject every frame ("Timestamp spread ... exceeds guard
# interval") -> source flips to esp32:offline. Field logs show the real-world
# spread reaching 200-330 ms, so 200 ms still rejected cycles; lift to 350 ms.
# Raising the ceiling only affects meshes that were exceeding it (they now fuse
# instead of dropping the cycle); a well-synced mesh fuses the same frames.
Environment=WDP_GUARD_INTERVAL_US=350000
ExecStart=$INSTALL_BIN --source $SOURCE --tick-ms $TICK_MS --ui-path $UI_PATH --http-port $HTTP_PORT --ws-port $WS_PORT --udp-port $UDP_PORT --bind-addr 0.0.0.0 $UDP_ARGS
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

if [ -n "$NODE_POSITIONS" ]; then
    DROPIN_DIR="/etc/systemd/system/$UNIT_NAME.d"
    as_root mkdir -p "$DROPIN_DIR"
    as_root tee "$DROPIN_DIR/node-positions.conf" >/dev/null <<DROPIN
# Coarse Observatory activity-centroid localization. Metres; ordered by
# ascending node_id from 1. Survives reinstall; retune live via the drop-in.
[Service]
Environment="SENSING_NODE_POSITIONS=$NODE_POSITIONS"
Environment=RUVIEW_LOCALIZE_POWER=$LOCALIZE_POWER
DROPIN
    log "Wrote node-positions drop-in ($NODE_POSITIONS, power $LOCALIZE_POWER)."
fi

as_root systemctl daemon-reload
as_root systemctl reset-failed "$UNIT_NAME" 2>/dev/null || true
# enable for boot, then RESTART (not `enable --now`): on an already-running
# service `enable --now` is a no-op, so a reinstall/update would copy the new
# binary + unit to disk but keep the OLD process running until a reboot. restart
# guarantees the freshly-vendored binary and unit env actually take effect now.
as_root systemctl enable "$UNIT_NAME"
as_root systemctl restart "$UNIT_NAME"

# ── 4. Verify ────────────────────────────────────────────────────────────────
sleep 2
if as_root systemctl is-active --quiet "$UNIT_NAME"; then
    log "Service active. Probing /api/v1/status…"
    if curl -s --max-time 5 "http://127.0.0.1:$HTTP_PORT/api/v1/status" | grep -q '"status"'; then
        log "Sensing backend responding on port $HTTP_PORT."
    else
        log "WARNING: service is up but /api/v1/status did not respond yet (may still be warming up)."
    fi
    log "=== INSTALL OK ==="
else
    as_root systemctl status "$UNIT_NAME" --no-pager -l | tail -20 || true
    fail "service $UNIT_NAME failed to start"
fi
