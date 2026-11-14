#!/bin/bash
# cardputer_lora_meshtastic.sh — run the CardputerZero LoRa Cap's SX1262 as a
# Meshtastic node, using meshtasticd (the Linux-native Meshtastic daemon).
# Ragnar then reaches it over TCP on 127.0.0.1:4403, like any other node.
#
#   sudo scripts/cardputer_lora_meshtastic.sh install   config + start
#   sudo scripts/cardputer_lora_meshtastic.sh remove    undo Ragnar's part
#   scripts/cardputer_lora_meshtastic.sh status
#
# It writes two files and nothing else:
#   /etc/meshtasticd/config.d/ragnar-cardputerzero-cap-lora.yaml   radio pins
#   /etc/systemd/system/meshtasticd.service.d/ragnar-cap.conf      powers the Cap
#                                                                  before start
# meshtasticd itself comes from Meshtastic's package repository. If it is not
# installed this script tries apt once and otherwise points at their guide:
#   https://meshtastic.org/docs/hardware/devices/linux-native-hardware/
# Set your region in the Meshtastic app or `meshtastic --set lora.region EU_868`
# before transmitting: the daemon stays silent until a region is chosen.

set -u

ROOT="${RAGNAR_CARDPUTER_ROOT:-}"                 # alternate root, for testing
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF_DIR="$ROOT/etc/meshtasticd/config.d"
CONF="$CONF_DIR/ragnar-cardputerzero-cap-lora.yaml"
DROPIN_DIR="$ROOT/etc/systemd/system/meshtasticd.service.d"
DROPIN="$DROPIN_DIR/ragnar-cap.conf"
GUIDE="https://meshtastic.org/docs/hardware/devices/linux-native-hardware/"

log() { echo "[cap-lora] $*"; }
have_daemon() { command -v meshtasticd >/dev/null 2>&1 || [ -n "${RAGNAR_FAKE_MESHTASTICD:-}" ]; }
sysctl_() { [ -n "$ROOT" ] || systemctl "$@" 2>/dev/null || true; }

install() {
    if ! have_daemon; then
        log "meshtasticd is not installed; trying apt"
        apt-get install -y meshtasticd >/dev/null 2>&1 || true
    fi
    if ! have_daemon; then
        log "meshtasticd is not available from this system's package sources."
        log "install it from Meshtastic's repository, then run this again:"
        log "  $GUIDE"
        return 1
    fi
    if ! python3 "$REPO/cardputer_caps.py" --prepare-lora; then
        log "the LoRa Cap did not answer. Fit it and run this again."
        [ -n "$ROOT" ] || return 1
    fi
    mkdir -p "$CONF_DIR" "$DROPIN_DIR"
    python3 "$REPO/cardputer_caps.py" --meshtasticd-config > "$CONF"
    cat > "$DROPIN" <<EOF
# Written by Ragnar. The Cap has no power until its 5 V rail is switched on,
# and its antenna path is behind an I2C switch: do both before the radio opens.
[Service]
ExecStartPre=/usr/bin/python3 $REPO/cardputer_caps.py --prepare-lora
EOF
    sysctl_ daemon-reload
    sysctl_ enable meshtasticd.service
    sysctl_ restart meshtasticd.service
    log "meshtasticd configured for the LoRa Cap ($CONF)"
    log "set a region before transmitting, e.g.: meshtastic --host 127.0.0.1 --set lora.region EU_868"
}

remove() {
    rm -f "$CONF" "$DROPIN"
    rmdir "$DROPIN_DIR" 2>/dev/null || true
    sysctl_ daemon-reload
    sysctl_ restart meshtasticd.service
    log "Ragnar's LoRa Cap settings removed (meshtasticd itself is left installed)"
}

status() {
    have_daemon && echo "meshtasticd: installed" || echo "meshtasticd: not installed"
    [ -f "$CONF" ] && echo "cap config: present" || echo "cap config: absent"
    [ -f "$DROPIN" ] && echo "power drop-in: present" || echo "power drop-in: absent"
    if [ -z "$ROOT" ]; then
        echo "service: $(systemctl is-active meshtasticd.service 2>/dev/null || echo unknown)"
    fi
}

case "${1:-}" in
    install) install ;;
    remove) remove ;;
    status) status ;;
    *) echo "usage: $0 install|remove|status"; exit 2 ;;
esac
