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
# meshtasticd is Meshtastic's firmware built for Linux: it drives the bare
# SX1262 itself, so the CardputerZero IS the node (no separate Meshtastic board
# needed). It comes from Meshtastic's package repository, which this script
# adds when the package is not installed:
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

OBS="https://download.opensuse.org/repositories/network:/Meshtastic:/beta"
KEYRING="$ROOT/etc/apt/keyrings/meshtastic.gpg"
SOURCES="$ROOT/etc/apt/sources.list.d/meshtastic.list"

# Meshtastic's repository directory for this system, e.g. Debian_12.
obs_target() {
    local id="" version="" codename="" arch
    [ -r "$ROOT/etc/os-release" ] && . "$ROOT/etc/os-release" \
        && id="${ID:-}" version="${VERSION_ID:-}" codename="${VERSION_CODENAME:-}"
    arch="$(dpkg --print-architecture 2>/dev/null || echo arm64)"
    case "$codename" in bookworm) version=12 ;; trixie) version=13 ;; esac
    case "$version" in 12|13) ;; *) version=13 ;; esac      # rolling releases track the newest
    if [ "$id" = "raspbian" ] && [ "$arch" = "armhf" ]; then
        echo "Raspbian_$version"
    else
        echo "Debian_$version"
    fi
}

add_repository() {
    local target url
    target="$(obs_target)"
    url="$OBS/$target"
    log "adding Meshtastic's package repository ($target)"
    mkdir -p "$(dirname "$KEYRING")" "$(dirname "$SOURCES")"
    if ! curl -fsSL "$url/Release.key" | gpg --dearmor > "$KEYRING.tmp" 2>/dev/null \
        || [ ! -s "$KEYRING.tmp" ]; then
        rm -f "$KEYRING.tmp"
        log "could not download the repository key (no internet?)"
        return 1
    fi
    mv "$KEYRING.tmp" "$KEYRING"
    chmod 644 "$KEYRING"
    echo "deb [signed-by=/etc/apt/keyrings/meshtastic.gpg] $url/ /" > "$SOURCES"
    apt-get update -o Dir::Etc::sourcelist="$SOURCES" -o Dir::Etc::sourceparts="-" \
        -o APT::Get::List-Cleanup="0" >/dev/null 2>&1 || apt-get update >/dev/null 2>&1 || true
}

install() {
    if ! have_daemon && [ -z "$ROOT" ]; then
        log "meshtasticd is not installed; installing it"
        DEBIAN_FRONTEND=noninteractive apt-get install -y meshtasticd >/dev/null 2>&1 || {
            add_repository && DEBIAN_FRONTEND=noninteractive apt-get install -y meshtasticd 2>&1 | tail -3
        }
    fi
    if ! have_daemon; then
        log "meshtasticd could not be installed."
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
