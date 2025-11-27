#!/bin/bash
# Pierre Gode 
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
STATUS_FILE="$REPO_ROOT/data/pwnagotchi_status.json"
LOG_DIR="/var/log/ragnar"
LOG_FILE="$LOG_DIR/pwnagotchi_install_$(date +%Y%m%d_%H%M%S).log"
PWN_DIR="/opt/pwnagotchi"
PWN_REPO="https://github.com/evilsocket/pwnagotchi.git"
SERVICE_FILE="/etc/systemd/system/pwnagotchi.service"
CONFIG_DIR="/etc/pwnagotchi"
CONFIG_FILE="$CONFIG_DIR/config.toml"

mkdir -p "$LOG_DIR"
mkdir -p "$REPO_ROOT/data"

touch "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

write_status() {
    local state="$1"
    local message="$2"
    local phase="$3"
    cat >"$STATUS_FILE" <<EOF
{
    "state": "${state}",
    "message": "${message}",
    "phase": "${phase}",
    "timestamp": "$(date -Iseconds)",
    "log_file": "${LOG_FILE}",
    "service_file": "${SERVICE_FILE}",
    "config_file": "${CONFIG_FILE}",
    "repo_dir": "${PWN_DIR}"
}
EOF
}

trap 'write_status "error" "Installation failed (line ${LINENO}). Check ${LOG_FILE}." "error"' ERR

if [[ $EUID -ne 0 ]]; then
    echo "This installer must be run as root."
    exit 1
fi

write_status "installing" "Starting Pwnagotchi installation" "preflight"
echo "[INFO] Beginning Pwnagotchi installation..."

echo "[INFO] Updating apt repositories"
apt-get update -y

packages=(
    git
    python3
    python3-pip
    python3-setuptools
    python3-dev
    libpcap-dev
    libatlas-base-dev
    libffi-dev
    libssl-dev
    libcap2-bin
    python3-smbus
    i2c-tools
)

optional_packages=(
    bettercap
    hcxdumptool
    hcxtools
)

echo "[INFO] Installing required packages"
apt-get install -y "${packages[@]}"

if [[ ${#optional_packages[@]} -gt 0 ]]; then
    echo "[INFO] Installing optional wireless tools"
    for pkg in "${optional_packages[@]}"; do
        if ! apt-get install -y "$pkg"; then
            echo "[WARN] Optional package $pkg failed to install"
        fi
    done
fi

write_status "installing" "System packages installed" "dependencies"

echo "[INFO] Upgrading pip"
if ! python3 -m pip install --upgrade pip; then
    echo "[WARN] Unable to upgrade pip automatically. Continuing with existing version."
fi

pip_flags=("--no-cache-dir" "--upgrade")
if python3 -m pip install --help 2>&1 | grep -q "break-system-packages"; then
    pip_flags+=("--break-system-packages")
fi

write_status "installing" "Installing Pwnagotchi python package" "python"
python3 -m pip install "${pip_flags[@]}" pwnagotchi

echo "[INFO] Ensuring repository at ${PWN_DIR}"
if [[ -d "$PWN_DIR/.git" ]]; then
    git -C "$PWN_DIR" pull --ff-only
else
    rm -rf "$PWN_DIR"
    git clone "$PWN_REPO" "$PWN_DIR"
fi

mkdir -p "$CONFIG_DIR" "$CONFIG_DIR/conf.d" "$CONFIG_DIR/custom_plugins"
if [[ ! -f "$CONFIG_FILE" ]]; then
    cat >"$CONFIG_FILE" <<'EOF'
main.name = "RagnarPwn"
main.confd = "/etc/pwnagotchi/conf.d"
main.custom_plugins = "/etc/pwnagotchi/custom_plugins"
ui.display.enabled = false
ui.web.enabled = true
ui.web.username = "ragnar"
ui.web.password = "ragnar"
plugins.grid.enabled = false
EOF
    echo "[INFO] Created default config at ${CONFIG_FILE}"
fi

cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=Pwnagotchi Mode Service
After=multi-user.target network.target

[Service]
Type=simple
ExecStart=/usr/bin/env python3 -m pwnagotchi --config ${CONFIG_FILE}
WorkingDirectory=${PWN_DIR}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SERVICE_FILE"
systemctl daemon-reload
systemctl disable pwnagotchi >/dev/null 2>&1 || true
systemctl stop pwnagotchi >/dev/null 2>&1 || true

write_status "installed" "Pwnagotchi installed. Use Ragnar dashboard to launch." "complete"
echo "[INFO] Installation complete. Service disabled until manually started."
