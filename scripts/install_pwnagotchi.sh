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

# Check available disk space (in MB)
if ! available_space=$(df /tmp 2>/dev/null | awk 'NR==2 {print int($4/1024)}'); then
    echo "[WARN] Unable to check disk space in /tmp. Proceeding with caution."
    available_space=0
fi

if [[ -n "$available_space" ]] && [[ "$available_space" -gt 0 ]]; then
    echo "[INFO] Available disk space in /tmp: ${available_space} MB"
    if [[ $available_space -lt 300 ]]; then
        echo "[ERROR] Insufficient disk space in /tmp (${available_space} MB). Need at least 300 MB."
        echo "[ERROR] /tmp appears to be a small tmpfs partition. Installation cannot proceed."
        echo "[INFO] Consider increasing tmpfs size or using a different temporary directory."
        write_status "error" "Insufficient disk space in /tmp: ${available_space} MB available, need at least 300 MB" "preflight"
        exit 1
    elif [[ $available_space -lt 500 ]]; then
        echo "[WARN] Low disk space detected in /tmp (${available_space} MB). Installation may fail."
    fi
else
    echo "[WARN] Unable to determine available disk space. Proceeding with installation."
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
    python3-full
    python3-venv
    libpcap-dev
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
    libatlas-base-dev
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

# Clean up apt cache to free disk space
echo "[INFO] Cleaning up apt cache to free disk space"
apt-get clean
rm -rf /var/cache/apt/archives/*.deb 2>/dev/null || true

write_status "installing" "System packages installed" "dependencies"

echo "[INFO] Ensuring repository at ${PWN_DIR}"
if [[ -d "$PWN_DIR/.git" ]]; then
    git -C "$PWN_DIR" pull --ff-only
else
    rm -rf "$PWN_DIR"
    git clone "$PWN_REPO" "$PWN_DIR"
fi

# Create virtual environment
VENV_DIR="$PWN_DIR/venv"
echo "[INFO] Creating virtual environment at ${VENV_DIR}"
if [[ -d "$VENV_DIR" ]]; then
    echo "[INFO] Virtual environment already exists, verifying..."
    if ! "$VENV_DIR/bin/python" --version >/dev/null 2>&1; then
        echo "[WARN] Existing virtual environment is corrupted, recreating..."
        rm -rf "$VENV_DIR"
        python3 -m venv "$VENV_DIR"
    fi
else
    python3 -m venv "$VENV_DIR"
fi

# Clean up pip cache and temporary build directories to free up space
echo "[INFO] Cleaning up pip cache and temporary build directories"
"$VENV_DIR/bin/python" -m pip cache purge 2>/dev/null || true
rm -rf /tmp/pip-* /tmp/pip-build-* /tmp/pip-install-* 2>/dev/null || true

# Upgrade pip, setuptools, and wheel to prefer pre-built wheels
echo "[INFO] Upgrading pip, setuptools, and wheel in virtual environment"
if ! "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel; then
    echo "[WARN] Unable to upgrade pip/setuptools/wheel in virtual environment. Continuing with existing version."
fi

write_status "installing" "Installing Pwnagotchi python package in virtual environment" "python"
echo "[INFO] Installing pwnagotchi in virtual environment"
# Use --no-cache-dir to avoid filling disk with cache
# Install dependencies first to allow cleanup between packages
if ! "$VENV_DIR/bin/pip" install --no-cache-dir "$PWN_DIR"; then
    echo "[ERROR] pip install failed in virtual environment"
    # Clean up on failure
    "$VENV_DIR/bin/python" -m pip cache purge 2>/dev/null || true
    rm -rf /tmp/pip-* /tmp/pip-build-* /tmp/pip-install-* 2>/dev/null || true
    exit 1
fi

# Final cleanup after successful installation
echo "[INFO] Cleaning up temporary files after installation"
"$VENV_DIR/bin/python" -m pip cache purge 2>/dev/null || true
rm -rf /tmp/pip-* /tmp/pip-build-* /tmp/pip-install-* 2>/dev/null || true

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
ExecStart=${PWN_DIR}/venv/bin/python -m pwnagotchi --config ${CONFIG_FILE}
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
