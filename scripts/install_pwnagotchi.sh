#!/bin/bash
# Pierre Gode (Updated Installer - Debian 12/13 Compatible + Key Fix + pwngrid Disable)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
STATUS_FILE="$REPO_ROOT/data/pwnagotchi_status.json"
LOG_DIR="/var/log/ragnar"
LOG_FILE="$LOG_DIR/pwnagotchi_install_$(date +%Y%m%d_%H%M%S).log"
PWN_DIR="/opt/pwnagotchi"
PWN_REPO="https://github.com/PierreGode/pwnagotchi.git"
SERVICE_FILE="/etc/systemd/system/pwnagotchi.service"
CONFIG_DIR="/etc/pwnagotchi"
CONFIG_FILE="$CONFIG_DIR/config.toml"
TEMP_DIR="/home/ragnar/tmp_pwnagotchi_install"
MIN_SPACE_MB=300

mkdir -p "$LOG_DIR" "$REPO_ROOT/data" "$TEMP_DIR"

export TMPDIR="$TEMP_DIR"
export TEMP="$TEMP_DIR"
export TMP="$TEMP_DIR"

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

# -------------------------------------------------------------------
# PRECHECK
# -------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "This installer must be run as root."
    exit 1
fi

# Block installation when Ragnar is running without an e-paper display
HEADLESS_DETECTED=false
if pgrep -f "headlessRagnar.py" >/dev/null 2>&1; then
    HEADLESS_DETECTED=true
else
    if systemctl cat ragnar.service 2>/dev/null | grep -q "headlessRagnar.py"; then
        HEADLESS_DETECTED=true
    fi
fi

if [[ "$HEADLESS_DETECTED" == true ]]; then
    BLOCK_MSG="Pwnagotchi requires an e-paper display, but Ragnar is running in Headless mode. Installation is disabled."
    echo "[ERROR] ${BLOCK_MSG}"
    write_status "error" "$BLOCK_MSG" "preflight"
    exit 1
fi

write_status "installing" "Starting Pwnagotchi installation" "preflight"
echo "[INFO] Beginning Pwnagotchi installation..."

echo "[INFO] Checking disk space in $TEMP_DIR..."
available_space=$(df -m "$TEMP_DIR" | awk 'NR==2 {print $4}')
echo "[INFO] Available disk space: ${available_space} MB"

if [[ $available_space -lt $MIN_SPACE_MB ]]; then
    echo "[ERROR] Insufficient disk space (${available_space} MB). Need at least ${MIN_SPACE_MB} MB."
    write_status "error" "Insufficient disk space. Free up space and retry." "preflight"
    exit 1
fi

echo "[INFO] Updating apt repositories"
apt-get update -y

# -------------------------------------------------------------------
# SYSTEM PACKAGES
# -------------------------------------------------------------------
packages=(
    git
    python3
    python3-pip
    python3-setuptools
    python3-dev
    python3-venv
    libpcap-dev
    libffi-dev
    libssl-dev
    libcap2-bin
    python3-smbus
    i2c-tools
    libglib2.0-dev
    pkg-config
    meson
)

optional_packages=(
    bettercap
    hcxdumptool
    hcxtools
    libopenblas-dev
    liblapack-dev
)

echo "[INFO] Installing required packages..."
apt-get install -y "${packages[@]}"

echo "[INFO] Installing optional wireless tools in one batch..."
if ! apt-get install -y "${optional_packages[@]}"; then
    echo "[WARN] Optional wireless bundle had installation issues. Continuing with required packages only."
fi

write_status "installing" "System packages installed" "dependencies"

# -------------------------------------------------------------------
# CLONE REPOSITORY
# -------------------------------------------------------------------
echo "[INFO] Cloning Pwnagotchi repository to ${PWN_DIR}"
rm -rf "$PWN_DIR"
git clone "$PWN_REPO" "$PWN_DIR"

write_status "installing" "Installing Pwnagotchi from source" "python"
cd "$PWN_DIR"

# Remove packages already handled by Ragnar installer
echo "[INFO] Stripping packages already installed by Ragnar..."
sed -i '/^waveshare-epd/d' requirements.txt 2>/dev/null || true
sed -i '/^Pillow/d' requirements.txt 2>/dev/null || true
sed -i '/^spidev/d' requirements.txt 2>/dev/null || true
sed -i '/^pandas/d' requirements.txt 2>/dev/null || true
sed -i '/^smbus2/d' requirements.txt 2>/dev/null || true
sed -i '/^numpy/d' requirements.txt 2>/dev/null || true

# -------------------------------------------------------------------
# PIP + INSTALL
# -------------------------------------------------------------------
echo "[INFO] Upgrading pip..."
python3 -m pip install --upgrade --break-system-packages pip || echo "[WARN] pip upgrade skipped"

echo "[INFO] Installing Pwnagotchi dependencies..."
python3 -m pip install \
    --no-cache-dir \
    --ignore-installed \
    --break-system-packages \
    -r requirements.txt

echo "[INFO] Installing Pwnagotchi package (editable mode)..."
python3 -m pip install \
    --no-cache-dir \
    --ignore-installed \
    --break-system-packages \
    --use-pep517 \
    -e .

# -------------------------------------------------------------------
# VALIDATE + FIX /etc/pwnagotchi
# -------------------------------------------------------------------
echo "[INFO] Validating /etc/pwnagotchi directory..."

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"
chown root:root "$CONFIG_DIR"

# -------------------------------------------------------------------
# RSA KEY VALIDATION + AUTO-GENERATION
# -------------------------------------------------------------------
if [[ ! -f "$CONFIG_DIR/id_rsa" ]]; then
    echo "[INFO] Generating new RSA keypair for Pwnagotchi..."
    ssh-keygen -t rsa -b 2048 -f "$CONFIG_DIR/id_rsa" -N ""
else
    echo "[INFO] RSA private key already exists — skipping generation."
fi

chmod 600 "$CONFIG_DIR/id_rsa"
chmod 644 "$CONFIG_DIR/id_rsa.pub"

# -------------------------------------------------------------------
# CONFIG FILE SETUP
# -------------------------------------------------------------------
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

mkdir -p "$CONFIG_DIR/conf.d" "$CONFIG_DIR/custom_plugins"

# -------------------------------------------------------------------
# DISABLE PWNGIRD EXECUTION (REMOVE LOG SPAM)
# -------------------------------------------------------------------
echo "[INFO] Installing pwngrid no-op shim..."

if [[ ! -f "/usr/local/bin/pwngrid" ]]; then
    cat >/usr/local/bin/pwngrid <<'EOF'
#!/bin/bash
# Dummy pwngrid replacement to avoid log spam
exit 0
EOF
    chmod +x /usr/local/bin/pwngrid
    echo "[INFO] pwngrid shim installed."
else
    echo "[INFO] pwngrid shim already exists — skipping."
fi

# -------------------------------------------------------------------
# ENSURE LAUNCHER WRAPPER EXISTS
# -------------------------------------------------------------------
echo "[INFO] Ensuring /usr/bin/pwnagotchi-launcher wrapper exists..."
launcher_candidates=(
    "$(command -v pwnagotchi 2>/dev/null)"
    "$(command -v pwnagotchi-launcher 2>/dev/null)"
    "/usr/local/bin/pwnagotchi"
    "/usr/local/bin/pwnagotchi-launcher"
)

launcher_target=""
for candidate in "${launcher_candidates[@]}"; do
    if [[ -n "$candidate" && -x "$candidate" && "$candidate" != "/usr/bin/pwnagotchi-launcher" ]]; then
        launcher_target="$candidate"
        break
    fi
done

if [[ -n "$launcher_target" ]]; then
    cat > /usr/bin/pwnagotchi-launcher <<EOF
#!/bin/bash
exec ${launcher_target} "\$@"
EOF
    chmod 755 /usr/bin/pwnagotchi-launcher
    chown root:root /usr/bin/pwnagotchi-launcher
    echo "[INFO] Launcher wrapper points to ${launcher_target}"
else
    echo "[WARN] Could not determine pwnagotchi binary path; launcher wrapper not updated."
fi

# -------------------------------------------------------------------
# SYSTEMD SERVICE SETUP
# -------------------------------------------------------------------
cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=Pwnagotchi Mode Service
After=multi-user.target network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pwnagotchi --config ${CONFIG_FILE}
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

# -------------------------------------------------------------------
# BETTERCAP SERVICE SYNC
# -------------------------------------------------------------------
if [[ -f "/usr/bin/bettercap-launcher" ]]; then
    echo "[INFO] Ensuring bettercap launcher permissions..."
    chmod 755 /usr/bin/bettercap-launcher
else
    echo "[WARN] /usr/bin/bettercap-launcher not found; skipping chmod."
fi

if systemctl list-unit-files | grep -q '^bettercap\.service'; then
    echo "[INFO] Reloading systemd units and restarting bettercap..."
    systemctl daemon-reload
    systemctl restart bettercap
else
    echo "[WARN] bettercap.service not detected; skipping restart."
fi

# -------------------------------------------------------------------
# CLEANUP
# -------------------------------------------------------------------
echo "[INFO] Cleaning up temporary files..."
rm -rf "$TEMP_DIR"

write_status "installed" "Pwnagotchi installed. Use Ragnar dashboard to launch." "complete"
echo "[INFO] Installation complete. Service disabled until manually started."
