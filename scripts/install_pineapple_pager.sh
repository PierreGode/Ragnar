#!/bin/bash
#
# install_pineapple_pager.sh - Deploy Ragnar to a WiFi Pineapple Pager
#
# This script packages Ragnar as a Pager payload and copies it to the device.
# The Pager must be accessible via SSH (default: root@172.16.42.1).
#
# Usage:
#   ./install_pineapple_pager.sh [pager-ip]
#
# Requirements:
#   - WiFi Pineapple Pager connected and accessible via SSH
#   - ssh and scp commands available
#   - PAGERCTL payload installed on the Pager (provides libpagerctl.so)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Locate the Ragnar repo root. This script lives in <repo>/scripts/ (the main
# installer and the docs call it there) but may also be run from the repo root.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "${SCRIPT_DIR}/pager/pager_menu.py" ]; then
    RAGNAR_DIR="${SCRIPT_DIR}"
elif [ -f "${SCRIPT_DIR}/../pager/pager_menu.py" ]; then
    RAGNAR_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
else
    echo "ERROR: cannot find the Ragnar repo (no pager/pager_menu.py next to or above ${SCRIPT_DIR})." >&2
    echo "       Run this script from a full Ragnar checkout." >&2
    exit 1
fi

# The Pager's USB-ethernet subnet is 172.16.<N>.0/24 with the Pager at .1, and
# <N> differs between units/firmware (42, 52, ...). If this machine has an
# address in such a subnet, offer that Pager as the default.
detect_pager_ip() {
    command -v ip >/dev/null 2>&1 || return 0
    ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 \
        | grep -E '^172\.16\.[0-9]+\.[0-9]+$' | grep -vE '\.1$' \
        | sed -E 's/\.[0-9]+$/.1/' | sort -u | head -1
}

# Configuration
if [ -z "$1" ]; then
    _detected_ip="$(detect_pager_ip)"
    _default_ip="${_detected_ip:-172.16.42.1}"
    [ -n "$_detected_ip" ] && echo "Detected a Pager USB network: ${_detected_ip}"
    read -p "Enter Pager IP address [${_default_ip}]: " _pager_ip
    PAGER_IP="${_pager_ip:-$_default_ip}"
else
    PAGER_IP="$1"
fi
PAGER_USER="root"
PAGER_PAYLOAD_DIR="/root/payloads/user/reconnaissance/pager_ragnar"

log() {
    local level=$1; shift
    case $level in
        "INFO")    echo -e "${BLUE}[INFO]${NC} $*" ;;
        "SUCCESS") echo -e "${GREEN}[OK]${NC} $*" ;;
        "WARNING") echo -e "${YELLOW}[WARN]${NC} $*" ;;
        "ERROR")   echo -e "${RED}[ERROR]${NC} $*" ;;
        *)         echo -e "$*" ;;
    esac
}

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║     Ragnar - WiFi Pineapple Pager Installer          ║"
echo "  ║                                                       ║"
echo "  ║  Deploy Ragnar as a Pager payload for autonomous      ║"
echo "  ║  network reconnaissance on the go.                    ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ============================================================
# Step 1: Check connectivity to Pager
# ============================================================

log "INFO" "Checking connectivity to Pager at ${PAGER_IP}..."

# Determine the real user's home directory (for SSH keys when running with sudo)
if [ -n "$SUDO_USER" ]; then
    REAL_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    log "INFO" "Running as sudo, using SSH keys from $REAL_USER_HOME"
else
    REAL_USER_HOME="$HOME"
fi

# Find the user's SSH identity file
SSH_IDENTITY=""
for key in "$REAL_USER_HOME/.ssh/id_ed25519" "$REAL_USER_HOME/.ssh/id_rsa" "$REAL_USER_HOME/.ssh/id_ecdsa"; do
    if [ -f "$key" ]; then
        SSH_IDENTITY="-i $key"
        log "INFO" "Using SSH key: $key"
        break
    fi
done

# SSH options for Pager connection (bypass host key issues common with Pager).
# One multiplexed connection is reused for every later ssh call, so password
# users are prompted once instead of ~20 times, and the install is much faster.
CTRL_DIR=$(mktemp -d)
STAGING_DIR=""
IPK_DIR=""
SSH_OPTS_BASE="-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR $SSH_IDENTITY"
SSH_MUX="-o ControlMaster=auto -o ControlPath=${CTRL_DIR}/mux -o ControlPersist=900"
SSH_OPTS="${SSH_OPTS_BASE} ${SSH_MUX} -o BatchMode=yes"

# All Pager SSH/transfer goes through these. They read $SSH_OPTS at call time,
# so they work both before and after the key-vs-password decision below.
pager_ssh() { ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "$@"; }

# Copy files to the Pager as a tar stream over ssh. scp is avoided on purpose:
# modern OpenSSH scp speaks SFTP, which the Pager's SSH server may not provide,
# and a single stream is far faster than scp -r for thousands of small files.
#   push_dir  <local-dir>  <remote-dir>   (contents of local-dir -> remote-dir)
#   push_files <remote-dir> <file>...     (files, flat, -> remote-dir)
push_dir() {
    tar -C "$1" -czf - . | pager_ssh "mkdir -p '$2' && tar -xzf - -C '$2'"
}
push_files() {
    local dest="$1"; shift
    local dir; dir="$(dirname "$1")"
    local names=(); local f
    for f in "$@"; do names+=("$(basename "$f")"); done
    tar -C "$dir" -czf - "${names[@]}" | pager_ssh "mkdir -p '$dest' && tar -xzf - -C '$dest'"
}

cleanup() {
    ssh -o ControlPath="${CTRL_DIR}/mux" -O exit "${PAGER_USER}@${PAGER_IP}" >/dev/null 2>&1 || true
    rm -rf "${CTRL_DIR}"
    [ -n "${STAGING_DIR}" ] && rm -rf "${STAGING_DIR}"
    [ -n "${IPK_DIR}" ] && rm -rf "${IPK_DIR}"
    return 0
}
trap cleanup EXIT

# Is the SSH port reachable at all? (separates "wrong IP / not plugged in"
# from "authentication failed")
if ! timeout 6 bash -c "exec 3<>/dev/tcp/${PAGER_IP}/22" 2>/dev/null; then
    log "ERROR" "No SSH service reachable at ${PAGER_IP}:22"
    echo ""
    echo "  Make sure:"
    echo "    1. The Pager is powered on and connected via USB"
    echo "    2. This machine got an address on the Pager's USB network"
    echo "       (run: ip -4 addr | grep 172.16.)  - the Pager is the .1 of that subnet"
    _hint="$(detect_pager_ip)"
    [ -n "$_hint" ] && [ "$_hint" != "$PAGER_IP" ] && \
        echo "    3. A Pager network was detected here - try: $0 ${_hint}"
    exit 1
fi

# First try with key auth (BatchMode)
if pager_ssh "echo ok" >/dev/null 2>&1; then
    log "SUCCESS" "Connected to Pager at ${PAGER_IP} (key auth)"
else
    log "WARNING" "Key-based SSH auth failed."
    echo ""
    echo -e "${YELLOW}You can continue with the Pager's root password (asked once).${NC}"
    echo ""
    read -p "Continue with password authentication? (y/n): " use_password
    if [[ ! "$use_password" =~ ^[Yy]$ ]]; then
        log "ERROR" "Cannot connect to Pager at ${PAGER_USER}@${PAGER_IP}"
        echo ""
        echo "  To set up SSH key auth:"
        echo "    ssh-copy-id ${PAGER_USER}@${PAGER_IP}"
        exit 1
    fi
    SSH_OPTS="${SSH_OPTS_BASE} ${SSH_MUX}"
    echo "Enter the Pager root password:"
    if ! pager_ssh "echo ok" >/dev/null; then
        log "ERROR" "Cannot log in to ${PAGER_USER}@${PAGER_IP} (wrong password?)"
        exit 1
    fi
    log "SUCCESS" "Connected to Pager at ${PAGER_IP} (password auth)"
fi

# ============================================================
# Step 2: Check for libpagerctl.so availability
# ============================================================

log "INFO" "Checking for libpagerctl.so..."

# Check if we have it bundled in Ragnar itself
RAGNAR_PAGERCTL="${RAGNAR_DIR}/libpagerctl.so"
BJORN_PAGERCTL_CHECK="${RAGNAR_DIR}/../pineapple_pager_bjorn/payloads/user/reconnaissance/pager_bjorn/libpagerctl.so"

if [ -f "$RAGNAR_PAGERCTL" ]; then
    log "SUCCESS" "Found libpagerctl.so in Ragnar (will be bundled)"
    PAGERCTL_SOURCE="ragnar"
elif [ -f "$BJORN_PAGERCTL_CHECK" ]; then
    log "SUCCESS" "Found libpagerctl.so in pineapple_pager_bjorn (will be bundled)"
    PAGERCTL_SOURCE="bjorn"
else
    # Check if it exists on the Pager already
    PAGERCTL_FOUND=$(pager_ssh "
        if [ -f /root/lib/pagerctl_mock.py ]; then
            echo 'mock'
        elif [ -f /root/payloads/user/utilities/PAGERCTL/libpagerctl.so ]; then
            echo 'utilities'
        elif find /root/payloads -name 'libpagerctl.so' 2>/dev/null | head -1 | grep -q '.'; then
            echo 'found'
        else
            echo 'missing'
        fi
    ")

    if [ "$PAGERCTL_FOUND" = "mock" ]; then
        log "SUCCESS" "Mock pager detected - web display will be used"
        PAGERCTL_SOURCE="mock"
    elif [ "$PAGERCTL_FOUND" = "missing" ]; then
        log "WARNING" "libpagerctl.so not found!"
        echo ""
        echo "  The libpagerctl.so library is needed for Pager display/input."
        echo ""
        echo "  Options:"
        echo "    1. Continue without display support (headless mode, web UI only)"
        echo ""
        read -p "  Continue without display support? (y/n): " choice
        if [[ ! "$choice" =~ ^[Yy]$ ]]; then
            exit 1
        fi
        PAGERCTL_SOURCE="none"
    else
        log "SUCCESS" "Found libpagerctl.so on Pager (will copy to payload)"
        PAGERCTL_SOURCE="pager"
    fi
fi

# ============================================================
# Step 3: Create payload directory structure
# ============================================================

log "INFO" "Preparing payload package..."

STAGING_DIR=$(mktemp -d)
PAYLOAD_STAGE="${STAGING_DIR}/pager_ragnar"
mkdir -p "${PAYLOAD_STAGE}"

# Pager-specific files (live in pager/ subdirectory of the repo, deployed flat)
PAGER_FILES=(
    "PagerRagnar.py"
    "pager_display.py"
    "pager_menu.py"
    "pager_spectrum.py"
    "pager_payload.sh"
    "pagerctl.py"
    "pagerctl_mock.py"
)

for f in "${PAGER_FILES[@]}"; do
    src="${RAGNAR_DIR}/pager/${f}"
    # Fallback: root of repo (in case someone hasn't reorganised yet)
    [ -f "$src" ] || src="${RAGNAR_DIR}/${f}"
    if [ -f "$src" ]; then
        cp "$src" "${PAYLOAD_STAGE}/"
    else
        log "WARNING" "Pager file not found: ${f} (skipping)"
    fi
done

# Core shared modules (live at repo root)
CORE_FILES=(
    # Shared modules
    "init_shared.py"
    "shared.py"
    "orchestrator.py"
    "comment.py"
    "logger.py"
    "__init__.py"

    # Database and storage
    "db_manager.py"
    "network_storage.py"

    # Network handling
    "multi_interface.py"
    "wifi_manager.py"
    "wifi_interfaces.py"

    # Loggers
    "nmap_logger.py"
    "attack_logger.py"

    # Intelligence and scanning
    "network_intelligence.py"
    "threat_intelligence.py"
    "traffic_analyzer.py"
    "advanced_vuln_scanner.py"
    "lynis_parser.py"

    # Utilities
    "utils.py"
    "env_manager.py"

    # AI service (optional but good to have)
    "ai_service.py"

    # Web interface
    "webapp_modern.py"
    "server_capabilities.py"

    # Resource monitor
    "resource_monitor.py"
)

for f in "${CORE_FILES[@]}"; do
    if [ -f "${RAGNAR_DIR}/${f}" ]; then
        cp "${RAGNAR_DIR}/${f}" "${PAYLOAD_STAGE}/"
    elif [ -f "${RAGNAR_DIR}/python/${f}" ]; then
        cp "${RAGNAR_DIR}/python/${f}" "${PAYLOAD_STAGE}/"
    else
        log "WARNING" "File not found: ${f} (skipping)"
    fi
done

# Rename payload.sh for Pager launcher
# Hak5 firmware expects payload.sh — create both for compatibility
if [ -f "${PAYLOAD_STAGE}/pager_payload.sh" ]; then
    mv "${PAYLOAD_STAGE}/pager_payload.sh" "${PAYLOAD_STAGE}/payload.sh"
    cp "${PAYLOAD_STAGE}/payload.sh" "${PAYLOAD_STAGE}/payload"
    chmod +x "${PAYLOAD_STAGE}/payload.sh" "${PAYLOAD_STAGE}/payload"
fi

# Copy actions directory
if [ -d "${RAGNAR_DIR}/actions" ]; then
    cp -r "${RAGNAR_DIR}/actions" "${PAYLOAD_STAGE}/actions"
    log "SUCCESS" "Copied actions directory"
fi

# Copy config directory
if [ -d "${RAGNAR_DIR}/config" ]; then
    cp -r "${RAGNAR_DIR}/config" "${PAYLOAD_STAGE}/config"
    log "SUCCESS" "Copied config directory"
fi

# Copy only required resources (skip e-paper driver and large PSD source files)
mkdir -p "${PAYLOAD_STAGE}/resources"
[ -d "${RAGNAR_DIR}/resources/fonts" ]   && cp -r "${RAGNAR_DIR}/resources/fonts"   "${PAYLOAD_STAGE}/resources/"
[ -d "${RAGNAR_DIR}/resources/comments" ] && cp -r "${RAGNAR_DIR}/resources/comments" "${PAYLOAD_STAGE}/resources/"
if [ -d "${RAGNAR_DIR}/resources/images" ]; then
    mkdir -p "${PAYLOAD_STAGE}/resources/images"
    [ -d "${RAGNAR_DIR}/resources/images/static" ] && cp -r "${RAGNAR_DIR}/resources/images/static" "${PAYLOAD_STAGE}/resources/images/"
    [ -d "${RAGNAR_DIR}/resources/images/status" ] && cp -r "${RAGNAR_DIR}/resources/images/status" "${PAYLOAD_STAGE}/resources/images/"
    # Skip *.psd source files (~21MB) and waveshare_epd (e-paper driver not used on pager)
fi
log "SUCCESS" "Copied pager resources (fonts, icons, status images)"

# Copy web directory (for web UI)
if [ -d "${RAGNAR_DIR}/web" ]; then
    cp -r "${RAGNAR_DIR}/web" "${PAYLOAD_STAGE}/web"
    log "SUCCESS" "Copied web directory"
fi

# Create data directories
mkdir -p "${PAYLOAD_STAGE}/data/logs"
mkdir -p "${PAYLOAD_STAGE}/data/output/crackedpwd"
mkdir -p "${PAYLOAD_STAGE}/data/output/data_stolen"
mkdir -p "${PAYLOAD_STAGE}/data/output/vulnerabilities"
mkdir -p "${PAYLOAD_STAGE}/data/output/scan_results"
mkdir -p "${PAYLOAD_STAGE}/data/output/zombies"
mkdir -p "${PAYLOAD_STAGE}/data/input/dictionary"

# Copy dictionary files if they exist
if [ -f "${RAGNAR_DIR}/data/input/dictionary/users.txt" ]; then
    cp "${RAGNAR_DIR}/data/input/dictionary/users.txt" "${PAYLOAD_STAGE}/data/input/dictionary/"
fi
if [ -f "${RAGNAR_DIR}/data/input/dictionary/passwords.txt" ]; then
    cp "${RAGNAR_DIR}/data/input/dictionary/passwords.txt" "${PAYLOAD_STAGE}/data/input/dictionary/"
fi

# Create default dictionary files if not present
if [ ! -f "${PAYLOAD_STAGE}/data/input/dictionary/users.txt" ]; then
    cat > "${PAYLOAD_STAGE}/data/input/dictionary/users.txt" << 'DICT'
admin
root
user
administrator
test
guest
DICT
fi

if [ ! -f "${PAYLOAD_STAGE}/data/input/dictionary/passwords.txt" ]; then
    cat > "${PAYLOAD_STAGE}/data/input/dictionary/passwords.txt" << 'DICT'
password
123456
admin
root
password123
123
test
guest
DICT
fi

# ============================================================
# Step 4: Bundle Python dependencies
# ============================================================

log "INFO" "Bundling Python dependencies..."

LIB_DIR="${PAYLOAD_STAGE}/lib"
mkdir -p "${LIB_DIR}"

# Check for bundled libraries - first in Ragnar/pager_lib, then in pineapple_pager_bjorn
RAGNAR_LIB_DIR="${RAGNAR_DIR}/pager_lib"
BJORN_LIB_DIR="${RAGNAR_DIR}/../pineapple_pager_bjorn/payloads/user/reconnaissance/pager_bjorn/lib"

if [ -d "$RAGNAR_LIB_DIR" ]; then
    log "INFO" "Found bundled libraries in Ragnar/pager_lib, copying..."
    cp -r "${RAGNAR_LIB_DIR}/"* "${LIB_DIR}/" 2>/dev/null || true
    log "SUCCESS" "Copied bundled Python libraries"
elif [ -d "$BJORN_LIB_DIR" ]; then
    log "INFO" "Found bundled libraries from pineapple_pager_bjorn, copying..."
    cp -r "${BJORN_LIB_DIR}/"* "${LIB_DIR}/" 2>/dev/null || true
    log "SUCCESS" "Copied bundled Python libraries"
else
    if [ "$PAGERCTL_SOURCE" = "mock" ]; then
        log "INFO" "Mock pager - skipping MIPS libraries (Pi uses native packages)"
    else
        log "WARNING" "MIPS Python libraries not found"
        echo ""
        echo "  The Pager requires bundled Python libraries (paramiko, nmap, pymysql, etc.)"
        echo "  These should be MIPS-compiled versions."
        echo ""
        echo "  Ragnar may have limited functionality without them."
        echo ""
        read -p "  Continue without bundled libraries? (y/n): " choice
        if [[ ! "$choice" =~ ^[Yy]$ ]]; then
            rm -rf "${STAGING_DIR}"
            exit 1
        fi
    fi
fi

# ============================================================
# Step 5: Copy binary dependencies (sfreerdp, etc.)
# ============================================================

RAGNAR_BIN_DIR="${RAGNAR_DIR}/pager_bin"
BJORN_BIN_DIR="${RAGNAR_DIR}/../pineapple_pager_bjorn/payloads/user/reconnaissance/pager_bjorn/bin"

if [ -d "$RAGNAR_BIN_DIR" ]; then
    log "INFO" "Copying binary dependencies from Ragnar/pager_bin..."
    mkdir -p "${PAYLOAD_STAGE}/bin"
    cp -r "${RAGNAR_BIN_DIR}/"* "${PAYLOAD_STAGE}/bin/" 2>/dev/null || true
    log "SUCCESS" "Copied binary dependencies"
elif [ -d "$BJORN_BIN_DIR" ]; then
    log "INFO" "Copying binary dependencies from pineapple_pager_bjorn..."
    mkdir -p "${PAYLOAD_STAGE}/bin"
    cp -r "${BJORN_BIN_DIR}/"* "${PAYLOAD_STAGE}/bin/" 2>/dev/null || true
    log "SUCCESS" "Copied binary dependencies"
fi

# ============================================================
# Step 5b: Copy libpagerctl.so for Pager display support
# ============================================================

RAGNAR_PAGERCTL="${RAGNAR_DIR}/libpagerctl.so"
BJORN_PAGERCTL="${RAGNAR_DIR}/../pineapple_pager_bjorn/payloads/user/reconnaissance/pager_bjorn/libpagerctl.so"

copy_pagerctl() {
    local src="$1"
    # Copy to payload root (where pagerctl.py looks for it)
    cp "${src}" "${PAYLOAD_STAGE}/"
    # Also copy to lib/ for LD_LIBRARY_PATH fallback
    cp "${src}" "${PAYLOAD_STAGE}/lib/" 2>/dev/null || true
}

if [ -f "$RAGNAR_PAGERCTL" ]; then
    log "INFO" "Copying libpagerctl.so from Ragnar..."
    copy_pagerctl "${RAGNAR_PAGERCTL}"
    log "SUCCESS" "Copied libpagerctl.so (Pager display library)"
elif [ -f "$BJORN_PAGERCTL" ]; then
    log "INFO" "Copying libpagerctl.so from pineapple_pager_bjorn..."
    copy_pagerctl "${BJORN_PAGERCTL}"
    log "SUCCESS" "Copied libpagerctl.so (Pager display library)"
elif [ "$PAGERCTL_SOURCE" = "pager" ]; then
    # Copy from an existing payload on the Pager
    log "INFO" "Copying libpagerctl.so from existing Pager payload..."
    PAGER_LIB_PATH=$(pager_ssh "find /root/payloads -name 'libpagerctl.so' 2>/dev/null | head -1")
    if [ -n "$PAGER_LIB_PATH" ]; then
        pager_ssh "cat '${PAGER_LIB_PATH}'" > "${PAYLOAD_STAGE}/libpagerctl.so"
        cp "${PAYLOAD_STAGE}/libpagerctl.so" "${PAYLOAD_STAGE}/lib/" 2>/dev/null || true
        log "SUCCESS" "Copied libpagerctl.so from Pager"
    fi
else
    log "WARNING" "No libpagerctl.so available - Ragnar will run in headless mode"
fi

# ============================================================
# Step 5c: Bundle NSE vulnerability scripts (vulners.nse)
# ============================================================

log "INFO" "Bundling nmap NSE scripts..."

NSE_SRC_DIR="${RAGNAR_DIR}/pager_lib/nmap_scripts"
if [ -d "$NSE_SRC_DIR" ] && [ -n "$(ls -A "$NSE_SRC_DIR" 2>/dev/null)" ]; then
    mkdir -p "${PAYLOAD_STAGE}/nmap_scripts"
    cp "${NSE_SRC_DIR}/"*.nse "${PAYLOAD_STAGE}/nmap_scripts/" 2>/dev/null || true
    NSE_COUNT=$(ls -1 "${PAYLOAD_STAGE}/nmap_scripts/"*.nse 2>/dev/null | wc -l)
    log "SUCCESS" "Bundled ${NSE_COUNT} NSE script(s) (vulners.nse etc.)"
else
    log "WARNING" "No NSE scripts found in pager_lib/nmap_scripts/ - vuln scanning may not work"
fi

# ============================================================
# Step 6: Deploy to Pager
# ============================================================

# Refuse to deploy a broken package (this used to "succeed" with an empty payload)
STAGE_MISSING=""
for f in payload.sh pager_menu.py PagerRagnar.py pagerctl.py shared.py orchestrator.py actions web; do
    [ -e "${PAYLOAD_STAGE}/${f}" ] || STAGE_MISSING="${STAGE_MISSING} ${f}"
done
if [ -n "$STAGE_MISSING" ]; then
    log "ERROR" "Payload package is incomplete, missing:${STAGE_MISSING}"
    log "ERROR" "Ragnar checkout used: ${RAGNAR_DIR} - is it a complete clone?"
    exit 1
fi

STAGE_KB=$(du -sk "${PAYLOAD_STAGE}" | cut -f1)
FREE_KB=$(pager_ssh "mkdir -p ${PAGER_PAYLOAD_DIR} && df -k ${PAGER_PAYLOAD_DIR} | tail -1 | awk '{print \$(NF-2)}'" 2>/dev/null || echo "")
OLD_KB=$(pager_ssh "du -sk ${PAGER_PAYLOAD_DIR} 2>/dev/null | cut -f1" 2>/dev/null || echo 0)
if [[ "$FREE_KB" =~ ^[0-9]+$ ]] && [ $((FREE_KB + ${OLD_KB:-0})) -lt $((STAGE_KB + 2048)) ]; then
    log "ERROR" "Not enough space on the Pager: payload needs $((STAGE_KB/1024)) MB, only $((FREE_KB/1024)) MB free"
    exit 1
fi

log "INFO" "Deploying Ragnar payload to Pager ($((STAGE_KB/1024)) MB, this takes a minute)..."

if ! push_dir "${PAYLOAD_STAGE}" "${PAGER_PAYLOAD_DIR}"; then
    log "ERROR" "Copying the payload to the Pager failed"
    exit 1
fi

log "SUCCESS" "Payload deployed to ${PAGER_PAYLOAD_DIR}"

# Set permissions
pager_ssh "chmod +x ${PAGER_PAYLOAD_DIR}/payload.sh && chmod -R 755 ${PAGER_PAYLOAD_DIR}"

log "SUCCESS" "Permissions set"

# Fix libsodium symlinks (git on Windows stores symlinks as text files)
log "INFO" "Fixing libsodium symlinks..."
pager_ssh "
    cd ${PAGER_PAYLOAD_DIR}/lib
    # If libsodium.so is a text file instead of a real symlink, recreate it
    if [ -f libsodium.so.26.1.0 ]; then
        rm -f libsodium.so libsodium.so.26 2>/dev/null
        ln -sf libsodium.so.26.1.0 libsodium.so.26
        ln -sf libsodium.so.26 libsodium.so
        echo 'Recreated libsodium symlinks'
    fi
"
log "SUCCESS" "Library symlinks fixed"

# ============================================================
# Step 7: Setup system-wide libpagerctl.so
# ============================================================

log "INFO" "Setting up system-wide libpagerctl.so..."

pager_ssh "
    # Create /root/lib if it doesn't exist
    mkdir -p /root/lib
    
    # Copy libpagerctl.so to system lib dir
    if [ -f ${PAGER_PAYLOAD_DIR}/libpagerctl.so ]; then
        cp ${PAGER_PAYLOAD_DIR}/libpagerctl.so /root/lib/
        chmod 755 /root/lib/libpagerctl.so
        echo 'Copied libpagerctl.so to /root/lib/'
    fi
    
    # Ensure pagerctl.py is in payload root (already copied in Step 3)
    if [ ! -f ${PAGER_PAYLOAD_DIR}/pagerctl.py ]; then
        echo 'WARNING: pagerctl.py missing from payload root'
    fi
"

log "SUCCESS" "libpagerctl.so installed to /root/lib/"

# ============================================================
# Step 7b: Install bundled NSE scripts into nmap scripts dir
# ============================================================

log "INFO" "Installing NSE vulnerability scripts on Pager..."

pager_ssh "
    # nmap's script dir on OpenWRT (opkg install nmap puts scripts here)
    NMAP_SCRIPTS_DIR=''
    for d in /usr/share/nmap/scripts /usr/lib/nmap/scripts /opt/nmap/scripts; do
        if [ -d \"\$d\" ]; then
            NMAP_SCRIPTS_DIR=\"\$d\"
            break
        fi
    done

    if [ -z \"\$NMAP_SCRIPTS_DIR\" ]; then
        # nmap not installed yet - create the dir so scripts are ready when nmap installs
        mkdir -p /usr/share/nmap/scripts
        NMAP_SCRIPTS_DIR='/usr/share/nmap/scripts'
        echo 'Created /usr/share/nmap/scripts (nmap not yet installed)'
    fi

    if [ -d ${PAGER_PAYLOAD_DIR}/nmap_scripts ]; then
        cp ${PAGER_PAYLOAD_DIR}/nmap_scripts/*.nse \"\$NMAP_SCRIPTS_DIR/\" 2>/dev/null && \
            echo \"Installed NSE scripts to \$NMAP_SCRIPTS_DIR\" || \
            echo 'WARNING: could not copy NSE scripts'
        # Rebuild the script database if nmap is available
        if command -v nmap >/dev/null 2>&1; then
            nmap --script-updatedb 2>&1 | tail -1
        fi
    else
        echo 'No nmap_scripts directory in payload'
    fi
"

log "SUCCESS" "NSE scripts installed (vulners.nse ready for vuln scanning)"

# ============================================================
# Step 8: Install Python3 and dependencies on Pager
# ============================================================
#
# The Pager is OpenWrt on mipsel_24kc. We never pin a package version here: the
# OpenWrt feed drops older point releases (python 3.11.14 -> 3.11.18 ...), so a
# hardcoded version 404s a few months later. Instead we either let the Pager's
# own opkg resolve the current version online, or - if the Pager has no
# internet - discover the current version from the feed index on THIS machine,
# download the .ipk set here, and stream them over.

OPENWRT_BASE="https://downloads.openwrt.org/releases/24.10.1/packages/mipsel_24kc/packages"

# Fetch tool on the host (for the offline-download fallback)
host_fetch() {  # host_fetch <url> <outfile>  -> 0 on success
    if command -v curl >/dev/null 2>&1; then
        curl -sfL -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        return 2
    fi
}

# python3 from `opkg -d mmc` lands under /mmc, which is NOT on the Pager's default
# PATH or ld search path. payload.sh exports exactly these at launch, so every
# on-device python3 call here must use them too - otherwise an installed python3
# wrongly looks "missing" (which is what made this installer bail out).
PY_ENV='export PATH=/mmc/usr/bin:$PATH; export LD_LIBRARY_PATH=/mmc/usr/lib:$LD_LIBRARY_PATH;'
# Same, plus the payload's bundled pure-python libs (nmap, paramiko, ...).
PY_ENV_LIB="${PY_ENV} export PYTHONPATH='${PAGER_PAYLOAD_DIR}/lib:${PAGER_PAYLOAD_DIR}';"

log "INFO" "Checking Python3 on Pager..."

PYTHON3_INSTALLED=$(pager_ssh "${PY_ENV} python3 --version 2>/dev/null && echo FOUND || echo MISSING")

# Package list Ragnar needs (OpenWrt names, no versions)
PY_PKGS="python3-base python3-light python3-logging python3-asyncio python3-codecs \
python3-ctypes python3-email python3-urllib python3-sqlite3 python3-multiprocessing \
python3-openssl python3-uuid python3-xml python3-decimal"

# --- Strategy A: install on the Pager with its own opkg (handles versions itself)
install_via_device_opkg() {
    log "INFO" "Trying on-device opkg (needs internet on the Pager)..."
    pager_ssh "
        rm -f /var/lock/opkg.lock 2>/dev/null
        opkg update >/dev/null 2>&1 || true
        # -d mmc keeps the small root flash free; falls back to root if no mmc dest
        if opkg --help 2>&1 | grep -q 'dest' && grep -q 'dest mmc' /etc/opkg.conf 2>/dev/null; then
            opkg -d mmc install python3 ${PY_PKGS} 2>&1 | tail -20
        else
            opkg install python3 ${PY_PKGS} 2>&1 | tail -20
        fi
    "
    pager_ssh "${PY_ENV} python3 -c 'import ctypes,sqlite3,ssl; print(42)'" 2>/dev/null | grep -q 42
}

# --- Strategy B: download .ipk set on the host, discover version, stream over
install_via_host_download() {
    IPK_DIR=$(mktemp -d)
    log "INFO" "Discovering current package versions from OpenWrt feed..."
    local idx="${IPK_DIR}/Packages"
    if ! host_fetch "${OPENWRT_BASE}/Packages.gz" "${idx}.gz"; then
        log "ERROR" "Could not download the OpenWrt package index (no network, or curl/wget missing)."
        rm -rf "${IPK_DIR}"; IPK_DIR=""
        return 1
    fi
    gunzip -f "${idx}.gz" 2>/dev/null || { log "ERROR" "Package index unreadable"; rm -rf "${IPK_DIR}"; IPK_DIR=""; return 1; }

    # For each package name, read its Filename: from the index and download it.
    # libpython3-3.11 is a dependency of python3-base; include it explicitly.
    local want="libpython3-3.11 ${PY_PKGS}"
    local missing=0 pkg fname
    for pkg in $want; do
        fname=$(awk -v p="$pkg" '
            $1=="Package:"{cur=$2}
            $1=="Filename:" && cur==p {print $2; exit}' "${idx}")
        if [ -z "$fname" ]; then
            log "WARNING" "Package not in feed index: ${pkg}"
            missing=$((missing+1)); continue
        fi
        if ! host_fetch "${OPENWRT_BASE}/${fname}" "${IPK_DIR}/${fname}"; then
            log "WARNING" "Failed to download ${fname}"
            missing=$((missing+1))
        fi
    done

    local count
    count=$(ls -1 "${IPK_DIR}"/*.ipk 2>/dev/null | wc -l)
    if [ "$count" -eq 0 ]; then
        log "ERROR" "No Python3 packages could be downloaded."
        rm -rf "${IPK_DIR}"; IPK_DIR=""
        return 1
    fi
    [ "$missing" -gt 0 ] && log "WARNING" "${missing} package(s) could not be fetched; continuing with ${count}."

    log "INFO" "Transferring ${count} packages to Pager..."
    push_files /tmp "${IPK_DIR}"/*.ipk || { log "ERROR" "Package transfer failed"; rm -rf "${IPK_DIR}"; IPK_DIR=""; return 1; }

    log "INFO" "Installing Python3 packages on Pager..."
    pager_ssh "
        rm -f /var/lock/opkg.lock 2>/dev/null
        # Core first (provides the interpreter), then the stdlib modules.
        opkg install /tmp/libpython3-3.11_*.ipk /tmp/python3-base_*.ipk /tmp/python3-light_*.ipk 2>&1 | tail -5 || true
        opkg install /tmp/python3-*.ipk 2>&1 | tail -10 || true
        rm -f /tmp/python3-*.ipk /tmp/libpython3-*.ipk 2>/dev/null
    "
    rm -rf "${IPK_DIR}"; IPK_DIR=""
    pager_ssh "${PY_ENV} python3 -c 'import ctypes,sqlite3,ssl; print(42)'" 2>/dev/null | grep -q 42
}

needs_python_install=false
if echo "$PYTHON3_INSTALLED" | grep -q "MISSING"; then
    needs_python_install=true
else
    log "SUCCESS" "Python3 already present on Pager"
    # Confirm the stdlib modules Ragnar imports are actually there
    MISSING_MODS=$(pager_ssh "${PY_ENV} python3 -c '
import importlib
need=[\"logging\",\"asyncio\",\"ctypes\",\"sqlite3\",\"xml.etree.ElementTree\",\"email\",\"urllib\",\"multiprocessing\",\"ssl\",\"uuid\",\"decimal\",\"codecs\"]
miss=[]
for m in need:
    try: importlib.import_module(m)
    except ImportError: miss.append(m)
print(\" \".join(miss) if miss else \"NONE\")' 2>/dev/null || echo CHECK_FAILED")
    if [ "$MISSING_MODS" != "NONE" ] && [ "$MISSING_MODS" != "CHECK_FAILED" ] && [ -n "$MISSING_MODS" ]; then
        log "WARNING" "Missing Python3 modules: ${MISSING_MODS}"
        needs_python_install=true
    else
        log "SUCCESS" "All required Python3 modules present"
    fi
fi

if [ "$needs_python_install" = true ]; then
    log "INFO" "Installing Python3 on the Pager..."
    if install_via_device_opkg; then
        log "SUCCESS" "Python3 installed on Pager (on-device opkg)"
    elif install_via_host_download; then
        log "SUCCESS" "Python3 installed on Pager (host-side download)"
    else
        log "WARNING" "Could not install Python3 automatically."
        echo ""
        echo "  Install it on the Pager manually (it needs internet), then re-run this script:"
        echo "    ssh ${PAGER_USER}@${PAGER_IP} 'opkg update && opkg install python3 python3-ctypes python3-sqlite3 python3-openssl'"
        echo ""
        read -p "  Continue without Python3? (y/n): " choice
        [[ "$choice" =~ ^[Yy]$ ]] || exit 1
    fi
fi

# ============================================================
# Step 8a: arp-scan (optional - adds vendor names to discovered hosts)
# ============================================================
# Ragnar works without it (MACs come from the neighbour table), so this is
# best-effort: it needs internet on the Pager and never fails the install.

if pager_ssh "PATH=/mmc/usr/bin:/mmc/usr/sbin:\$PATH command -v arp-scan >/dev/null 2>&1"; then
    log "SUCCESS" "arp-scan already installed on Pager"
else
    log "INFO" "Trying to install arp-scan on the Pager (optional)..."
    pager_ssh "
        rm -f /var/lock/opkg.lock 2>/dev/null
        opkg update >/dev/null 2>&1 || true
        if grep -q 'dest mmc' /etc/opkg.conf 2>/dev/null; then
            opkg -d mmc install arp-scan >/dev/null 2>&1
        else
            opkg install arp-scan >/dev/null 2>&1
        fi
    " || true
    if pager_ssh "PATH=/mmc/usr/bin:/mmc/usr/sbin:\$PATH command -v arp-scan >/dev/null 2>&1"; then
        log "SUCCESS" "arp-scan installed"
    else
        log "INFO" "arp-scan not available (no internet on the Pager, or not in its feed) - Ragnar will use the neighbour table instead"
    fi
fi

# ============================================================
# Step 8b: Install python-nmap (pure Python wrapper for nmap)
# ============================================================

log "INFO" "Checking python-nmap on Pager..."

NMAP_PY_OK=$(pager_ssh "${PY_ENV_LIB} python3 -c 'import nmap; print(\"OK\")' 2>/dev/null || echo 'MISSING'")

if [ "$NMAP_PY_OK" != "OK" ]; then
    # Prefer the copy bundled in the repo (works fully offline); fall back to PyPI.
    NMAP_SRC=""
    if [ -d "${RAGNAR_DIR}/pager_lib/nmap" ]; then
        NMAP_SRC="${RAGNAR_DIR}/pager_lib/nmap"
        log "INFO" "Installing python-nmap from bundled pager_lib/nmap..."
    else
        log "INFO" "Downloading python-nmap..."
        NMAP_PY_DIR=$(mktemp -d)
        if host_fetch "https://files.pythonhosted.org/packages/source/p/python-nmap/python-nmap-0.7.1.tar.gz" "${NMAP_PY_DIR}/n.tgz" \
           || host_fetch "https://pypi.io/packages/source/p/python-nmap/python-nmap-0.7.1.tar.gz" "${NMAP_PY_DIR}/n.tgz"; then
            tar xzf "${NMAP_PY_DIR}/n.tgz" -C "${NMAP_PY_DIR}" 2>/dev/null
            NMAP_SRC=$(find "${NMAP_PY_DIR}" -maxdepth 2 -type d -name "nmap" | head -1)
        fi
    fi

    if [ -n "$NMAP_SRC" ] && [ -d "$NMAP_SRC" ]; then
        # Determine the Pager's python3.x site dir instead of assuming 3.11
        PY_LIBDIR=$(pager_ssh "${PY_ENV} python3 -c 'import sys,os;print(os.path.join(sys.prefix,\"lib\",\"python%d.%d\"%sys.version_info[:2]))' 2>/dev/null")
        [ -z "$PY_LIBDIR" ] && PY_LIBDIR="/mmc/usr/lib/python3.11"
        if push_dir "$NMAP_SRC" "${PY_LIBDIR}/nmap"; then
            log "SUCCESS" "python-nmap installed to ${PY_LIBDIR}/nmap"
        else
            log "WARNING" "Could not copy python-nmap to the Pager"
        fi
    else
        log "WARNING" "python-nmap unavailable (no bundle, no network). Nmap scanning may not work."
    fi
    [ -n "${NMAP_PY_DIR:-}" ] && rm -rf "${NMAP_PY_DIR}"
else
    log "SUCCESS" "python-nmap already installed on Pager"
fi

log "INFO" "Verifying installation..."

VERIFY_RESULT=$(pager_ssh "
    errors=0
    
    # Check core files (libpagerctl.so not required on mock pager)
    for f in pager_menu.py pagerctl.py payload.sh; do
        if [ ! -f ${PAGER_PAYLOAD_DIR}/\$f ]; then
            echo \"MISSING: \$f\"
            errors=\$((errors + 1))
        fi
    done

    # Check display library: either libpagerctl.so (real) or pagerctl_mock.py (mock)
    if [ ! -f ${PAGER_PAYLOAD_DIR}/libpagerctl.so ] && [ ! -f ${PAGER_PAYLOAD_DIR}/pagerctl_mock.py ]; then
        echo 'MISSING: libpagerctl.so or pagerctl_mock.py'
        errors=\$((errors + 1))
    fi
    
    # Check lib directory
    if [ ! -d ${PAGER_PAYLOAD_DIR}/lib ]; then
        echo 'MISSING: lib directory'
        errors=\$((errors + 1))
    fi
    
    # Check actions directory
    if [ ! -d ${PAGER_PAYLOAD_DIR}/actions ]; then
        echo 'MISSING: actions directory'
        errors=\$((errors + 1))
    fi
    
    # Check resources/fonts
    if [ ! -d ${PAGER_PAYLOAD_DIR}/resources/fonts ]; then
        echo 'MISSING: resources/fonts directory'
        errors=\$((errors + 1))
    fi
    
    # Check system libpagerctl
    if [ ! -f /root/lib/libpagerctl.so ]; then
        echo 'MISSING: /root/lib/libpagerctl.so'
        errors=\$((errors + 1))
    fi
    
    # Test Python import
    cd ${PAGER_PAYLOAD_DIR}
    export PATH=\"/mmc/usr/bin:\$PATH\"
    export PYTHONPATH=\"${PAGER_PAYLOAD_DIR}/lib:${PAGER_PAYLOAD_DIR}:\$PYTHONPATH\"
    export LD_LIBRARY_PATH=\"/mmc/usr/lib:/root/lib:${PAGER_PAYLOAD_DIR}/lib:${PAGER_PAYLOAD_DIR}:\$LD_LIBRARY_PATH\"
    
    python3 -c 'from pagerctl import Pager; print(\"PAGERCTL_OK\")' 2>/dev/null || echo 'PAGERCTL_IMPORT_FAILED'
    python3 -c 'import nmap; nmap.PortScanner(); print(\"NMAP_PY_OK\")' 2>/dev/null || echo 'NMAP_PY_FAILED'
    python3 -c 'import logging, asyncio, ctypes, sqlite3, xml.etree.ElementTree; print(\"STDLIB_OK\")' 2>/dev/null || echo 'STDLIB_FAILED'

    if [ \$errors -eq 0 ]; then
        echo 'ALL_OK'
    else
        echo \"ERRORS: \$errors\"
    fi
")

if echo "$VERIFY_RESULT" | grep -q "ALL_OK"; then
    log "SUCCESS" "Installation verified successfully"
else
    log "WARNING" "Verification issues detected:"
    echo "$VERIFY_RESULT" | grep -v "ALL_OK" | while read line; do
        [ -n "$line" ] && echo "  - $line"
    done
fi

if echo "$VERIFY_RESULT" | grep -q "PAGERCTL_OK"; then
    log "SUCCESS" "pagerctl library imports correctly"
else
    log "WARNING" "pagerctl import test failed - display may not work"
fi

if echo "$VERIFY_RESULT" | grep -q "NMAP_PY_OK"; then
    log "SUCCESS" "python-nmap module works correctly"
else
    log "WARNING" "python-nmap import failed - network scanning may not work"
fi

if echo "$VERIFY_RESULT" | grep -q "STDLIB_OK"; then
    log "SUCCESS" "Python3 standard library modules OK"
else
    log "WARNING" "Some Python3 standard library modules missing"
fi

# ============================================================
# Step 9b: Generate actions.json if missing
# ============================================================

log "INFO" "Ensuring actions.json is up to date..."

pager_ssh "
    cd ${PAGER_PAYLOAD_DIR}
    export PATH=\"/mmc/usr/bin:\$PATH\"
    export PYTHONPATH=\"${PAGER_PAYLOAD_DIR}/lib:${PAGER_PAYLOAD_DIR}:\$PYTHONPATH\"
    export LD_LIBRARY_PATH=\"/mmc/usr/lib:/root/lib:${PAGER_PAYLOAD_DIR}/lib:${PAGER_PAYLOAD_DIR}:\$LD_LIBRARY_PATH\"

    python3 -c '
import sys, os, json, importlib
sys.path.insert(0, \".\")
actions_dir = \"actions\"
actions_config = []
for filename in os.listdir(actions_dir):
    if filename.endswith(\".py\") and filename != \"__init__.py\":
        module_name = filename[:-3]
        try:
            module = importlib.import_module(f\"actions.{module_name}\")
            if getattr(module, \"BYPASS_ACTION_MODULE\", False):
                continue
            b_class = getattr(module, \"b_class\", None)
            b_status = getattr(module, \"b_status\", None)
            if not b_class or not b_status:
                continue
            b_port = getattr(module, \"b_port\", None)
            b_parent = getattr(module, \"b_parent\", None)
            actions_config.append({\"b_module\": module_name, \"b_class\": b_class, \"b_port\": b_port, \"b_status\": b_status, \"b_parent\": b_parent})
        except Exception:
            pass
os.makedirs(\"config\", exist_ok=True)
with open(\"config/actions.json\", \"w\") as f:
    json.dump(actions_config, f, indent=4)
print(f\"Generated actions.json with {len(actions_config)} actions\")
' 2>&1 || echo 'actions.json generation failed (will be created on first run)'
"

log "SUCCESS" "actions.json configured"

# ============================================================
# Step 10: Create convenience symlink at /root/Ragnar
# ============================================================

log "INFO" "Creating /root/Ragnar symlink for compatibility..."

pager_ssh "
    # Remove old symlink if exists
    [ -L /root/Ragnar ] && rm -f /root/Ragnar
    
    # Create symlink if /root/Ragnar doesn't exist as directory
    if [ ! -d /root/Ragnar ]; then
        ln -sf ${PAGER_PAYLOAD_DIR} /root/Ragnar
        echo 'Symlink created: /root/Ragnar -> ${PAGER_PAYLOAD_DIR}'
    else
        echo '/root/Ragnar already exists as directory'
    fi
"

log "SUCCESS" "Ragnar accessible at /root/Ragnar"

# ============================================================
# Cleanup and finish
# ============================================================

rm -rf "${STAGING_DIR}"

echo ""
echo -e "${GREEN}  ╔═══════════════════════════════════════════════════════╗"
echo -e "  ║     Ragnar successfully deployed to Pineapple Pager!  ║"
echo -e "  ╚═══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  To launch Ragnar on the Pager:"
echo "    1. Open the Pager's payload menu"
echo "    2. Navigate to: Reconnaissance > PagerRagnar"
echo "    3. Press GREEN to start"
echo ""
echo "  Web interface (when enabled): http://${PAGER_IP}:8000"
echo ""
echo "  To update later:"
echo "    ./install_pineapple_pager.sh ${PAGER_IP}"
echo ""
