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

# Configuration
PAGER_IP="${1:-172.16.42.1}"
PAGER_USER="root"
PAGER_PAYLOAD_DIR="/root/payloads/user/reconnaissance/pager_ragnar"
RAGNAR_DIR="$(cd "$(dirname "$0")" && pwd)"

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

# SSH options for Pager connection (bypass host key issues common with Pager)
SSH_OPTS_BASE="-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_IDENTITY"
SSH_OPTS_BATCH="${SSH_OPTS_BASE} -o BatchMode=yes"
SSH_OPTS="${SSH_OPTS_BATCH}"
USE_INTERACTIVE=false

# First try with key auth (BatchMode)
if ssh $SSH_OPTS_BATCH "${PAGER_USER}@${PAGER_IP}" "echo ok" >/dev/null 2>&1; then
    log "SUCCESS" "Connected to Pager at ${PAGER_IP} (key auth)"
else
    log "WARNING" "Key-based SSH auth failed. Trying interactive mode..."
    echo ""
    # Test if we can reach the host at all
    if ssh $SSH_OPTS_BASE -o PasswordAuthentication=yes -o NumberOfPasswordPrompts=0 "${PAGER_USER}@${PAGER_IP}" "echo ok" >/dev/null 2>&1; then
        log "SUCCESS" "Connected to Pager at ${PAGER_IP}"
    else
        echo -e "${YELLOW}SSH key auth is not working. You can continue with password auth.${NC}"
        echo -e "${YELLOW}You'll be prompted for the root password multiple times during install.${NC}"
        echo ""
        read -p "Continue with password authentication? (y/n): " use_password
        if [[ "$use_password" =~ ^[Yy]$ ]]; then
            USE_INTERACTIVE=true
            SSH_OPTS="${SSH_OPTS_BASE}"
            # Verify we can actually connect with password
            echo "Testing connection (enter root password):"
            if ! ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "echo ok"; then
                log "ERROR" "Cannot connect to Pager at ${PAGER_USER}@${PAGER_IP}"
                echo ""
                echo "  Make sure:"
                echo "    1. Pager is powered on and connected via USB"
                echo "    2. SSH is accessible at ${PAGER_IP}"
                echo "    3. You entered the correct password"
                exit 1
            fi
            log "SUCCESS" "Connected to Pager at ${PAGER_IP} (password auth)"
        else
            log "ERROR" "Cannot connect to Pager at ${PAGER_USER}@${PAGER_IP}"
            echo ""
            echo "  To set up SSH key auth:"
            echo "    ssh-copy-id ${PAGER_USER}@${PAGER_IP}"
            echo ""
            echo "  Debug: Try manually connecting:"
            echo "    ssh -v ${PAGER_USER}@${PAGER_IP}"
            exit 1
        fi
    fi
fi

# ============================================================
# Step 2: Check for libpagerctl.so availability
# ============================================================

log "INFO" "Checking for libpagerctl.so..."

# First check if we have it bundled in Ragnar itself
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
    PAGERCTL_FOUND=$(ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
        if [ -f /root/payloads/user/utilities/PAGERCTL/libpagerctl.so ]; then
            echo 'utilities'
        elif find /root/payloads -name 'libpagerctl.so' 2>/dev/null | head -1 | grep -q '.'; then
            echo 'found'
        else
            echo 'missing'
        fi
    ")

    if [ "$PAGERCTL_FOUND" = "missing" ]; then
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

# Core Ragnar files - ALL Python modules needed
CORE_FILES=(
    # Pager-specific entry points
    "PagerRagnar.py"
    "pager_display.py"
    "pager_menu.py"
    "pager_payload.sh"
    "pagerctl.py"
    
    # Core shared modules
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
    
    # Display helpers
    "epd_helper.py"
    "display.py"
    
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
    "routes.json"
    
    # Resource monitor
    "resource_monitor.py"
)

for f in "${CORE_FILES[@]}"; do
    if [ -f "${RAGNAR_DIR}/${f}" ]; then
        cp "${RAGNAR_DIR}/${f}" "${PAYLOAD_STAGE}/"
    else
        log "WARNING" "File not found: ${f} (skipping)"
    fi
done

# Rename payload.sh for Pager launcher
if [ -f "${PAYLOAD_STAGE}/pager_payload.sh" ]; then
    mv "${PAYLOAD_STAGE}/pager_payload.sh" "${PAYLOAD_STAGE}/payload.sh"
    chmod +x "${PAYLOAD_STAGE}/payload.sh"
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

# Copy resources directory (fonts, images, comments, dictionaries)
if [ -d "${RAGNAR_DIR}/resources" ]; then
    cp -r "${RAGNAR_DIR}/resources" "${PAYLOAD_STAGE}/resources"
    log "SUCCESS" "Copied resources directory"
fi

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
    PAGER_LIB_PATH=$(ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "find /root/payloads -name 'libpagerctl.so' 2>/dev/null | head -1")
    if [ -n "$PAGER_LIB_PATH" ]; then
        scp $SSH_OPTS "${PAGER_USER}@${PAGER_IP}:${PAGER_LIB_PATH}" "${PAYLOAD_STAGE}/"
        cp "${PAYLOAD_STAGE}/libpagerctl.so" "${PAYLOAD_STAGE}/lib/" 2>/dev/null || true
        log "SUCCESS" "Copied libpagerctl.so from Pager"
    fi
else
    log "WARNING" "No libpagerctl.so available - Ragnar will run in headless mode"
fi

# ============================================================
# Step 6: Deploy to Pager
# ============================================================

log "INFO" "Deploying Ragnar payload to Pager..."

# Create payload directory on Pager
ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "mkdir -p ${PAGER_PAYLOAD_DIR}"

# Copy payload
scp $SSH_OPTS -r "${PAYLOAD_STAGE}/"* "${PAGER_USER}@${PAGER_IP}:${PAGER_PAYLOAD_DIR}/"

log "SUCCESS" "Payload deployed to ${PAGER_PAYLOAD_DIR}"

# Set permissions
ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "chmod +x ${PAGER_PAYLOAD_DIR}/payload.sh && chmod -R 755 ${PAGER_PAYLOAD_DIR}"

log "SUCCESS" "Permissions set"

# Fix libsodium symlinks (git on Windows stores symlinks as text files)
log "INFO" "Fixing libsodium symlinks..."
ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
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

ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
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
# Step 8: Verify installation
# ============================================================

log "INFO" "Verifying installation..."

VERIFY_RESULT=$(ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
    errors=0
    
    # Check core files
    for f in pager_menu.py pagerctl.py libpagerctl.so payload.sh; do
        if [ ! -f ${PAGER_PAYLOAD_DIR}/\$f ]; then
            echo \"MISSING: \$f\"
            errors=\$((errors + 1))
        fi
    done
    
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
    export PYTHONPATH=\"${PAGER_PAYLOAD_DIR}/lib:${PAGER_PAYLOAD_DIR}:\$PYTHONPATH\"
    export LD_LIBRARY_PATH=\"/root/lib:${PAGER_PAYLOAD_DIR}/lib:${PAGER_PAYLOAD_DIR}:\$LD_LIBRARY_PATH\"
    
    python3 -c 'from pagerctl import Pager; print(\"PAGERCTL_OK\")' 2>/dev/null || echo 'PAGERCTL_IMPORT_FAILED'
    
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

# ============================================================
# Step 9: Create convenience symlink at /root/Ragnar
# ============================================================

log "INFO" "Creating /root/Ragnar symlink for compatibility..."

ssh $SSH_OPTS "${PAGER_USER}@${PAGER_IP}" "
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
