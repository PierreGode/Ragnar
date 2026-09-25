#!/bin/bash

# ragnar Update Script
# This script safely updates ragnar while preserving configurations and data
# Author: infinition
# Version: 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ragnar_PATH="/home/ragnar/Ragnar"

echo -e "${BLUE}ragnar Update Script${NC}"
echo -e "${YELLOW}This will update ragnar while preserving your data and configurations.${NC}"

# Check if we're in the right directory
if [ ! -d "$ragnar_PATH" ]; then
    echo -e "${RED}Error: ragnar directory not found at $ragnar_PATH${NC}"
    exit 1
fi

if [ ! -d "$ragnar_PATH/.git" ]; then
    echo -e "${RED}Error: This is not a git repository. Cannot update.${NC}"
    echo -e "${YELLOW}Please reinstall ragnar using the installation script.${NC}"
    exit 1
fi

cd "$ragnar_PATH"

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root. Please use 'sudo'.${NC}"
    exit 1
fi

echo -e "\n${BLUE}Step 1: Stopping ragnar service...${NC}"
systemctl stop ragnar.service

echo -e "${BLUE}Step 1.5: Preparing git repository...${NC}"
# Root runs this script while the checkout belongs to user 'ragnar' — newer
# git refuses that mix ("detected dubious ownership") unless the path is
# whitelisted in root's global config. Interrupted runs can also leave stale
# lock files, and previous sudo runs leave root-owned files that break git.
git config --global --get-all safe.directory 2>/dev/null | grep -qxF "$ragnar_PATH" \
    || git config --global --add safe.directory "$ragnar_PATH"
rm -f "$ragnar_PATH/.git/index.lock" "$ragnar_PATH/.git/HEAD.lock" "$ragnar_PATH/.git/shallow.lock" 2>/dev/null
chown -R ragnar:ragnar "$ragnar_PATH" 2>/dev/null || true
# Stash and merge commits need an author identity; root rarely has one.
GIT_ID=(-c user.name="Ragnar Updater" -c user.email="ragnar-updater@localhost" -c pull.rebase=false)

echo -e "${BLUE}Step 2: Backing up local changes...${NC}"
if git diff --quiet && git diff --staged --quiet; then
    echo -e "${GREEN}No local changes to backup.${NC}"
else
    echo -e "${YELLOW}Local changes detected. Creating backup...${NC}"
    git "${GIT_ID[@]}" stash push -m "Auto-backup before update $(date)"
    echo -e "${GREEN}Local changes backed up.${NC}"
fi

echo -e "${BLUE}Step 2.5: Preserving local runtime data...${NC}"
BACKUP_DIR=".local_backup"
mkdir -p "$BACKUP_DIR"
PRESERVE_FILES=("data/ragnar.db" "data/livestatus.csv" "data/netkb.csv" "data/pwnagotchi_status.json")
for file in "${PRESERVE_FILES[@]}"; do
    if [ -f "$file" ]; then
        cp -p "$file" "$BACKUP_DIR/$(basename $file)"
        echo -e "  ${GREEN}✓${NC} Backed up: $file"
    fi
done

echo -e "${BLUE}Step 3: Fetching latest updates...${NC}"
git fetch origin

echo -e "${BLUE}Step 4: Updating to latest version...${NC}"
CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)"
if [ "$CURRENT_BRANCH" = "HEAD" ]; then
    # Detached checkout (e.g. a past checkout of a tag) - go back to main.
    echo -e "${YELLOW}Detached checkout detected - switching back to main.${NC}"
    git checkout main 2>/dev/null || git checkout -B main origin/main
    CURRENT_BRANCH="main"
fi
if git "${GIT_ID[@]}" pull origin "$CURRENT_BRANCH"; then
    echo -e "${GREEN}Update completed successfully!${NC}"
else
    # Deterministic fallback: local changes are already in the stash and the
    # runtime data is copied aside below, so matching origin exactly is safe
    # and guarantees the update lands even on conflicted/diverged checkouts.
    echo -e "${YELLOW}git pull failed - forcing checkout to match origin/$CURRENT_BRANCH (local changes stay in the stash)...${NC}"
    if git fetch origin "$CURRENT_BRANCH" && git reset --hard "origin/$CURRENT_BRANCH"; then
        echo -e "${GREEN}Update completed via forced sync.${NC}"
    else
        echo -e "${RED}Update failed. Attempting to restore backup...${NC}"
        git "${GIT_ID[@]}" stash pop 2>/dev/null || true
        echo -e "${YELLOW}Backup restored. Please check for conflicts manually.${NC}"
        systemctl start ragnar.service
        exit 1
    fi
fi

echo -e "${BLUE}Step 5: Updating Python dependencies...${NC}"
# Fast path: one batch upgrade. If pip cannot satisfy the full set (e.g.
# one bad/unsatisfiable pin) it installs NOTHING, silently leaving every
# dependency un-upgraded. Fall back to installing each requirement on its
# own so a single bad package can not block all the others.
if ! pip3 install --break-system-packages --upgrade -r requirements.txt; then
    echo -e "${YELLOW}Batch dependency install failed - retrying package-by-package so one bad pin can not block the rest...${NC}"
    while IFS= read -r req || [ -n "$req" ]; do
        req="${req%%#*}"                 # strip inline comments
        req="$(echo "$req" | xargs)"     # trim whitespace
        [ -z "$req" ] && continue
        pip3 install --break-system-packages --upgrade "$req" \
            || echo -e "  ${YELLOW}!${NC} Failed to install: $req (continuing)"
    done < requirements.txt
fi

echo -e "${BLUE}Step 5.5: Restoring local runtime data...${NC}"
for file in "${PRESERVE_FILES[@]}"; do
    backup_file="$BACKUP_DIR/$(basename $file)"
    if [ -f "$backup_file" ]; then
        mkdir -p "$(dirname $file)"
        cp -p "$backup_file" "$file"
        echo -e "  ${GREEN}✓${NC} Restored: $file"
    fi
done
rm -rf "$BACKUP_DIR"
echo -e "${GREEN}Local runtime data restored.${NC}"

echo -e "${BLUE}Step 5.6: Initializing data files from templates...${NC}"
bash "$ragnar_PATH/scripts/init_data_files.sh"

echo -e "${BLUE}Step 6: Setting correct permissions...${NC}"
chown -R ragnar:ragnar "$ragnar_PATH"
chmod +x "$ragnar_PATH"/*.sh 2>/dev/null || true

# Ensure specific critical scripts are executable
chmod +x "$ragnar_PATH/kill_port_8000.sh" 2>/dev/null || true
chmod +x "$ragnar_PATH/scripts/update_ragnar.sh" 2>/dev/null || true
chmod +x "$ragnar_PATH/scripts/"*.sh 2>/dev/null || true

echo -e "${BLUE}Step 6.5: Validating actions.json configuration...${NC}"
python3 << 'PYTHON_EOF'
import json
import os

actions_file = "/home/ragnar/Ragnar/config/actions.json"

try:
    with open(actions_file, 'r') as f:
        actions = json.load(f)
    
    has_scanning = any(action.get('b_module') == 'scanning' for action in actions)
    
    if not has_scanning:
        print("WARNING: scanning module missing, adding it...")
        scanning_action = {
            "b_module": "scanning",
            "b_class": "NetworkScanner",
            "b_port": None,
            "b_status": "network_scanner",
            "b_parent": None
        }
        actions.insert(0, scanning_action)
        
        with open(actions_file, 'w') as f:
            json.dump(actions, f, indent=4)
        print("SUCCESS: Added scanning module to actions.json")
    else:
        print("SUCCESS: scanning module validated")
        
except Exception as e:
    print(f"ERROR validating actions.json: {e}")
PYTHON_EOF

echo -e "${BLUE}Step 6.7: Checking Pwnagotchi migration...${NC}"
MIGRATE_SCRIPT="$ragnar_PATH/scripts/migrate_pwnagotchi.sh"
if [[ -d "/opt/pwnagotchi" ]] && [[ -f "$MIGRATE_SCRIPT" ]]; then
    chmod +x "$MIGRATE_SCRIPT"
    if bash "$MIGRATE_SCRIPT"; then
        echo -e "${GREEN}Pwnagotchi migration check completed.${NC}"
    else
        echo -e "${YELLOW}Pwnagotchi migration had issues. Check /var/log/ragnar/ for details.${NC}"
    fi

    # Ensure boot-time migration service is installed
    if [[ ! -f "/etc/systemd/system/ragnar-pwn-migrate.service" ]]; then
        cat >"/etc/systemd/system/ragnar-pwn-migrate.service" <<SVCEOF
[Unit]
Description=Ragnar Pwnagotchi Migration Check
After=local-fs.target network-online.target
Before=pwnagotchi.service ragnar.service
ConditionPathExists=/opt/pwnagotchi

[Service]
Type=oneshot
ExecStart=${MIGRATE_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVCEOF
        chmod 644 "/etc/systemd/system/ragnar-pwn-migrate.service"
        systemctl daemon-reload
        systemctl enable ragnar-pwn-migrate >/dev/null 2>&1 || true
        echo -e "${GREEN}Boot-time migration service installed.${NC}"
    fi
else
    echo -e "${GREEN}No Pwnagotchi installation found or migration script missing. Skipping.${NC}"
fi

echo -e "${BLUE}Step 6.8: Ensuring radios are unblocked (rfkill)...${NC}"
# USB Bluetooth and monitor-mode/injection WiFi dongles come up soft-blocked
# and stay dead until unblocked. Unblock now and install a persistent udev
# rule so it also works at boot and on hot-plug. Idempotent.
if command -v rfkill >/dev/null 2>&1; then
    rfkill unblock all
    RFKILL_BIN="$(command -v rfkill)"
    cat > /etc/udev/rules.d/99-ragnar-rfkill.rules << RFEOF
# Ragnar: auto-unblock every radio when it appears (boot + hot-plug).
# USB Bluetooth and monitor-mode/injection WiFi dongles are soft-blocked by
# default and stay dead until unblocked.
SUBSYSTEM=="rfkill", ACTION=="add", RUN+="$RFKILL_BIN unblock all"
RFEOF
    chmod 644 /etc/udev/rules.d/99-ragnar-rfkill.rules
    if command -v udevadm >/dev/null 2>&1; then
        udevadm control --reload-rules 2>/dev/null || true
        udevadm trigger --subsystem-match=rfkill 2>/dev/null || true
    fi
    echo -e "${GREEN}All radios unblocked and persistent rfkill rule installed.${NC}"
else
    echo -e "${YELLOW}rfkill not available - skipping radio unblock.${NC}"
fi

echo -e "${BLUE}Step 6.9: Ensuring network diagnostic tools...${NC}"
# Tools for the Network > Diagnostics / Switch & L2 / Interfaces tabs.
# Idempotent so existing installs pick them up on update (Debian/apt).
if command -v apt-get >/dev/null 2>&1; then
    NET_PKGS=""
    for pair in "traceroute:traceroute" "mtr:mtr-tiny" "whois:whois" "lldpctl:lldpd" "ethtool:ethtool" "speedtest-cli:speedtest-cli"; do
        bin="${pair%%:*}"; pkg="${pair##*:}"
        command -v "$bin" >/dev/null 2>&1 || NET_PKGS="$NET_PKGS $pkg"
    done
    if [ -n "$NET_PKGS" ]; then
        echo -e "  Installing:$NET_PKGS"
        DEBIAN_FRONTEND=noninteractive apt-get install -y $NET_PKGS >/dev/null 2>&1 \
            && echo -e "  ${GREEN}✓${NC} Installed network tools" \
            || echo -e "  ${YELLOW}!${NC} Some network tools failed to install"
    else
        echo -e "  ${GREEN}✓${NC} Network tools already present"
    fi
fi
# Configure lldpd to also decode CDP/EDP/FDP/SONMP (non-LLDP switches)
if command -v lldpd >/dev/null 2>&1 || command -v lldpctl >/dev/null 2>&1; then
    mkdir -p /etc/default
    cat > /etc/default/lldpd << 'LLDPEOF'
# Ragnar: decode CDP (Cisco), EDP (Extreme), FDP (Foundry), SONMP (Nortel)
# neighbours in addition to LLDP, so switch discovery covers non-LLDP gear.
DAEMON_ARGS="-c -e -f -s"
LLDPEOF
    systemctl enable lldpd >/dev/null 2>&1 || true
    systemctl restart lldpd >/dev/null 2>&1 || true
    echo -e "  ${GREEN}✓${NC} lldpd configured for switch discovery"
fi

echo -e "${BLUE}Step 7: Starting ragnar service...${NC}"
systemctl start ragnar.service

# Check if service started successfully
sleep 3
if systemctl is-active --quiet ragnar.service; then
    echo -e "${GREEN}ragnar service started successfully!${NC}"
else
    echo -e "${RED}Warning: ragnar service failed to start. Check logs with:${NC}"
    echo -e "${YELLOW}sudo journalctl -u ragnar.service -f${NC}"
fi

echo -e "\n${GREEN}Update completed!${NC}"
echo -e "${BLUE}To check if your local changes were backed up:${NC}"
echo -e "  git stash list"
echo -e "${BLUE}To restore your local changes if needed:${NC}"
echo -e "  git stash pop"
echo -e "${BLUE}To check service status:${NC}"
echo -e "  sudo systemctl status ragnar.service"
