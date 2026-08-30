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

# Never let git stop and wait for a human. A checkout whose origin wants
# credentials, or an ssh remote with an unknown host key, otherwise parks on a
# prompt - and when this script is driven from a service or a cron job there is
# nobody to answer it, so the update hangs instead of failing. Same guards the
# in-app updater (git_updater.py) applies.
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=echo
export SSH_ASKPASS=echo
export SSH_ASKPASS_REQUIRE=never
export GIT_SSH_COMMAND="ssh -oBatchMode=yes -oStrictHostKeyChecking=accept-new -oConnectTimeout=15"

echo -e "${BLUE}ragnar Update Script${NC}"
echo -e "${YELLOW}This will update ragnar while preserving your data and configurations.${NC}"

# Check if we're in the right directory
if [ ! -d "$ragnar_PATH" ]; then
    echo -e "${RED}Error: ragnar directory not found at $ragnar_PATH${NC}"
    exit 1
fi

cd "$ragnar_PATH"

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root. Please use 'sudo'.${NC}"
    exit 1
fi

# A working git is a hard prerequisite, and on some boards it is exactly what is
# broken: Debian Trixie arm64 can ship a git built with ARMv8.1+ atomics that
# dies with SIGILL on a Cortex-A53 (Pi Zero 2 W). The installer detects this and
# falls back to tarball downloads, so a box can be running Ragnar perfectly well
# with no usable git at all. Say so plainly rather than failing on a git command.
if ! git --version >/dev/null 2>&1; then
    echo -e "${RED}Error: git does not run on this system.${NC}"
    echo -e "${YELLOW}If this is a Pi Zero 2 W (or another Cortex-A53 board), the packaged"
    echo -e "git may be built for a newer ARM revision and crash with 'Illegal"
    echo -e "instruction'. Confirm with:${NC}"
    echo -e "    git --version"
    echo -e "${YELLOW}Then try reinstalling it:${NC}"
    echo -e "    sudo apt update && sudo apt install --reinstall git"
    echo -e "${YELLOW}Ragnar itself keeps running — only updates need git.${NC}"
    exit 1
fi

# Repair a tarball install. When git was unusable at install time the installer
# unpacks a release tarball instead of cloning, which leaves a complete, working
# tree with no .git in it — and every update from then on had nothing to work
# with. If git runs now, rebuild the repository metadata in place rather than
# dead-ending the user into a full reinstall. The working tree is left alone;
# only .git is created, so local data files are untouched.
if [ ! -d "$ragnar_PATH/.git" ]; then
    echo -e "${YELLOW}No .git found — this box was installed from a tarball.${NC}"
    echo -e "${BLUE}Reattaching it to the upstream repository (your files are kept)...${NC}"
    if git init -q "$ragnar_PATH" 2>/dev/null \
       && git -C "$ragnar_PATH" remote add origin https://github.com/PierreGode/Ragnar.git 2>/dev/null \
       && git -C "$ragnar_PATH" fetch --depth=1 origin main 2>/dev/null; then
        # Point main at upstream WITHOUT touching the working tree, so the files
        # already on disk (including local data) survive. Anything that differs
        # from upstream simply shows up as a normal local modification, which
        # the stash step below then handles like any other update.
        git -C "$ragnar_PATH" reset -q --mixed FETCH_HEAD 2>/dev/null || true
        git -C "$ragnar_PATH" branch -q -f main FETCH_HEAD 2>/dev/null || true
        git -C "$ragnar_PATH" symbolic-ref HEAD refs/heads/main 2>/dev/null || true
        git -C "$ragnar_PATH" branch -q --set-upstream-to=origin/main main 2>/dev/null || true
        # Restore only files upstream has that the tree is missing. A tarball
        # can be short of files (.github, dotfiles) that would otherwise look
        # like deliberate local deletions and get stashed by the step below.
        # Deleted-only: modified files are left alone so real local edits still
        # reach the stash/merge path intact.
        git -C "$ragnar_PATH" ls-files -d -z 2>/dev/null \
            | xargs -0 -r git -C "$ragnar_PATH" checkout -- 2>/dev/null || true
        echo -e "${GREEN}Repository metadata rebuilt — continuing with the update.${NC}"
    else
        rm -rf "$ragnar_PATH/.git"
        echo -e "${RED}Error: could not reattach to the upstream repository.${NC}"
        echo -e "${YELLOW}Check network access to github.com, then re-run this script.${NC}"
        exit 1
    fi
fi

# ── Docker deployment: update the container, skip the native flow ─────────────
# If Ragnar runs here as a Docker container (compose service name 'ragnar') and
# there is NO native systemd service, this box is a container deployment. Update
# it the Docker way — pull the code, rebuild the image, restart the container —
# and skip every native step (service stop/start, host pip installs, hardware
# tweaks). Detection is deliberately strict: a real native install (service
# present) always falls through to the unchanged flow below, even if a stray
# 'ragnar' container also exists, so nothing here can break native updates.
if command -v docker >/dev/null 2>&1 \
   && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx 'ragnar' \
   && ! systemctl is-active --quiet ragnar.service 2>/dev/null \
   && ! systemctl list-unit-files 2>/dev/null | grep -q '^ragnar\.service'; then
    echo -e "\n${BLUE}Docker deployment detected — updating the container instead of a native install.${NC}"

    # Same dubious-ownership guard the native path uses (root over a ragnar-owned
    # checkout), so the pull below does not stop on it.
    git config --global --get-all safe.directory 2>/dev/null | grep -qxF "$ragnar_PATH" \
        || git config --global --add safe.directory "$ragnar_PATH"
    find "$ragnar_PATH/.git" -name '*.lock' -type f -delete 2>/dev/null || true

    DOCKER_BRANCH="$(git -C "$ragnar_PATH" rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)"
    echo -e "${BLUE}Pulling latest code (${DOCKER_BRANCH})...${NC}"
    if ! git -C "$ragnar_PATH" pull --ff-only origin "$DOCKER_BRANCH"; then
        echo -e "${YELLOW}Fast-forward pull failed — forcing to origin/${DOCKER_BRANCH} (local edits are kept in git's reflog)...${NC}"
        if ! { git -C "$ragnar_PATH" fetch origin "$DOCKER_BRANCH" \
               && git -C "$ragnar_PATH" reset --hard "origin/${DOCKER_BRANCH}"; }; then
            echo -e "${RED}git update failed — aborting Docker update (container left running).${NC}"
            exit 1
        fi
    fi

    # Pick the compose command (v2 plugin preferred, v1 fallback).
    if docker compose version >/dev/null 2>&1; then
        DOCKER_COMPOSE="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        DOCKER_COMPOSE="docker-compose"
    else
        echo -e "${RED}Docker Compose not found. Rebuild manually:${NC} cd $ragnar_PATH && docker compose up -d --build"
        exit 1
    fi

    # Preserve the port the container is already bound to (host networking uses
    # RAGNAR_WEB_PORT), so an update never silently moves the UI off its port.
    DOCKER_WEB_PORT="$(docker inspect ragnar --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
        | sed -n 's/^RAGNAR_WEB_PORT=//p' | head -1)"
    DOCKER_WEB_PORT="${DOCKER_WEB_PORT:-8000}"

    echo -e "${BLUE}Rebuilding image and restarting container (RAGNAR_WEB_PORT=${DOCKER_WEB_PORT}) — this can take a few minutes...${NC}"
    if ( cd "$ragnar_PATH" && RAGNAR_WEB_PORT="$DOCKER_WEB_PORT" $DOCKER_COMPOSE up -d --build ); then
        DOCKER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
        echo -e "\n${GREEN}Docker deployment updated successfully.${NC}"
        echo -e "  ${GREEN}Web UI:${NC} http://${DOCKER_IP:-<host-ip>}:${DOCKER_WEB_PORT}"
        echo -e "  ${BLUE}Logs:${NC}   cd $ragnar_PATH && $DOCKER_COMPOSE logs -f"
        exit 0
    else
        echo -e "\n${RED}Docker rebuild failed. Inspect with:${NC} cd $ragnar_PATH && $DOCKER_COMPOSE logs"
        exit 1
    fi
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
# Clear ALL stale git locks (index/HEAD/shallow AND ref locks like
# refs/remotes/origin/<branch>.lock, packed-refs.lock, config.lock) so an
# interrupted run never leaves a lock that needs a manual service stop.
find "$ragnar_PATH/.git" -name '*.lock' -type f -delete 2>/dev/null || true
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
# A branch that upstream no longer has (a leftover test branch, a rename) makes
# every pull below fail with "couldn't find remote ref" and nothing recovers
# from it. Fall back to whatever origin's default branch is.
if ! git rev-parse --verify --quiet "refs/remotes/origin/$CURRENT_BRANCH" >/dev/null; then
    DEFAULT_BRANCH="$(git symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null | sed 's|^origin/||')"
    [ -z "$DEFAULT_BRANCH" ] && DEFAULT_BRANCH=main
    echo -e "${YELLOW}Branch '$CURRENT_BRANCH' does not exist on origin - updating from '$DEFAULT_BRANCH' instead.${NC}"
    git checkout -B "$DEFAULT_BRANCH" "origin/$DEFAULT_BRANCH" 2>/dev/null || true
    CURRENT_BRANCH="$DEFAULT_BRANCH"
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

echo -e "${BLUE}Step 5.1: Checking package system health...${NC}"
# apt refuses every operation while a previous dpkg run is unfinished
# ("E: dpkg was interrupted, you must manually run 'dpkg --configure -a'").
# A low-memory Pi reaches that state easily — an OOM kill, power loss, or a
# Ctrl-C mid-install — and it then blocks every apt call below. Idempotent and
# a no-op on a healthy system.
if [ -n "$(ls -A /var/lib/dpkg/updates 2>/dev/null)" ] || [ -n "$(dpkg --audit 2>/dev/null)" ]; then
    echo -e "  ${YELLOW}⚠${NC} dpkg is in an interrupted state — repairing"
    DEBIAN_FRONTEND=noninteractive dpkg --configure -a >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -f -y >/dev/null 2>&1 || true
    if [ -n "$(dpkg --audit 2>/dev/null)" ]; then
        echo -e "  ${YELLOW}⚠${NC} dpkg still reports problems — run: sudo dpkg --configure -a"
    else
        echo -e "  ${GREEN}✓${NC} dpkg state repaired"
    fi
fi

echo -e "${BLUE}Step 5.2: Ensuring Bluetooth overlay dependencies...${NC}"
# The WiFi-analyzer Bluetooth/BLE 2.4 GHz overlay (bt_scanner.py) talks to BlueZ
# over D-Bus via python3-dbus, and needs bluez/bluetoothctl. The BLE
# provisioning peripheral (ble_provisioning.py) additionally needs python3-gi
# for its GLib main loop. These ship in the installer; ensure them here too so
# update-only boxes get both. Guarded and idempotent — only apt-installs a
# package that is actually missing.
for _btpkg in python3-dbus python3-gi bluez; do
    if ! dpkg -s "$_btpkg" >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$_btpkg" >/dev/null 2>&1 \
            && echo -e "  ${GREEN}✓${NC} Installed $_btpkg (Bluetooth overlay)" \
            || echo -e "  ${YELLOW}⚠${NC} Could not install $_btpkg — the overlay falls back to bluetoothctl text mode"
    fi
done
# Optional tooling. Each backs one feature that resolves the binary at runtime
# and disables itself when it is missing (hackrf → the HackRF 2.4/5/6 GHz half of
# the RF Waterfall in sdr_spectrum.py; the rest → the recon/vuln scanners, which
# server_capabilities already marks 'critical': False). Not every suite ships all
# of them — ffuf only entered Debian in trixie — so a miss is reported and
# skipped, never fatal. (rtl-sdr/rtl-433 for the RTL-SDR sub-GHz half get their
# own self-healing block below, together with the DVB-T blacklist they need.)
_missing_optional=()
for _opt in hackrf:"RF Waterfall (Wi-Fi bands)" nikto:"vuln scanner" \
            sqlmap:"vuln scanner" whatweb:"vuln scanner" ffuf:"content discovery"; do
    _pkg="${_opt%%:*}"; _why="${_opt#*:}"
    dpkg -s "$_pkg" >/dev/null 2>&1 && continue
    if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$_pkg" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Installed $_pkg ($_why)"
    else
        _missing_optional+=("$_pkg")
    fi
done
if [ ${#_missing_optional[@]} -gt 0 ]; then
    echo -e "  ${YELLOW}⚠${NC} Not available in this suite: ${_missing_optional[*]} — the features using them stay disabled"
fi

# RTL-SDR support (RTL-SDR Blog V3/V4, Nooelec NESDR, RTL-SDR.com, generic
# RTL2832U) for the sub-GHz RF Waterfall + ISM decoder. Two things must be true
# for a plugged-in dongle to work, so we guarantee BOTH here (self-healing —
# mirrors install_ragnar.sh so update-only boxes get the full setup in one run):
#   1) the rtl-sdr + rtl-433 tools are installed;
#   2) the DVB-T kernel driver is blacklisted + unloaded so it can't grab the
#      device before rtl_power / rtl_433 / rtl_test can.
if ! command -v rtl_test >/dev/null 2>&1; then
    if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends rtl-sdr rtl-433 >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Installed rtl-sdr + rtl-433 (RTL-SDR sub-GHz / ISM)"
    else
        echo -e "  ${YELLOW}⚠${NC} Could not install rtl-sdr/rtl-433 — RTL-SDR features stay disabled until they're present"
    fi
fi
if command -v rtl_test >/dev/null 2>&1 || dpkg -s rtl-sdr >/dev/null 2>&1; then
    _rtl_bl=/etc/modprobe.d/blacklist-rtl-sdr.conf
    if ! grep -q "dvb_usb_rtl28xxu" "$_rtl_bl" 2>/dev/null; then
        cat > "$_rtl_bl" << 'EOF'
# Ragnar: keep the DVB-T kernel drivers off RTL-SDR dongles so rtl_power /
# rtl_433 / rtl_test can claim them (RTL-SDR Blog V3/V4, Nooelec NESDR, generic).
blacklist dvb_usb_rtl28xxu
blacklist rtl2832
blacklist rtl2830
blacklist rtl2838
EOF
        chmod 644 "$_rtl_bl"
        echo -e "  ${GREEN}✓${NC} Blacklisted DVB-T kernel driver so RTL-SDR dongles are usable"
    fi
    rmmod dvb_usb_rtl28xxu 2>/dev/null || true
    command -v rtl_test >/dev/null 2>&1 \
        && echo -e "  ${GREEN}✓${NC} RTL-SDR tools ready (rtl_test / rtl_power / rtl_433)"
    # dump1090 powers the ADS-B radar (1090 MHz aircraft). Not in standard apt
    # repos, so the helper tries apt then builds from source (only runs when it's
    # actually missing, so it's a one-time cost). Best-effort.
    if ! command -v dump1090-fa >/dev/null 2>&1 && ! command -v dump1090-mutability >/dev/null 2>&1 && ! command -v dump1090 >/dev/null 2>&1; then
        if [ -x "$ragnar_PATH/scripts/install_dump1090.sh" ] \
           && bash "$ragnar_PATH/scripts/install_dump1090.sh" >/dev/null 2>&1; then
            echo -e "  ${GREEN}✓${NC} Installed dump1090 (ADS-B radar, 1090 MHz)"
        fi
    fi
    # acarsdec powers the ADS-B ACARS panel (VHF datalink). Build from source.
    if ! command -v acarsdec >/dev/null 2>&1; then
        if [ -x "$ragnar_PATH/scripts/install_acarsdec.sh" ] \
           && bash "$ragnar_PATH/scripts/install_acarsdec.sh" >/dev/null 2>&1; then
            echo -e "  ${GREEN}✓${NC} Installed acarsdec (ADS-B ACARS datalink)"
        fi
    fi
    # dumpvdl2 (+ libacars) powers the VDL Mode 2 / ATN panel (CPDLC + ADS-C).
    if ! command -v dumpvdl2 >/dev/null 2>&1; then
        if [ -x "$ragnar_PATH/scripts/install_dumpvdl2.sh" ] \
           && bash "$ragnar_PATH/scripts/install_dumpvdl2.sh" >/dev/null 2>&1; then
            echo -e "  ${GREEN}✓${NC} Installed dumpvdl2 + libacars (VDL Mode 2 / ATN datalink)"
        fi
    fi
    # meshtastic Python package for the Mesh Nodes page (USB companion node).
    if ! python3 -c "import meshtastic" >/dev/null 2>&1; then
        command -v pip3 >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3-pip >/dev/null 2>&1
        if pip3 install --break-system-packages meshtastic >/dev/null 2>&1 || pip3 install meshtastic >/dev/null 2>&1; then
            echo -e "  ${GREEN}✓${NC} Installed meshtastic (Mesh Nodes companion)"
        fi
    fi
    # multimon-ng powers the Pager Decode page (POCSAG/FLEX) — it IS in the repos.
    if ! command -v multimon-ng >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends multimon-ng >/dev/null 2>&1 \
            && echo -e "  ${GREEN}✓${NC} Installed multimon-ng (Pager Decode)"
    fi
fi

# Firefox backs the ZAP AJAX-spider browser crawl (advanced_vuln_scanner looks up
# firefox/firefox-esr at runtime). Ship it to update-only boxes too. Debian and
# Pi OS provide it as firefox-esr; try that first, then plain firefox for other
# suites. Idempotent — skipped when either binary is already present.
if ! command -v firefox >/dev/null 2>&1 && ! command -v firefox-esr >/dev/null 2>&1; then
    if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends firefox-esr >/dev/null 2>&1 \
       || DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends firefox >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Installed Firefox (ZAP AJAX spider)"
    else
        echo -e "  ${YELLOW}⚠${NC} Could not install Firefox — the ZAP AJAX spider falls back to a lighter crawl"
    fi
fi

echo -e "${BLUE}Step 5.3: Ensuring recon engine dependencies...${NC}"
# sslyze (TLS audit), dnspython (DNS recon) and tldextract (domain parsing) back
# three independent recon_engine features. They are deliberately NOT in
# requirements.txt — sslyze pulls nassl, a compiled extension with no wheel for
# every Pi platform, and a failure there must not abort the whole requirements
# install. So they are ensured here, one at a time, preferring apt for the two
# pure-Python ones. Idempotent: an importable module is left alone.
_recon_missing=()
_ensure_recon() {   # <import name> <apt package|-> <pip package> <feature>
    python3 -c "import $1" 2>/dev/null && return 0
    if [ "$2" != "-" ] && ! dpkg -s "$2" >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$2" >/dev/null 2>&1
    fi
    python3 -c "import $1" 2>/dev/null && { echo -e "  ${GREEN}✓${NC} Installed $3 (apt)"; return 0; }
    # Confirm the import, not just pip's exit code — a "successful" install that
    # still cannot be imported must be reported as missing, not as installed.
    if pip3 install --break-system-packages "$3" >/dev/null 2>&1 \
       && python3 -c "import $1" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Installed $3 (pip)"; return 0
    fi
    _recon_missing+=("$3 → $4")
    return 1
}
_ensure_recon "dns.resolver" python3-dnspython  dnspython  "DNS recon"
_ensure_recon "tldextract"   python3-tldextract tldextract "domain parsing"
_ensure_recon "sslyze"       -                  sslyze     "TLS audit scans"
if [ ${#_recon_missing[@]} -gt 0 ]; then
    echo -e "  ${YELLOW}⚠${NC} Recon features unavailable: ${_recon_missing[*]}"
fi

echo -e "${BLUE}Step 5.4: Ensuring Traffic Analysis capture tools...${NC}"
# Traffic Analysis is no longer gated behind server mode — it is a tcpdump pipe
# and runs on any board, Pi Zero included. tcpdump is its one hard requirement
# and the sudoers rule is what lets Ragnar spawn it, so both are ensured here
# for boxes that only ever update. Both are idempotent.
if ! command -v tcpdump >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tcpdump >/dev/null 2>&1 || true
fi
# tshark powers the JA3/IRC sidecars (sudoers already grants it). Best-effort,
# idempotent; preseed the wireshark setuid question so it can't stall.
if ! command -v tshark >/dev/null 2>&1; then
    echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections 2>/dev/null || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark >/dev/null 2>&1 || true
fi
# dig (dnsutils) is a hard requirement for DNS Doctor (do_dns_doctor: multi-
# resolver consensus, NXDOMAIN/bogon probes, DNSSEC negative control, Team-Cymru
# ASN lookups). It degrades to a "Click Install" prompt in the UI when missing,
# but DNS Doctor is a core diagnostic, so ensure it on update-only boxes too.
if ! command -v dig >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends dnsutils >/dev/null 2>&1 || true
fi
if command -v tcpdump >/dev/null 2>&1; then
    if [ ! -f /etc/sudoers.d/ragnar-traffic ]; then
        cat > /etc/sudoers.d/ragnar-traffic << 'EOF'
# Allow ragnar user to run traffic analysis tools without password
ragnar ALL=(ALL) NOPASSWD: /usr/bin/tcpdump
ragnar ALL=(ALL) NOPASSWD: /usr/bin/tshark
ragnar ALL=(ALL) NOPASSWD: /usr/sbin/iftop
ragnar ALL=(ALL) NOPASSWD: /usr/sbin/nethogs
EOF
        chmod 440 /etc/sudoers.d/ragnar-traffic
        echo -e "  ${GREEN}✓${NC} Added sudoers rule for packet capture"
    fi
    echo -e "  ${GREEN}✓${NC} tcpdump present — Traffic Analysis available"
else
    echo -e "  ${YELLOW}⚠${NC} tcpdump missing — Traffic Analysis tab stays hidden (apt install tcpdump)"
fi

echo -e "${BLUE}Step 5.4b: Tailscale subnet-router IP forwarding...${NC}"
# A Ragnar that advertises subnet routes (e.g. an on-site unit that lets an
# off-site scanner reach the LAN over the tunnel) must have IP forwarding on, or
# tailscaled silently drops every forwarded packet. The web UI enables this when
# you advertise a route; this self-heals boxes that were already advertising
# before that fix. Only touches nodes that ARE advertising — others are left as-is.
if command -v tailscale >/dev/null 2>&1 && \
   tailscale debug prefs 2>/dev/null | tr -d ' \n' | grep -q '"AdvertiseRoutes":\["'; then
    cat > /etc/sysctl.d/99-ragnar-tailscale-forwarding.conf <<'EOF'
# Managed by Ragnar — required for Tailscale subnet routing
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
    echo -e "  ${GREEN}✓${NC} IP forwarding on (this node advertises subnet routes)"
else
    echo -e "  ${GREEN}✓${NC} Not a subnet router — IP forwarding left unchanged"
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
bash "$ragnar_PATH/init_data_files.sh"

echo -e "${BLUE}Step 6: Setting correct permissions...${NC}"
chown -R ragnar:ragnar "$ragnar_PATH"
chmod +x "$ragnar_PATH"/*.sh 2>/dev/null || true

# Ensure specific critical scripts are executable
chmod +x "$ragnar_PATH/kill_port_8000.sh" 2>/dev/null || true
chmod +x "$ragnar_PATH/update_ragnar.sh" 2>/dev/null || true
chmod +x "$ragnar_PATH/scripts/"*.sh 2>/dev/null || true

# RuSense sensing unit: upgrade the data-dir ExecStartPre to the root-run
# ('+') self-heal variant that also re-asserts ownership. Without it, files
# left root-owned by sudo runs make CSI recording fail ("internal_error" on
# recording/start) and block adaptive-model saves, since the sensing server
# runs as user ragnar. Idempotent: only rewrites the old plain-mkdir line;
# install_sensing.sh writes the new form on fresh installs.
SENSING_UNIT="/etc/systemd/system/ragnar-sensing.service"
if [ -f "$SENSING_UNIT" ] && grep -q '^ExecStartPre=/bin/mkdir' "$SENSING_UNIT"; then
    sed -i "s|^ExecStartPre=/bin/mkdir .*|ExecStartPre=+/bin/sh -c 'mkdir -p $ragnar_PATH/data/recordings $ragnar_PATH/data/models \&\& chown -R ragnar:ragnar $ragnar_PATH/data/recordings $ragnar_PATH/data/models; chown -f ragnar:ragnar $ragnar_PATH/data/adaptive_model.json; true'|" "$SENSING_UNIT"
    systemctl daemon-reload
    systemctl try-restart ragnar-sensing.service 2>/dev/null || true
    echo -e "${GREEN}Patched ragnar-sensing.service with ownership self-heal.${NC}"
fi

# Lift the multi-node fusion guard from the old 200 ms to 350 ms — field logs
# showed real-world timestamp spread reaching ~330 ms, so 200 ms rejected fusion
# cycles ("Timestamp spread exceeds guard interval"). Only rewrites the exact old
# default, so a hand-tuned value is left alone; idempotent.
if [ -f "$SENSING_UNIT" ] && grep -q '^Environment=WDP_GUARD_INTERVAL_US=200000' "$SENSING_UNIT"; then
    sed -i 's|^Environment=WDP_GUARD_INTERVAL_US=200000|Environment=WDP_GUARD_INTERVAL_US=350000|' "$SENSING_UNIT"
    systemctl daemon-reload
    systemctl try-restart ragnar-sensing.service 2>/dev/null || true
    echo -e "${GREEN}Raised sensing fusion guard to 350 ms (was 200 ms).${NC}"
fi

# ADR-296 (upstream RuView): the sensing-server UDP CSI receiver now defaults to
# loopback-only and drops LAN senders unless a routable bind is opted into. Our
# ESP32 nodes send CSI from the LAN, so a unit whose ExecStart predates the flag
# would silently stop ingesting once the newer binary is deployed. Add
# `--udp-bind 0.0.0.0 --udp-insecure-lan` in place — but ONLY when the installed
# binary actually understands the flag, so an older binary is never fed an
# unknown arg (which would break its startup). Idempotent: skips a unit that
# already carries --udp-bind (including a hand-tuned --udp-allow variant).
if [ -f "$SENSING_UNIT" ] \
   && grep -q '^ExecStart=.*ragnar-sensing-server' "$SENSING_UNIT" \
   && ! grep -q -- '--udp-bind' "$SENSING_UNIT" \
   && /usr/local/bin/ragnar-sensing-server --help 2>/dev/null | grep -q -- '--udp-bind'; then
    sed -i '/^ExecStart=.*ragnar-sensing-server/ s|$| --udp-bind 0.0.0.0 --udp-insecure-lan|' "$SENSING_UNIT"
    systemctl daemon-reload
    systemctl try-restart ragnar-sensing.service 2>/dev/null || true
    echo -e "${GREEN}Added UDP LAN bind to ragnar-sensing.service (ADR-296 CSI fix).${NC}"
fi

# Headless (web-only) installs must never initialize the EPD: SharedData() inits
# the display at import time, seizing SPI0 + GPIO and blanking a DPI/HDMI panel
# on shared-pin boards (HackBerry Pi). The headless entrypoint now sets
# RAGNAR_HEADLESS=1 itself, but make it explicit in the unit too. Idempotent:
# only touches units that already run headlessRagnar.py and lack the var.
RAGNAR_UNIT="/etc/systemd/system/ragnar.service"
if [ -f "$RAGNAR_UNIT" ] && grep -q 'headlessRagnar\.py' "$RAGNAR_UNIT" \
        && ! grep -q '^Environment=RAGNAR_HEADLESS=1' "$RAGNAR_UNIT"; then
    sed -i '/^ExecStart=.*headlessRagnar\.py/i Environment=RAGNAR_HEADLESS=1' "$RAGNAR_UNIT"
    systemctl daemon-reload
    echo -e "${GREEN}Set RAGNAR_HEADLESS=1 on ragnar.service (protects DPI/HDMI panel).${NC}"
fi

echo -e "${BLUE}Step 6.6: Ensuring hardware watchdog (auto-reboot on hard hang)...${NC}"
# Unattended / inline devices should reboot fast if the Pi wedges rather than
# black-holing the link. Enable the BCM watchdog and have systemd pet it.
# Idempotent; the config.txt bit applies on the next reboot.
BOOT_CFG=""
for c in /boot/firmware/config.txt /boot/config.txt; do
    [ -f "$c" ] && { BOOT_CFG="$c"; break; }
done
if [ -n "$BOOT_CFG" ] && ! grep -q '^dtparam=watchdog=on' "$BOOT_CFG"; then
    echo 'dtparam=watchdog=on' >> "$BOOT_CFG"
    echo -e "  ${GREEN}✓${NC} Enabled dtparam=watchdog=on in $BOOT_CFG (reboot to apply)"
fi
if [ -f /etc/systemd/system.conf ]; then
    sed -i '/^#\?RuntimeWatchdogSec=/d;/^#\?RebootWatchdogSec=/d' /etc/systemd/system.conf
    printf 'RuntimeWatchdogSec=15\nRebootWatchdogSec=2min\n' >> /etc/systemd/system.conf
    systemctl daemon-reexec 2>/dev/null || true
    echo -e "  ${GREEN}✓${NC} systemd watchdog set (RuntimeWatchdogSec=15)"
fi

echo -e "${BLUE}Step 6.7: Refreshing kiosk wrapper (if installed)...${NC}"
# Existing kiosk installs keep a COPY of the wrapper at /usr/local/bin; the
# active copy only updates when kiosk is re-installed. Refresh it here so the
# Pi Zero2W/4/5 hardening reaches boxes that just `git pull` + update.
KIOSK_WRAPPER_SRC="$ragnar_PATH/scripts/ragnar_kiosk_run.sh"
if [ -f /usr/local/bin/ragnar-kiosk-run ] && [ -f "$KIOSK_WRAPPER_SRC" ]; then
    install -m 0755 "$KIOSK_WRAPPER_SRC" /usr/local/bin/ragnar-kiosk-run
    echo -e "  ${GREEN}✓${NC} Kiosk wrapper refreshed from repo"
    # Seed the on-screen keyboard so touchscreen typing works on existing kiosk
    # installs too (not just fresh installs). Best-effort, guarded, idempotent:
    # squeekboard for the Wayland/autostart path, matchbox-keyboard for the X
    # service path. The wrapper only launches it when a touchscreen is detected.
    if [ -f /etc/systemd/system/ragnar-kiosk.service ]; then
        OSK_PKG="matchbox-keyboard"; command -v matchbox-keyboard >/dev/null 2>&1 && OSK_PKG=""
    else
        OSK_PKG="squeekboard"; command -v squeekboard >/dev/null 2>&1 && OSK_PKG=""
    fi
    if [ -n "$OSK_PKG" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$OSK_PKG" >/dev/null 2>&1 \
            && echo -e "  ${GREEN}✓${NC} On-screen keyboard installed ($OSK_PKG)" \
            || echo -e "  ${YELLOW}⚠${NC} Could not install on-screen keyboard ($OSK_PKG)"
    fi
    # Seed the kiosk escape-hatch deps (touch ✕ button + Ctrl+Alt+Q hotkey) so
    # existing kiosk installs gain an exit path too — vital on handhelds like the
    # Hackberry Pi CM5 whose keyboard has no easy Ctrl. Best-effort, idempotent;
    # the wrapper only shows the ✕/hotkey when a touchscreen is detected.
    HATCH_PKGS=()
    python3 -c 'import tkinter' >/dev/null 2>&1 || HATCH_PKGS+=(python3-tk)
    command -v xbindkeys >/dev/null 2>&1 || HATCH_PKGS+=(xbindkeys)
    if [ "${#HATCH_PKGS[@]}" -gt 0 ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${HATCH_PKGS[@]}" >/dev/null 2>&1 \
            && echo -e "  ${GREEN}✓${NC} Kiosk escape-hatch deps installed (${HATCH_PKGS[*]})" \
            || echo -e "  ${YELLOW}⚠${NC} Could not install kiosk escape-hatch deps (${HATCH_PKGS[*]})"
    fi
    # Cap the kiosk restart loop on existing service-mode installs (drop-in, so
    # we don't rewrite the generated unit). Idempotent.
    if [ -f /etc/systemd/system/ragnar-kiosk.service ]; then
        install -d -m 0755 /etc/systemd/system/ragnar-kiosk.service.d
        cat > /etc/systemd/system/ragnar-kiosk.service.d/10-restart-limit.conf <<'DROPIN'
[Unit]
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
RestartSec=10
DROPIN
        systemctl daemon-reload 2>/dev/null || true
        echo -e "  ${GREEN}✓${NC} Kiosk restart-loop cap applied (drop-in)"
    fi
fi

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

echo -e "${BLUE}Step 6.8: Provisioning radios + network tools (background)...${NC}"
# rfkill unblock, network diagnostic tools, and lldpd switch decoding now
# live in one shared script so the in-app Update button provisions the same
# things as this CLI updater (see webapp_modern.py _execute_git_update).
# Run it in the background so slow apt installs never hold up the ragnar
# service restart below -- the tools are not needed for ragnar to start.
if [ -f "$ragnar_PATH/scripts/provision_network_tools.sh" ]; then
    mkdir -p "$ragnar_PATH/data/logs"
    nohup bash "$ragnar_PATH/scripts/provision_network_tools.sh" \
        > "$ragnar_PATH/data/logs/provision_network_tools.log" 2>&1 &
    echo -e "  ${GREEN}✓${NC} Provisioning started in background (log: data/logs/provision_network_tools.log)"
else
    echo -e "${YELLOW}provision_network_tools.sh missing - skipping tool provisioning.${NC}"
fi

echo -e "${BLUE}Step 6.9: Ensuring persistent journal...${NC}"
# Raspberry Pi OS defaults to Storage=auto, which keeps logs in RAM unless
# /var/log/journal exists — so a board reset (e.g. a USB WiFi adapter browning
# out the 5V rail) wipes the log that would have explained it and
# `journalctl -b -1` reports "no persistent journal was found". Idempotent, and
# capped so the journal can't fill the SD card. Mirrors install_ragnar.sh.
if [ ! -d /var/log/journal ]; then
    mkdir -p /var/log/journal
    systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
    echo -e "  ${GREEN}✓${NC} Persistent journald logging enabled (survives reboots)"
else
    echo -e "  ${GREEN}✓${NC} Persistent journal already enabled"
fi
if ! grep -qE '^SystemMaxUse=' /etc/systemd/journald.conf 2>/dev/null; then
    sed -i 's/^#\?SystemMaxUse=.*/SystemMaxUse=200M/' /etc/systemd/journald.conf 2>/dev/null || true
    grep -qE '^SystemMaxUse=' /etc/systemd/journald.conf 2>/dev/null \
        || echo 'SystemMaxUse=200M' >> /etc/systemd/journald.conf
fi
systemctl restart systemd-journald >/dev/null 2>&1 || true

echo -e "${BLUE}Step 6.95: Checking Ragnar Mesh prerequisites...${NC}"
# Mesh setup must run on the update path too, not only at install: most users
# only ever update, so an installer-only change never reaches the units that
# already exist. Strictly conditional — a unit that has not opted into the mesh
# gets nothing installed, and one already joined is left alone.
#
# Also picks up an unattended re-provision: dropping /boot/ragnar-mesh.conf onto
# a running unit and updating is a way to move a box onto the mesh with no
# console access at all.
_MESH_SCRIPT="$(dirname "$0")/scripts/setup_mesh.sh"
_MESH_WANTED=false
if [ -n "${RAGNAR_MESH_AUTHKEY:-}" ] || [ -f /boot/ragnar-mesh.conf ] \
   || [ -f /boot/firmware/ragnar-mesh.conf ]; then
    _MESH_WANTED=true
elif grep -q '"mesh_enabled"[[:space:]]*:[[:space:]]*true' \
        "$(dirname "$0")/config/shared_config.json" 2>/dev/null; then
    _MESH_WANTED=true
fi

if [ "$_MESH_WANTED" = true ] && [ -f "$_MESH_SCRIPT" ]; then
    chmod +x "$_MESH_SCRIPT" 2>/dev/null
    if bash "$_MESH_SCRIPT" provision; then
        echo -e "  ${GREEN}✓${NC} Mesh prerequisites in place"
    else
        echo -e "  ${YELLOW}⚠${NC} Mesh setup reported a problem — check the Ragnar Mesh tab"
    fi
elif [ "$_MESH_WANTED" = true ]; then
    echo -e "  ${YELLOW}⚠${NC} Mesh is enabled but scripts/setup_mesh.sh is missing"
else
    echo -e "  ${GREEN}✓${NC} Mesh not enabled on this unit — nothing to do"
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
