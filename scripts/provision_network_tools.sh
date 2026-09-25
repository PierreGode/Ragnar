#!/bin/bash
#
# provision_network_tools.sh
#
# Idempotent system provisioning shared by the CLI updater (update_ragnar.sh)
# and the in-app "Update" button (webapp_modern.py -> _execute_git_update).
# Historically only the CLI updater installed these, so updating from the
# Settings tab left a device without traceroute/mtr/lldpd/arp-scan etc. and
# with radios still rfkill-blocked. This one script is the single source of
# truth so both paths provision identically.
#
# Does three things, each safe to re-run:
#   1. Unblock all radios (rfkill) + install a persistent boot/hot-plug rule.
#   2. Install network diagnostic tools (with per-distro package fallbacks).
#   3. Configure lldpd to decode CDPv1/v2, EDP, FDP and SONMP for switch discovery.
#
# Must run as root. Prints plain progress lines; never exits non-zero for a
# single failed tool so a partial environment still gets everything it can.

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
# No colors when output is captured (e.g. the in-app Update button pipes this
# through subprocess) so the web UI doesn't show raw ANSI escape codes.
if [ ! -t 1 ]; then
    GREEN=''; YELLOW=''; NC=''
fi

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${YELLOW}provision_network_tools.sh must run as root - skipping.${NC}"
    exit 0
fi

# ---------------------------------------------------------------------------
# 1. Radios unblocked (rfkill)
# ---------------------------------------------------------------------------
# USB Bluetooth and monitor-mode/injection WiFi dongles come up soft-blocked
# and stay dead until unblocked. Unblock now and install a persistent udev
# rule so it also survives reboot and hot-plug.
echo -e "Ensuring radios are unblocked (rfkill)..."
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

# ---------------------------------------------------------------------------
# 2. Network diagnostic tools
# ---------------------------------------------------------------------------
# Tools for the Network > Diagnostics / Switch & L2 / Interfaces tabs.
# Package names (and their fallbacks) mirror install_ragnar.sh so distros that
# name a package differently -- mtr vs mtr-tiny, whois vs jwhois, the
# speedtest-cli python variants -- still resolve instead of silently failing.
echo -e "Ensuring network diagnostic tools..."
if command -v apt-get >/dev/null 2>&1; then
    # sbin tools (lldpctl, arp-scan, ethtool, traceroute) may not be on a bare
    # PATH; make sure the presence checks can find them.
    export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"
    # "binary:pkg1 pkg2 ..." -- first candidate package that provides the
    # binary wins; remaining candidates are only tried if it is still missing.
    net_tools=(
        "traceroute:traceroute"
        "mtr:mtr-tiny mtr"
        "whois:whois jwhois"
        "lldpctl:lldpd"
        "arp-scan:arp-scan arpscan"
        "ethtool:ethtool"
        "speedtest-cli:speedtest-cli python3-speedtest-cli python-speedtest-cli"
    )
    # Refresh the package index once, but only if something is actually missing
    # -- an update run never did `apt-get update`, so installs against a stale
    # index silently failed (unlike a fresh install, which updates first).
    need_net_install=false
    for entry in "${net_tools[@]}"; do
        command -v "${entry%%:*}" >/dev/null 2>&1 || { need_net_install=true; break; }
    done
    # ...but not on every single update. Some of these tools are simply not
    # packaged for every suite (speedtest-cli is the usual one), so "something is
    # missing" can be permanently true - and that turned a minutes-long
    # apt-get update into a fixed cost of every update on those boxes, with the
    # update card sitting on "Finishing update: network tools..." each time.
    # Refresh at most once every six hours; a genuinely missing package is still
    # retried immediately against the index already on disk.
    APT_STAMP=/var/lib/ragnar/apt-index-refreshed
    if [ "$need_net_install" = true ]; then
        stamp_age=999999
        if [ -f "$APT_STAMP" ]; then
            stamp_age=$(( $(date +%s) - $(stat -c %Y "$APT_STAMP" 2>/dev/null || echo 0) ))
        fi
        if [ "$stamp_age" -gt 21600 ]; then
            echo -e "  Refreshing package index..."
            DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
            mkdir -p "$(dirname "$APT_STAMP")" 2>/dev/null || true
            touch "$APT_STAMP" 2>/dev/null || true
        else
            echo -e "  Package index refreshed $((stamp_age / 60))m ago - reusing it"
        fi
    fi
    for entry in "${net_tools[@]}"; do
        bin="${entry%%:*}"; pkgs="${entry#*:}"
        if command -v "$bin" >/dev/null 2>&1; then
            continue
        fi
        installed=false
        for pkg in $pkgs; do
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>&1 || true
            if command -v "$bin" >/dev/null 2>&1; then
                echo -e "  ${GREEN}✓${NC} Installed $bin ($pkg)"
                installed=true
                break
            fi
        done
        if [ "$installed" = false ]; then
            echo -e "  ${YELLOW}!${NC} Could not install $bin (tried: $pkgs)"
        fi
    done
    echo -e "  ${GREEN}✓${NC} Network tools checked"
else
    echo -e "${YELLOW}apt-get not available - skipping network tool install.${NC}"
fi

# The speedtest diagnostic (network_diagnostics.py) probes `speedtest-cli`
# first, then a bare `speedtest`. The apt speedtest-cli package usually ships
# both binaries, but on distros where it only provides speedtest-cli, guarantee
# a `speedtest` alias too so neither lookup can miss.
if command -v speedtest-cli >/dev/null 2>&1 && ! command -v speedtest >/dev/null 2>&1; then
    ln -sf "$(command -v speedtest-cli)" /usr/local/bin/speedtest \
        && echo -e "  ${GREEN}✓${NC} Linked speedtest -> speedtest-cli"
fi

# ---------------------------------------------------------------------------
# 3. lldpd switch-discovery decoding
# ---------------------------------------------------------------------------
# Configure lldpd to also decode CDPv1/v2, EDP, FDP and SONMP (non-LLDP switches)
if command -v lldpd >/dev/null 2>&1 || command -v lldpctl >/dev/null 2>&1; then
    mkdir -p /etc/default
    cat > /etc/default/lldpd << 'LLDPEOF'
# Ragnar: decode CDPv1/v2 (Cisco), EDP (Extreme), FDP (Foundry), SONMP (Nortel)
# neighbours in addition to LLDP, so switch discovery covers non-LLDP gear.
DAEMON_ARGS="-c -e -f -s"
LLDPEOF
    systemctl enable lldpd >/dev/null 2>&1 || true
    systemctl restart lldpd >/dev/null 2>&1 || true
    echo -e "  ${GREEN}✓${NC} lldpd configured for switch discovery"
fi

exit 0
