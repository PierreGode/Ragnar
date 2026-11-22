#!/bin/bash
#
# install_ulfberht_extras.sh
#
# On-demand installer for the Ulfberht "arsenal extras" — the lighter recon/OSINT
# tools and the WPA-Enterprise Wi-Fi set that are NOT baked into the image (the
# core wireless / AD / pivoting arsenals are baked by the RagnarOS build). The
# Engagements tab drives this via sudo; it is also runnable by hand.
#
# Kali / Ulfberht only. Prints plain progress lines (the web UI tails them) and
# never exits non-zero for a single failed tool — a partial environment still
# gets everything it can. The final VALIDATION block lists what is / isn't
# present so the UI (and the operator) can see the real outcome.

set -uo pipefail

log() { printf '%s\n' "$*"; }

# ── Edition / base gate ─────────────────────────────────────────────────────
# These are offensive Kali packages; refuse to install them anywhere that isn't
# the Ulfberht image or a Kali base, so a standard box or a bare git clone can't
# be talked into pulling them in.
is_ulfberht_or_kali() {
    local m
    for m in /etc/ragnar-edition /boot/firmware/ragnar-edition; do
        [ -f "$m" ] && grep -qi 'ulfberht' "$m" 2>/dev/null && return 0
    done
    [ "${RAGNAR_EDITION:-}" = "ulfberht" ] && return 0
    [ -f /etc/kali_version ] && return 0
    if [ -r /etc/os-release ]; then
        . /etc/os-release 2>/dev/null
        [ "${ID:-}" = "kali" ] && return 0
        case " ${ID_LIKE:-} " in *" kali "*) return 0 ;; esac
    fi
    return 1
}

if ! is_ulfberht_or_kali; then
    log "ERROR: the arsenal extras are Ulfberht/Kali-only; refusing on this base."
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: must run as root (the web UI calls this via sudo)."
    exit 3
fi
if ! command -v apt-get >/dev/null 2>&1; then
    log "ERROR: apt-get not found — unexpected on a Kali base."
    exit 4
fi

export DEBIAN_FRONTEND=noninteractive

# "binary:candidate-packages" — the first candidate package that actually puts
# the binary on PATH wins; the rest are only tried if it is still missing.
#   recon / OSINT (tier 3) + WPA-Enterprise Wi-Fi (tier 4)
EXTRAS=(
    "subfinder:subfinder"
    "httpx:httpx-toolkit httpx"
    "dnsx:dnsx"
    "katana:katana"
    "dnsrecon:dnsrecon"
    "dnsenum:dnsenum"
    "theHarvester:theharvester"
    "searchsploit:exploitdb"
    "mdk4:mdk4"
    "eaphammer:eaphammer"
    "hostapd-wpe:hostapd-wpe"
)

# Refresh the index once, but only if something is actually missing — an
# already-complete box shouldn't pay for a minutes-long apt-get update.
need=false
for e in "${EXTRAS[@]}"; do
    command -v "${e%%:*}" >/dev/null 2>&1 || { need=true; break; }
done
if [ "$need" = true ]; then
    log "Refreshing package index…"
    apt-get update -y >/dev/null 2>&1 \
        || log "WARN: apt-get update failed; trying installs against the on-disk index."
else
    log "All extras already present — nothing to install."
fi

for e in "${EXTRAS[@]}"; do
    bin="${e%%:*}"; pkgs="${e#*:}"
    if command -v "$bin" >/dev/null 2>&1; then
        log "✓ $bin already installed"
        continue
    fi
    log "Installing $bin…"
    ok=false
    for p in $pkgs; do
        apt-get install -y "$p" >/dev/null 2>&1 || true
        if command -v "$bin" >/dev/null 2>&1; then
            log "  ✓ $bin ($p)"
            ok=true
            break
        fi
    done
    [ "$ok" = true ] || log "  ✗ $bin — not available via apt (tried: $pkgs)"
done

# ── Validation summary ──────────────────────────────────────────────────────
# The UI reads the VALIDATION / DONE lines; keep the tokens stable.
log "VALIDATION:"
present=0; total=0
for e in "${EXTRAS[@]}"; do
    bin="${e%%:*}"; total=$((total + 1))
    if command -v "$bin" >/dev/null 2>&1; then
        log "  [OK]   $bin"
        present=$((present + 1))
    else
        log "  [MISS] $bin"
    fi
done
log "DONE: $present/$total extras present."
exit 0
