#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# wifidef_dedicate.sh — claim a WiFi adapter as a DEDICATED passive monitor for
# Ragnar WiFi Defense, once, at boot (meant for systemd ExecStart / a sensor box
# that owns the adapter). Switch-mode: the whole interface becomes type=monitor,
# so there's no shared-radio vif, no runtime enable/disable dance, and none of
# the EBUSY / "ragmon0 disappeared" failure modes.
#
# Delegates to wifi_defense.py so the claim logic lives in ONE place (regdomain,
# NM/wpa_supplicant/dhclient release, switch to monitor, verify). WiFi Defense
# then just captures on the already-monitor interface.
#
# Usage:  wifidef_dedicate.sh <iface> [regdomain] [init_freq_mhz] [six_ghz:0|1]
#   e.g.  wifidef_dedicate.sh wlan1 US 2437 0
# Env (override args):  WIFIDEF_IFACE, WIFIDEF_REGDOMAIN, WIFIDEF_INIT_FREQ,
#                       WIFIDEF_SIX_GHZ
# ---------------------------------------------------------------------------
set -euo pipefail

# Run as root — monitor-mode + reg set need it.
if [ "$(id -u)" -ne 0 ]; then exec sudo -E bash "$0" "$@"; fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"

IFACE="${1:-${WIFIDEF_IFACE:-}}"
REG="${2:-${WIFIDEF_REGDOMAIN:-}}"
INIT_FREQ="${3:-${WIFIDEF_INIT_FREQ:-}}"
SIX_GHZ="${4:-${WIFIDEF_SIX_GHZ:-0}}"

if [ -z "$IFACE" ]; then
  echo "[wifidef-dedicate] ERROR: no interface given (arg 1 or WIFIDEF_IFACE)" >&2
  exit 1
fi
if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "[wifidef-dedicate] ERROR: interface $IFACE not found" >&2
  exit 1
fi

args=(dedicate --interface "$IFACE")
[ -n "$REG" ]        && args+=(--regdomain "$REG")
[ -n "$INIT_FREQ" ]  && args+=(--init-freq "$INIT_FREQ")
[ "$SIX_GHZ" = "1" ] && args+=(--six-ghz)

echo "[wifidef-dedicate] claiming $IFACE as dedicated monitor (${args[*]})"
exec python3 "$REPO/wifi_defense.py" "${args[@]}"
