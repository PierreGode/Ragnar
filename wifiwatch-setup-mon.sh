#!/usr/bin/env bash
# wifiwatch-setup-mon.sh — put a wireless NIC into PASSIVE monitor mode.
# On the Alfa AWUS036AXM (mt7921u) passive monitor is the stable path; we never
# inject, and channel retuning is done by the tool via `iw set freq` (RX only).
set -euo pipefail
IFACE="${1:-wlan1}"
REG="${2:-US}"
iw dev "$IFACE" info >/dev/null 2>&1 || { echo "no such iface: $IFACE" >&2; exit 1; }
iw reg set "$REG" || true
nmcli dev set "$IFACE" managed no 2>/dev/null || systemctl stop NetworkManager 2>/dev/null || true
ip link set "$IFACE" down
iw dev "$IFACE" set type monitor
ip link set "$IFACE" up
echo "$IFACE is now in monitor mode (reg $REG)."
iw dev "$IFACE" info | sed -n 's/^\t//p'
