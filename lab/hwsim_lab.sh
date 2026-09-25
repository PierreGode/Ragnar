#!/usr/bin/env bash
# hwsim_lab.sh — live-path lab for legacywatch / wpswatch using mac80211_hwsim.
#
# Exercises the REAL capture path (Scapy monitor-mode sniff), not just --replay,
# by injecting a test pcap onto a virtual radio and sniffing it on a second one.
# Injection is off-the-shelf tcpreplay against sealed virtual radios; nothing
# leaves the machine.
#
# REQUIRES root + the mac80211_hwsim kernel module + tcpreplay + iw. It CANNOT
# run on the headless Ragnar dev box (no wireless stack / module) — run it on a
# Linux host where you can `modprobe mac80211_hwsim`.
#
#   sudo ./hwsim_lab.sh legacy
#   sudo ./hwsim_lab.sh wps
#
# Exit 0 = every expected finding code was observed on the live path.
set -euo pipefail

MODE="${1:-}"
case "$MODE" in
  legacy) MODULE=legacywatch; EXPECT="ERP_PROTECTION_ACTIVE NONERP_STA_PRESENT BSS_ADMITS_11B GROUP_CIPHER_TKIP CLIENT_11B_ONLY CLIENT_AIRTIME_DISPROPORTIONATE" ;;
  wps)    MODULE=wpswatch;    EXPECT="WPS_ENABLED WPS_PIN_METHOD_AVAILABLE WPS_VERSION_1 WPS_BRUTE_FORCE_IN_PROGRESS WPS_SESSION_OBSERVED" ;;
  *) echo "usage: sudo $0 {legacy|wps}" >&2; exit 2 ;;
esac

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="$HERE/../python/$MODULE.py"
WORK="$(mktemp -d)"
PCAP="$WORK/$MODE.pcap"
OUT="$WORK/alerts.jsonl"
MON_TX="wlan0"; MON_RX="wlan1"

cleanup() {
  set +e
  [ -n "${WPID:-}" ] && kill "$WPID" 2>/dev/null
  ip link set "$MON_TX" down 2>/dev/null
  ip link set "$MON_RX" down 2>/dev/null
  rmmod mac80211_hwsim 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "[*] building test pcap"
python3 "$HERE/make_lab_pcap.py" "$MODE" "$PCAP"

echo "[*] loading mac80211_hwsim (2 radios)"
modprobe mac80211_hwsim radios=2

echo "[*] putting both radios in monitor mode on channel 6"
for IF in "$MON_TX" "$MON_RX"; do
  ip link set "$IF" down
  iw dev "$IF" set type monitor
  ip link set "$IF" up
  iw dev "$IF" set channel 6 2>/dev/null || true
done

echo "[*] starting $MODULE on $MON_RX (live capture)"
python3 "$PY" -i "$MON_RX" --jsonl "$OUT" &
WPID=$!
sleep 2

echo "[*] injecting $(basename "$PCAP") on $MON_TX with tcpreplay"
tcpreplay -i "$MON_TX" --topspeed "$PCAP" >/dev/null 2>&1 || \
  tcpreplay -i "$MON_TX" "$PCAP" >/dev/null 2>&1
sleep 3
kill "$WPID" 2>/dev/null; WPID=""

echo "[*] observed codes:"
GOT="$(python3 -c "import sys,json
seen=set()
for l in open('$OUT'):
    try: seen.add(json.loads(l)['type'])
    except Exception: pass
print(' '.join(sorted(seen)))" 2>/dev/null || true)"
echo "    $GOT"

MISSING=""
for c in $EXPECT; do
  case " $GOT " in *" $c "*) ;; *) MISSING="$MISSING $c" ;; esac
done
if [ -n "$MISSING" ]; then
  echo "[FAIL] missing on the live path:$MISSING" >&2
  exit 1
fi
echo "[OK] all expected $MODULE codes observed on the live capture path"
