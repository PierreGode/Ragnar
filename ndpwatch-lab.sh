#!/usr/bin/env bash
# ndpwatch-lab.sh — network-namespace validation lab for ndpwatch, mirroring the
# FRR labs used for isiswatch / eigrpwatch / ospfwatch.
#
#   ndp-gw (radvd/FRR)  ndp-vic (kernel SLAAC)  ndp-atk (inject)  ndp-mon (ndpwatch)
#         gw0 ─┐            vic0 ─┐                 atk0 ─┐           mon0 ─┐
#              └────────────── bridge ndp-br0 (root ns, snooping off) ──────┘
#
# One bridge in the root ns with multicast snooping OFF, so all ND multicast
# floods to the monitor — a SPAN-like passive tap (also how you'd deploy for
# real). No uplink; nothing routes off it. NEEDS IPv6 IN THE KERNEL — run on the
# Pi or a privileged host/VM, not a CI container with IPv6 compiled out.
#
# Validates what the self-tests cannot: the FALSE-POSITIVE GATE (a real RA daemon
# + genuine kernel SLAAC/DAD must make ndpwatch emit NOTHING) and the LIVE
# CAPTURE PATH (real sniff -> parse -> icmp6 BPF -> promiscuous multicast rx).
set -u

BR=ndp-br0
REPO="$(cd "$(dirname "$0")" && pwd)"
NDPWATCH="${NDPWATCH:-$REPO/python/ndpwatch.py}"
INJECT="$REPO/python/ndp_inject.py"
GW_RA_DAEMON="${GW_RA_DAEMON:-radvd}"        # radvd | frr
NODES=(gw vic atk mon)
GW_LLA="fe80::1"; GW_MAC="02:00:00:00:00:01"; PREFIX="2001:db8:0:1::/64"
LABDIR=/run/ndpwatch-lab
CFG=/run/ndpwatch-lab/ndpwatch.json
CAP=/run/ndpwatch-lab/mon.jsonl

die()  { echo "error: $*" >&2; exit 1; }
info() { echo ">> $*"; }
need_root() { [ "$(id -u)" -eq 0 ] || die "must run as root (netns + IPv6 need CAP_NET_ADMIN)"; }
check_ipv6() { [ -e /proc/net/if_inet6 ] || die "kernel IPv6 is disabled — run on a host with IPv6"; }

do_setup() {
    need_root; check_ipv6
    ip link show "$BR" >/dev/null 2>&1 && die "lab already up? run '$0 teardown' first"
    command -v scapy >/dev/null 2>&1 || python3 -c 'import scapy' 2>/dev/null || \
        die "python3-scapy required (pip install scapy)"
    mkdir -p "$LABDIR"
    info "bridge $BR (multicast snooping off) + netns ${NODES[*]}"
    ip link add "$BR" type bridge
    echo 0 > "/sys/class/net/$BR/bridge/multicast_snooping" 2>/dev/null || true
    ip link set "$BR" up
    for node in "${NODES[@]}"; do
        ip netns add "ndp-$node"
        ip link add "${node}0" netns "ndp-$node" type veth peer name "${node}-br"
        ip link set "${node}-br" master "$BR"; ip link set "${node}-br" up
        ip -n "ndp-$node" link set lo up
        ip -n "ndp-$node" link set "${node}0" up
    done
    # Pin the gateway identity so the learned baseline + injector agree.
    ip -n ndp-gw link set gw0 addr "$GW_MAC"
    ip netns exec ndp-gw sysctl -qw "net.ipv6.conf.gw0.addr_gen_mode=1" 2>/dev/null || true
    ip -n ndp-gw addr add "$GW_LLA/64" dev gw0 nodad 2>/dev/null || ip -n ndp-gw addr add "$GW_LLA/64" dev gw0
    ip netns exec ndp-gw sysctl -qw net.ipv6.conf.gw0.forwarding=1
    # Victim does real kernel SLAAC/DAD off the RA.
    ip netns exec ndp-vic sysctl -qw net.ipv6.conf.vic0.accept_ra=2
    # Write the ndpwatch config with the pinned gateway + prefix baseline.
    cat > "$CFG" <<EOF
{ "trusted_routers": ["$GW_LLA", "$GW_MAC"], "trusted_prefixes": ["$PREFIX"],
  "flap_count": 3, "na_override_count": 8, "ra_flood_count": 10,
  "rs_flood_count": 20, "ns_sweep_count": 20, "dad_defend_count": 3 }
EOF
    info "up. now: $0 baseline   (start the RA daemon + ndpwatch)"
}

_start_radvd() {
    local conf="$LABDIR/radvd.conf"
    cat > "$conf" <<EOF
interface gw0 {
    AdvSendAdvert on;
    MinRtrAdvInterval 3; MaxRtrAdvInterval 5;
    prefix $PREFIX { AdvOnLink on; AdvAutonomous on; };
};
EOF
    command -v radvd >/dev/null 2>&1 || die "radvd not installed (apt install radvd) — or GW_RA_DAEMON=frr"
    ip netns exec ndp-gw radvd -C "$conf" -p "$LABDIR/radvd.pid" -m logfile -l "$LABDIR/radvd.log" -n &
    echo $! > "$LABDIR/radvd.wrap.pid"
}

do_baseline() {
    need_root
    ip link show "$BR" >/dev/null 2>&1 || die "run '$0 setup' first"
    info "starting RA daemon ($GW_RA_DAEMON) on gw0"
    [ "$GW_RA_DAEMON" = radvd ] && _start_radvd || die "GW_RA_DAEMON=frr not wired in this minimal lab; use radvd"
    info "starting ndpwatch on mon0 -> $CAP"
    ip netns exec ndp-mon python3 "$NDPWATCH" -i mon0 -c "$CFG" --jsonl "$CAP" &
    echo $! > "$LABDIR/mon.pid"
    sleep 2
    info "baseline running. give SLAAC/DAD ~10s, then: $0 benign"
}

do_benign() {
    need_root
    info "benign phase: real RA + kernel SLAAC/DAD for 12s — ndpwatch must stay SILENT"
    : > "$CAP" 2>/dev/null || true
    ip -n ndp-vic addr flush dev vic0 scope global 2>/dev/null || true
    ip netns exec ndp-vic sysctl -qw net.ipv6.conf.vic0.accept_ra=2 >/dev/null
    ip -n ndp-vic link set vic0 down; ip -n ndp-vic link set vic0 up   # trigger RS + SLAAC + DAD
    sleep 12
    local n; n=$(wc -l < "$CAP" 2>/dev/null || echo 0)
    if [ "$n" -eq 0 ]; then
        info "PASS: no false positives on genuine RA/SLAAC/DAD ($n alerts)"
    else
        echo "FAIL: $n alert(s) on benign traffic — false positive:" >&2
        cat "$CAP" >&2
    fi
}

do_attack() {
    need_root
    ip link show "$BR" >/dev/null 2>&1 || die "run '$0 setup && $0 baseline' first"
    : > "$CAP" 2>/dev/null || true
    info "attack phase: injecting every scenario from ndp-atk"
    for s in $(python3 "$INJECT" --list | awk '{print $1}'); do
        info "  inject $s"
        ip netns exec ndp-atk python3 "$INJECT" --iface atk0 --scenario "$s"
        sleep 0.5
    done
    sleep 1
    do_report
}

do_report() {
    [ -f "$CAP" ] || die "no capture yet (run '$0 baseline' then '$0 attack')"
    info "alerts captured on mon0:"
    python3 - "$CAP" <<'PY'
import json, sys
codes = set()
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    a = json.loads(line)
    codes.update(a.get('codes', []))
    print('  [%s] %s :: %s' % (a['severity'], ','.join(a['codes']), a['summary']))
print('distinct codes seen live: %d -> %s' % (len(codes), ' '.join(sorted(codes))))
PY
}

do_teardown() {
    need_root
    info "tearing down"
    for p in "$LABDIR"/*.pid "$LABDIR"/*.wrap.pid; do
        [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null
    done
    for node in "${NODES[@]}"; do
        ip netns pids "ndp-$node" 2>/dev/null | xargs -r kill 2>/dev/null
        ip netns del "ndp-$node" 2>/dev/null
    done
    ip link del "$BR" 2>/dev/null
    rm -rf "$LABDIR"
    info "down."
}

usage() {
    cat <<EOF
Usage: sudo $0 <command>
  setup      build the bridge + 4 namespaces (gw/vic/atk/mon), pin the gateway
  baseline   start the RA daemon (radvd) + ndpwatch on mon0
  benign     genuine RA + kernel SLAAC/DAD — ndpwatch MUST emit nothing (FP gate)
  attack     inject every ndp_inject scenario; report the codes seen live
  report     re-print the captured alerts + distinct codes
  teardown   destroy everything
  all        setup -> baseline -> benign -> attack -> report -> teardown
Env: GW_RA_DAEMON=radvd|frr   NDPWATCH=/path/to/ndpwatch.py
EOF
}

cmd=${1:-}; shift || true
case "$cmd" in
    setup)    do_setup ;;
    baseline) do_baseline ;;
    benign)   do_benign ;;
    attack)   do_attack ;;
    report)   do_report ;;
    teardown) do_teardown ;;
    all)      do_setup; do_baseline; sleep 10; do_benign; do_attack; do_teardown ;;
    ''|-h|--help|help) usage ;;
    *) usage; exit 1 ;;
esac
