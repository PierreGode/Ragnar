#!/usr/bin/env bash
# eigrp_lab.sh — self-contained EIGRP FRR lab in network namespaces, for
# validating eigrp-watch against real FRR EIGRP. The EIGRP analogue of an
# ospfwatch FRR lab.
#
#               br-eigrp (Linux bridge, no uplink)
#    ┌──────────────┼───────────────┐
#    │              │               │
#  r1-br          r2-br        (eigrp-watch sniffs br-eigrp here)
#    │              │
# [ netns r1 ]   [ netns r2 ]
#  zebra+eigrpd   zebra+eigrpd     AS 100
#  10.10.0.1/24   10.10.0.2/24
#  172.16.1.0/24  172.16.2.0/24    (advertised LANs on dummy lan0)
#
# Everything lives on an isolated bridge with no route to any real network.
# eigrp-watch stays passive/RX-only; only eigrp_inject.py transmits, onto this
# bridge only.  LAB-ONLY — never point the injector at a production segment.
set -u

BR=br-eigrp
ASN=100
LABDIR=/run/eigrp-lab
REPO="$(cd "$(dirname "$0")" && pwd)"
FRR_LIBDIR=/usr/lib/frr
ROUTERS=(r1 r2)
declare -A OCTET=( [r1]=1 [r2]=2 )

die()  { echo "error: $*" >&2; exit 1; }
info() { echo ">> $*"; }
need_root() { [ "$(id -u)" -eq 0 ] || die "must run as root (netns + FRR need CAP_NET_ADMIN)"; }

check_frr() {
    [ -x "$FRR_LIBDIR/zebra" ]  || die "FRR zebra not found at $FRR_LIBDIR/zebra — install frr (>=8.x) with eigrpd"
    [ -x "$FRR_LIBDIR/eigrpd" ] || die "FRR eigrpd not found at $FRR_LIBDIR/eigrpd — install the frr package that ships eigrpd"
    # FRR chowns its vty socket to the frrvty group; make sure it exists and
    # root is a member or the daemons abort with 'vty_serv_un: could chown socket'.
    getent group frrvty >/dev/null || groupadd -r frrvty
    id -nG root | tr ' ' '\n' | grep -qx frrvty || usermod -aG frrvty root 2>/dev/null || true
    getent group frr >/dev/null || groupadd -r frr
}

# ---- topology ------------------------------------------------------------

write_conf() {
    local r=$1 oct=${OCTET[$1]} auth=$2 d="$LABDIR/$r"
    mkdir -p "$d"
    cat > "$d/zebra.conf" <<EOF
hostname ${r}-zebra
!
EOF
    {
        echo "hostname ${r}-eigrpd"
        echo "!"
        if [ "$auth" = auth ]; then
            echo "key chain LAB"
            echo " key 1"
            echo "  key-string ragnarlab"
            echo "!"
        fi
        echo "interface ${r}-eth0"
        if [ "$auth" = auth ]; then
            echo " ip authentication mode eigrp $ASN md5"
            echo " ip authentication key-chain eigrp $ASN LAB"
        fi
        echo "!"
        echo "router eigrp $ASN"
        echo " network 10.10.0.0/24"
        echo " network 172.16.${oct}.0/24"
        echo "!"
    } > "$d/eigrpd.conf"
}

start_daemon() {
    local r=$1 daemon=$2 d="$LABDIR/$r"
    ip netns exec "$r" "$FRR_LIBDIR/$daemon" \
        -d -f "$d/$daemon.conf" \
        -i "$d/$daemon.pid" \
        -z "$d/zserv.api" \
        --vty_socket "$d" \
        > "$d/$daemon.log" 2>&1 \
        || die "$daemon failed to start in netns $r (see $d/$daemon.log)"
}

do_up() {
    need_root; check_frr
    local auth=${1:-noauth}
    [ "$auth" = auth ] || [ "$auth" = noauth ] || die "usage: up [auth]"
    ip link show "$BR" >/dev/null 2>&1 && die "lab already up? run '$0 down' first"

    info "building bridge $BR + netns ${ROUTERS[*]} (auth=$auth)"
    ip link add "$BR" type bridge
    ip link set "$BR" up

    for r in "${ROUTERS[@]}"; do
        local oct=${OCTET[$r]}
        ip netns add "$r"
        ip link add "${r}-eth0" netns "$r" type veth peer name "${r}-br"
        ip link set "${r}-br" master "$BR"
        ip link set "${r}-br" up
        # router side
        ip -n "$r" link set lo up
        ip -n "$r" link set "${r}-eth0" up
        ip -n "$r" addr add "10.10.0.${oct}/24" dev "${r}-eth0"
        # advertised LAN on a dummy iface
        ip -n "$r" link add lan0 type dummy
        ip -n "$r" link set lan0 up
        ip -n "$r" addr add "172.16.${oct}.1/24" dev lan0
        ip netns exec "$r" sysctl -qw net.ipv4.ip_forward=1

        write_conf "$r" "$auth"
        start_daemon "$r" zebra
        start_daemon "$r" eigrpd
    done
    info "up. give adjacency a few seconds, then: $0 status"
}

do_down() {
    need_root
    info "tearing down"
    for r in "${ROUTERS[@]}"; do
        [ -d "$LABDIR/$r" ] && for p in "$LABDIR/$r"/*.pid; do
            [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null
        done
        ip netns pids "$r" 2>/dev/null | xargs -r kill 2>/dev/null
        ip netns del "$r" 2>/dev/null
    done
    ip link del "$BR" 2>/dev/null
    rm -rf "$LABDIR"
    info "down."
}

# ---- observe -------------------------------------------------------------

do_status() {
    need_root
    ip link show "$BR" >/dev/null 2>&1 || die "lab is not up (run '$0 up')"
    local any=0
    for r in "${ROUTERS[@]}"; do
        echo "== netns $r : EIGRP-learned routes =="
        local out
        out=$(ip -n "$r" route show proto eigrp 2>/dev/null)
        [ -z "$out" ] && out=$(ip -n "$r" route show proto 192 2>/dev/null)
        if [ -n "$out" ]; then echo "$out"; any=1; else echo "  (none yet)"; fi
    done
    [ "$any" = 1 ] || echo "No EIGRP routes learned yet — wait a few seconds after 'up' and retry."
}

do_watch() {
    need_root
    ip link show "$BR" >/dev/null 2>&1 || die "lab is not up (run '$0 up')"
    local sec=${1:-20}
    info "eigrp-watch on $BR for ${sec}s (passive)"
    python3 "$REPO/network_diagnostics.py" eigrp-watch --iface "$BR" --seconds "$sec"
}

do_flap() {
    need_root
    local what=${1:-lan}
    case "$what" in
        lan)
            info "flapping r2 LAN (172.16.2.0/24 withdraw + re-advertise)"
            ip -n r2 link set lan0 down; sleep 2; ip -n r2 link set lan0 up ;;
        link)
            info "flapping r2 uplink (adjacency reset -> full Update)"
            ip -n r2 link set r2-eth0 down; sleep 3; ip -n r2 link set r2-eth0 up ;;
        *) die "usage: flap [lan|link]" ;;
    esac
}

do_demo() {
    need_root
    ip link show "$BR" >/dev/null 2>&1 || die "lab is not up (run '$0 up')"
    local sec=${1:-24}
    info "demo: eigrp-watch ${sec}s while flapping r2 LAN then uplink"
    python3 "$REPO/network_diagnostics.py" eigrp-watch --iface "$BR" --seconds "$sec" &
    local wpid=$!
    sleep 4;  do_flap lan
    sleep 6;  do_flap link
    wait "$wpid"
    echo; do_status
}

usage() {
    cat <<EOF
Usage: sudo $0 <command>
  up [auth]        build topology + start FRR (optionally with MD5 key-chain auth)
  status           show EIGRP routes learned in each router's kernel RIB
  watch [sec]      run eigrp-watch on $BR (default 20s)
  flap [lan|link]  churn topology to emit Update/Query TLVs (default lan)
  demo [sec]       watch (+route view) while flapping — one shot (default 24s)
  down             tear everything down
  inject ...       shortcut: python3 python/eigrp_inject.py --iface $BR ...
EOF
}

cmd=${1:-}; shift || true
case "$cmd" in
    up)     do_up "$@" ;;
    down)   do_down ;;
    status) do_status ;;
    watch)  do_watch "$@" ;;
    flap)   do_flap "$@" ;;
    demo)   do_demo "$@" ;;
    inject) need_root; python3 "$REPO/python/eigrp_inject.py" --iface "$BR" "$@" ;;
    ''|-h|--help|help) usage ;;
    *) usage; exit 1 ;;
esac
