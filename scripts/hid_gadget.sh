#!/bin/bash
# On-demand control of the Rubber Ducky USB HID keyboard gadget.
#
#   hid_gadget.sh status   # report gadget/UDC/hidg0 state as JSON
#   hid_gadget.sh up        # add the HID keyboard function and bind -> /dev/hidg0
#   hid_gadget.sh down      # remove the HID function (keep ECM networking)
#
# Operates on the composite gadget `g1` created by usb-gadget.sh. Runtime only:
# it does NOT edit boot config. The dwc2 peripheral controller (the UDC) must
# already exist — that part is enabled by the installer/updater HID option and
# a reboot. Must run as root (configfs writes). Emits one line of JSON.
set -uo pipefail

GDIR=/sys/kernel/config/usb_gadget/g1
CFG="$GDIR/configs/c.1"
HIDF="$GDIR/functions/hid.usb0"
# Standard US boot-keyboard HID report descriptor (63 bytes).
HID_DESC='\x05\x01\x09\x06\xa1\x01\x05\x07\x19\xe0\x29\xe7\x15\x00\x25\x01\x75\x01\x95\x08\x81\x02\x95\x01\x75\x08\x81\x03\x95\x05\x75\x01\x05\x08\x19\x01\x29\x05\x91\x02\x95\x01\x75\x03\x91\x03\x95\x06\x75\x08\x15\x00\x25\x65\x05\x07\x19\x00\x29\x65\x81\x00\xc0'

udc_name() { ls /sys/class/udc 2>/dev/null | head -1; }

emit_status() {
    local udc bound hid node state
    [ -n "$(udc_name)" ] && udc=true || udc=false
    { [ -d "$GDIR" ] && [ -n "$(cat "$GDIR/UDC" 2>/dev/null)" ]; } && bound=true || bound=false
    [ -L "$CFG/hid.usb0" ] && hid=true || hid=false
    [ -e /dev/hidg0 ] && node=true || node=false
    state=$(cat /sys/class/udc/*/state 2>/dev/null | head -1)
    printf '{"ok":true,"udc":%s,"bound":%s,"hid_linked":%s,"hidg0":%s,"state":"%s"}\n' \
        "$udc" "$bound" "$hid" "$node" "${state:-unknown}"
}

fail() { printf '{"ok":false,"error":"%s"}\n' "$1"; exit 1; }

unbind() { echo "" > "$GDIR/UDC" 2>/dev/null || true; }
rebind() { local u; u=$(udc_name); [ -n "$u" ] || return 1; echo "$u" > "$GDIR/UDC" 2>/dev/null; }

ensure_hid_function() {
    [ -d "$HIDF" ] && return 0
    mkdir -p "$HIDF" || return 1
    echo 1 > "$HIDF/protocol"
    echo 1 > "$HIDF/subclass"
    echo 8 > "$HIDF/report_length"
    printf "$HID_DESC" > "$HIDF/report_desc"
}

case "${1:-status}" in
    status)
        emit_status
        ;;
    up)
        [ "$(id -u)" = "0" ] || fail "must run as root"
        [ -d "$GDIR" ] || fail "gadget g1 not present (run the installer)"
        [ -n "$(udc_name)" ] || fail "no USB device controller; enable the HID gadget option in the installer/updater and reboot"
        # Legacy g_ether holds the UDC on some boxes; free it.
        modprobe -r g_ether 2>/dev/null || true
        unbind
        ensure_hid_function || fail "could not create HID function"
        [ -L "$CFG/hid.usb0" ] || ln -s "$HIDF" "$CFG/" || fail "could not link HID function"
        rebind || fail "bind failed (UDC busy?)"
        emit_status
        ;;
    down)
        [ "$(id -u)" = "0" ] || fail "must run as root"
        [ -d "$GDIR" ] || { emit_status; exit 0; }
        unbind
        [ -L "$CFG/hid.usb0" ] && rm "$CFG/hid.usb0"
        # Rebind so ECM (usb0) networking returns if it is still configured.
        if [ -L "$CFG/ecm.usb0" ] && [ -n "$(udc_name)" ]; then rebind || true; fi
        emit_status
        ;;
    *)
        fail "unknown command: ${1:-}"
        ;;
esac
