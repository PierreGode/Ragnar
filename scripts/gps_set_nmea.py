#!/usr/bin/env python3
"""Switch a u-blox receiver from UBX binary output to NMEA.

Why this exists: u-blox receivers (u-blox 7 pucks especially) can come up
emitting only UBX *binary* frames — every message starts with the sync bytes
b5 62. Ragnar's GPS layer parses NMEA sentences, so in that state it reads a
perfectly healthy receiver and sees nothing it understands: no position, no
satellites, "Searching..." forever, and no error anywhere. gps_diag.sh reports
this as "DATA IS ARRIVING ... BUT NO NMEA".

This sends three things over the serial port:
  1. CFG-PRT  — enable NMEA in the port's output protocol mask (keeping UBX,
                so anything already speaking UBX, e.g. gpsd, still works).
  2. CFG-MSG  — explicitly enable the sentences Ragnar needs (GGA, RMC) plus
                GSA/GSV for satellite info, in case they were switched off.
  3. CFG-CFG  — persist to battery-backed RAM/flash so it survives a replug.

Usage:
    sudo python3 scripts/gps_set_nmea.py [/dev/ttyACM0] [--no-save] [--verify]

Notes:
  * Stop anything holding the port first (ragnar, gpsd) or the write will fail.
  * --verify re-reads the port afterwards and reports whether NMEA now appears.
  * gpsd can also decode UBX natively; switching to NMEA is the more portable
    fix because it makes the direct-serial path work too.
"""

import argparse
import os
import struct
import sys
import termios
import time
import tty

SYNC = b'\xb5\x62'


def ubx_checksum(payload: bytes) -> bytes:
    """8-bit Fletcher over class+id+length+payload, per the u-blox protocol."""
    ck_a = ck_b = 0
    for byte in payload:
        ck_a = (ck_a + byte) & 0xFF
        ck_b = (ck_b + ck_a) & 0xFF
    return bytes((ck_a, ck_b))


def ubx(msg_class: int, msg_id: int, payload: bytes = b'') -> bytes:
    """Build a complete UBX frame."""
    body = bytes((msg_class, msg_id)) + struct.pack('<H', len(payload)) + payload
    return SYNC + body + ubx_checksum(body)


def cfg_prt_usb() -> bytes:
    """CFG-PRT for the USB port: output both UBX and NMEA.

    portID 3 = USB. mode/baudRate are ignored for USB but must be present.
    outProtoMask bit0=UBX, bit1=NMEA -> 0x0003 keeps UBX and adds NMEA.
    """
    payload = struct.pack(
        '<BBHIIHHHH',
        3,        # portID: USB
        0,        # reserved
        0,        # txReady
        0,        # mode (unused on USB)
        0,        # baudRate (unused on USB)
        0x0007,   # inProtoMask: UBX + NMEA + RTCM (stay permissive)
        0x0003,   # outProtoMask: UBX + NMEA  <-- the actual fix
        0,        # flags
        0,        # reserved
    )
    return ubx(0x06, 0x00, payload)


def cfg_msg(msg_class: int, msg_id: int, rate: int = 1) -> bytes:
    """CFG-MSG short form: set output rate on the port this arrives on."""
    return ubx(0x06, 0x01, bytes((msg_class, msg_id, rate)))


def cfg_save() -> bytes:
    """CFG-CFG: persist current config to BBR + flash so a replug keeps it."""
    payload = struct.pack(
        '<IIIB',
        0x00000000,   # clearMask
        0x0000FFFF,   # saveMask: everything
        0x00000000,   # loadMask
        0x17,         # deviceMask: BBR | flash | EEPROM
    )
    return ubx(0x06, 0x09, payload)


# NMEA sentences Ragnar's parser consumes (class 0xF0 = standard NMEA).
NMEA_MESSAGES = [
    ('GGA', 0x00),   # position + fix quality  -> drives fix_quality
    ('GLL', 0x01),
    ('GSA', 0x02),
    ('GSV', 0x03),   # satellites in view      -> drives the "searching" display
    ('RMC', 0x04),   # position + status A/V   -> drives has_fix
    ('VTG', 0x05),
]


def open_port(path):
    """Open the tty raw at 9600 8N1. USB CDC ignores baud, but setting it keeps
    the call valid for ttyUSB bridges too."""
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        tty.setraw(fd)
        attrs = termios.tcgetattr(fd)
        attrs[4] = attrs[5] = termios.B9600     # ispeed / ospeed
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
    except termios.error:
        pass    # CDC-ACM devices may reject termios tweaks; harmless
    return fd


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('device', nargs='?', default='/dev/ttyACM0')
    ap.add_argument('--no-save', action='store_true',
                    help='do not persist (config reverts on power cycle)')
    ap.add_argument('--verify', action='store_true',
                    help='re-read the port afterwards and report NMEA/UBX')
    args = ap.parse_args()

    if not os.path.exists(args.device):
        sys.exit(f"No such device: {args.device}")

    try:
        fd = open_port(args.device)
    except PermissionError:
        sys.exit(f"Permission denied on {args.device} — run with sudo.")
    except OSError as exc:
        sys.exit(f"Could not open {args.device}: {exc}\n"
                 f"Stop whatever holds it first:  sudo systemctl stop ragnar gpsd.socket gpsd")

    try:
        print(f"Configuring {args.device} for NMEA output...")
        os.write(fd, cfg_prt_usb())
        time.sleep(0.3)
        for name, msg_id in NMEA_MESSAGES:
            os.write(fd, cfg_msg(0xF0, msg_id, 1))
            time.sleep(0.05)
        print(f"  enabled: {', '.join(n for n, _ in NMEA_MESSAGES)}")

        if not args.no_save:
            os.write(fd, cfg_save())
            time.sleep(0.3)
            print("  saved to non-volatile storage (survives replug)")

        if args.verify:
            time.sleep(1.0)
            deadline = time.time() + 5
            buf = b''
            while time.time() < deadline:
                try:
                    chunk = os.read(fd, 4096)
                    if chunk:
                        buf += chunk
                except BlockingIOError:
                    pass
                time.sleep(0.1)
            nmea = sum(1 for line in buf.split(b'\n') if line.startswith(b'$G'))
            ubx_frames = buf.count(SYNC)
            print(f"\nVerify: {len(buf)} bytes — {nmea} NMEA sentences, "
                  f"{ubx_frames} UBX frames")
            if nmea:
                print("  SUCCESS: the receiver is emitting NMEA. Restart Ragnar.")
                for line in buf.split(b'\n'):
                    if line.startswith(b'$G'):
                        print("   ", line.decode('ascii', 'replace').strip())
                        break
            else:
                print("  Still no NMEA. The receiver may need a power cycle "
                      "(unplug/replug), or try: sudo gpsctl -f -n " + args.device)
    finally:
        os.close(fd)

    print("\nNext: sudo systemctl restart ragnar")


# --- self-test: verify frame construction against known-good UBX bytes -------
def _selftest():
    # The canonical CFG-PRT poll is B5 62 06 00 00 00 06 18.
    assert ubx(0x06, 0x00) == bytes.fromhex('b5620600000006 18'.replace(' ', '')), \
        ubx(0x06, 0x00).hex()
    # CFG-MSG enabling GGA: B5 62 06 01 03 00 F0 00 01 FB 10
    assert cfg_msg(0xF0, 0x00, 1) == bytes.fromhex('b5620601030 0f00001fb10'.replace(' ', '')), \
        cfg_msg(0xF0, 0x00, 1).hex()
    prt = cfg_prt_usb()
    assert prt[:6] == bytes.fromhex('b562060014 00'.replace(' ', '')), prt[:6].hex()
    assert len(prt) == 28, len(prt)          # 6 header + 20 payload + 2 checksum
    assert ubx_checksum(prt[2:-2]) == prt[-2:]
    print("selftest OK")


if __name__ == '__main__':
    if '--selftest' in sys.argv:
        _selftest()
    else:
        main()
