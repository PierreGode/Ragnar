#!/usr/bin/env python3
"""make_lab_pcap.py — build radiotap pcaps of legacy-Wi-Fi / WPS test traffic
for the legacywatch / wpswatch netns labs.

Reuses the pure-Python frame builders from the modules' self-tests, so the lab
traffic is exactly what the offline tests assert on. Writes pcap FILES only —
opens no sockets, sets no radio state (same discipline as the modules).

    python3 make_lab_pcap.py legacy legacy.pcap
    python3 make_lab_pcap.py wps    wps.pcap

The resulting LINKTYPE_IEEE802_11_RADIOTAP (127) pcap can be:
  * replayed offline:  python3 ../python/legacywatch.py --replay legacy.pcap --echo
  * injected live in the hwsim lab: tcpreplay -i wlan0mon legacy.pcap
"""

import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
import legacywatch_selftest as LS
import wpswatch_selftest as WS

PCAP_MAGIC = 0xa1b2c3d4
LINKTYPE_RADIOTAP = 127


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_RADIOTAP))
        ts = 1000
        for i, fr in enumerate(frames):
            usec = (i * 1000) % 1000000
            f.write(struct.pack('<IIII', ts + i // 1000, usec, len(fr), len(fr)))
            f.write(fr)


def legacy_frames():
    AP, PLUG, PHONE = 'aa:bb:cc:00:00:0a', '20:30:40:00:00:02', '10:20:30:00:00:09'
    erp = LS.ie(42, bytes([0x03]))
    cck = LS.ie(1, bytes([0x82, 0x84, 0x8b, 0x96]))
    htcap = LS.ie(45, b'\x00' * 26)
    tkip = LS.rsn_ie(group=2, pairwise=(4, 2), akms=(2,), mfpc=False)
    frames = [LS.beacon(AP, cap=0x0021, elements=erp + cck + tkip + htcap)] * 5
    frames.append(LS.probe_req(PHONE, elements=htcap, rate=6.0))
    frames += [LS.data(PHONE, AP, 1500, mcs=7) for _ in range(200)]
    frames += [LS.data(PLUG, AP, 400, rate=1.0) for _ in range(40)]
    frames += [LS.data(PLUG, AP, 400, rate=1.0, downlink=True) for _ in range(40)]
    return frames


def wps_frames():
    AP, STA = 'aa:bb:cc:00:00:0a', '10:20:30:00:00:09'
    frames = [WS.beacon(AP, wsc=WS.wsc_ie(state=1, locked=False, cfg=0x0100))] * 3
    for _ in range(25):
        frames.append(WS.eap_wsc(STA, AP, msg_type=0x04))   # M1
        frames.append(WS.eap_wsc(STA, AP, msg_type=0x0e))   # NACK
    return frames


def main(argv):
    if len(argv) != 2 or argv[0] not in ('legacy', 'wps'):
        sys.stderr.write('usage: make_lab_pcap.py {legacy|wps} OUT.pcap\n')
        return 2
    frames = legacy_frames() if argv[0] == 'legacy' else wps_frames()
    write_pcap(argv[1], frames)
    sys.stderr.write('wrote %d frames to %s\n' % (len(frames), argv[1]))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
