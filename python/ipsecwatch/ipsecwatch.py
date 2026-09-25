"""
ipsecwatch.py — Ragnar module entry point.

Passive IKE security-posture detector. Dual-stack by construction:
the same detector path runs whether the IKE rode in on IPv4 or IPv6 UDP —
address family is a report label, never a branch in detection.

Modes:
  --iface eth0            live capture (needs libpcap / root)
  --pcap file.pcap        offline replay
  --self-test             run the built-in Tier-1 suite

Dual-stack BPF (single filter, both families):
  (udp port 500 or udp port 4500) and (ip or ip6)

The IPv4/IPv6 + UDP decode here is deliberately hand-rolled and minimal so the
module has no hard scapy dependency for live use; if scapy is present it's used
for pcap parsing convenience, else a raw-socket path is available.
"""

import argparse
import json
import socket
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ike_parser import parse_ike
from ike_detectors import IPSecWatch
from ike_constants import IKE_PORT, IKE_NATT_PORT

DUAL_STACK_BPF = "(udp port 500 or udp port 4500) and (ip or ip6)"

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD


# ─────────────────────────────────────────────────────────────────────────────
# Minimal L2/L3/L4 decode to reach the UDP payload, both families
# ─────────────────────────────────────────────────────────────────────────────
def _decode_ipv4(data):
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    proto = data[9]
    if proto != 17:  # UDP
        return None
    src = socket.inet_ntop(socket.AF_INET, data[12:16])
    dst = socket.inet_ntop(socket.AF_INET, data[16:20])
    return _decode_udp(data[ihl:], src, dst, "IPv4")


def _decode_ipv6(data):
    if len(data) < 40:
        return None
    next_hdr = data[6]
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    offset = 40
    # Walk extension headers to reach UDP (this is the exact blind spot that bit
    # juniperwatch/tlswatch: a naive parser assumes next_hdr==17 right after the
    # base header and misses IKE behind a Hop-by-Hop/Routing/Dest-Options EH).
    EXT_HDRS = {0, 43, 44, 60}  # HBH, Routing, Fragment, Dest-Opts
    guard = 0
    while next_hdr in EXT_HDRS and offset + 2 <= len(data):
        guard += 1
        if guard > 8:
            return None
        if next_hdr == 44:  # Fragment header is fixed 8 bytes
            ext_len = 8
        else:
            ext_len = (data[offset + 1] + 1) * 8
        next_hdr = data[offset]
        offset += ext_len
    if next_hdr != 17:
        return None
    return _decode_udp(data[offset:], src, dst, "IPv6")


def _decode_udp(data, src, dst, family):
    if len(data) < 8:
        return None
    sport, dport, ulen, _ = struct.unpack("!HHHH", data[:8])
    if sport not in (IKE_PORT, IKE_NATT_PORT) and dport not in (IKE_PORT, IKE_NATT_PORT):
        return None
    payload = data[8:]
    return (payload, src, dst, sport, dport, family)


def decode_ethernet(frame):
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    body = frame[14:]
    if ethertype == ETH_P_IP:
        return _decode_ipv4(body)
    elif ethertype == ETH_P_IPV6:
        return _decode_ipv6(body)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────
class IPSecWatchRunner:
    def __init__(self, watch: IPSecWatch, emit=print):
        self.watch = watch
        self.emit = emit
        self.stats = {"packets": 0, "ike_msgs": 0, "findings": 0}

    def feed_udp_payload(self, payload, src, dst, sport, dport, family):
        self.stats["packets"] += 1
        msg = parse_ike(payload, src=src, dst=dst, sport=sport, dport=dport, family=family)
        if msg is None:
            return
        self.stats["ike_msgs"] += 1
        for f in self.watch.analyze(msg):
            self.stats["findings"] += 1
            self.emit(f.to_json())

    def feed_frame(self, frame):
        decoded = decode_ethernet(frame)
        if decoded:
            self.feed_udp_payload(*decoded)


def run_pcap(path, watch):
    runner = IPSecWatchRunner(watch)
    try:
        from scapy.all import PcapReader, Ether  # noqa
        with PcapReader(path) as pr:
            for pkt in pr:
                runner.feed_frame(bytes(pkt))
    except ImportError:
        # Fallback: minimal pcap file reader (classic little/big-endian global hdr)
        _read_pcap_raw(path, runner)
    return runner.stats


def _read_pcap_raw(path, runner):
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        else:
            endian = ">"
        while True:
            ph = fh.read(16)
            if len(ph) < 16:
                break
            _, _, incl, _ = struct.unpack(endian + "IIII", ph)
            data = fh.read(incl)
            if len(data) < incl:
                break
            runner.feed_frame(data)


def run_live(iface, watch):
    runner = IPSecWatchRunner(watch)
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((iface, 0))
    except PermissionError:
        print("ipsecwatch: need root/CAP_NET_RAW for live capture", file=sys.stderr)
        return runner.stats
    except AttributeError:
        print("ipsecwatch: AF_PACKET unavailable on this platform", file=sys.stderr)
        return runner.stats
    print(f"ipsecwatch: capturing on {iface} (BPF equivalent: {DUAL_STACK_BPF})",
          file=sys.stderr)
    try:
        while True:
            frame = s.recv(65535)
            runner.feed_frame(frame)
    except KeyboardInterrupt:
        print(json.dumps(runner.stats), file=sys.stderr)
    return runner.stats


def build_watch(args):
    return IPSecWatch(
        enable_dheater_correlation=not args.no_dheater_correlation,
        enable_aggressive_hash_extraction=not args.no_aggressive_extraction,
        enable_ml_kem_detection=args.enable_ml_kem,
        ml_kem_downgrade_prevention_notify=args.ml_kem_dp_notify_code,
    )


def main(argv=None):
    p = argparse.ArgumentParser(description="ipsecwatch — passive IKE security-posture detector")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="live capture interface")
    src.add_argument("--pcap", help="offline pcap to replay")
    src.add_argument("--self-test", action="store_true", help="run built-in Tier-1 suite")
    p.add_argument("--no-dheater-correlation", action="store_true",
                   help="disable E1 stateful downgrade correlation")
    p.add_argument("--no-aggressive-extraction", action="store_true",
                   help="disable E2 aggressive-mode PSK hash extraction")
    p.add_argument("--enable-ml-kem", action="store_true",
                   help="request E3 ML-KEM downgrade detection. Inert until BOTH "
                        "IANA registrations are confirmed: ML-KEM KE transform IDs "
                        "(set ML_KEM_KE_IDS_CONFIRMED + real ids in ike_constants) "
                        "AND --ml-kem-dp-notify-code below.")
    p.add_argument("--ml-kem-dp-notify-code", type=int, default=None,
                   help="IKEv2 downgrade-prevention Notify status-type code point "
                        "(registry B: draft-ietf-ipsecme-ikev2-downgrade-prevention). "
                        "Its presence in an SA_INIT marks a PQ offer as protected.")
    args = p.parse_args(argv)

    if args.self_test:
        import unittest
        loader = unittest.TestLoader()
        suite = loader.discover(os.path.join(os.path.dirname(__file__), "..", "tests"))
        unittest.TextTestRunner(verbosity=2).run(suite)
        return

    watch = build_watch(args)
    # Surface the E3 gate decision so a requested-but-gated run isn't silent.
    if args.enable_ml_kem:
        print(f"ipsecwatch: {watch.e3_status()}", file=sys.stderr)
    if args.pcap:
        stats = run_pcap(args.pcap, watch)
    else:
        stats = run_live(args.iface, watch)
    print(json.dumps({"stats": stats}), file=sys.stderr)


if __name__ == "__main__":
    main()
