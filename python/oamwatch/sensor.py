"""oamwatch sensor: receive-only capture and offline pcap replay.

The live path opens a single AF_PACKET socket in receive mode. Nothing in this
module sends. The socket is never bound for transmit, no send/sendto/sendmsg
call appears anywhere in the package, and the systemd unit additionally denies
every address family but AF_PACKET/AF_NETLINK/AF_UNIX plus all IP addressing,
so transmit is unavailable even if this code were wrong.
"""

import argparse
import json
import os
import struct
import sys
import time

from . import registry as reg
from .config import Config, ConfigError
from .engine import Engine
from .parser import is_oam_frame, parse_frame

ETH_P_ALL = 0x0003
DLT_EN10MB = 1
PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D


# --------------------------------------------------------------------------
# offline pcap reader (no scapy, no libpcap)
# --------------------------------------------------------------------------
def read_pcap(path):
    """Yield (timestamp, frame_bytes) from a classic pcap file."""
    with open(path, "rb") as fh:
        hdr = fh.read(24)
        if len(hdr) < 24:
            raise ValueError("%s: truncated pcap header" % path)
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic == PCAP_MAGIC_US:
            endian, nano = "<", False
        elif magic == PCAP_MAGIC_NS:
            endian, nano = "<", True
        elif struct.unpack(">I", hdr[:4])[0] == PCAP_MAGIC_US:
            endian, nano = ">", False
        elif struct.unpack(">I", hdr[:4])[0] == PCAP_MAGIC_NS:
            endian, nano = ">", True
        else:
            raise ValueError("%s: not a classic pcap file" % path)
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        if linktype != DLT_EN10MB:
            raise ValueError("%s: linktype %d, expected Ethernet (%d)"
                             % (path, linktype, DLT_EN10MB))
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                return
            tsec, tfrac, caplen, _origlen = struct.unpack(endian + "IIII", rh)
            data = fh.read(caplen)
            if len(data) < caplen:
                return
            ts = tsec + (tfrac / 1e9 if nano else tfrac / 1e6)
            yield ts, data


def write_pcap(path, frames, base_ts=1000000.0, interval=0.001):
    """Write frames to a classic pcap.

    Timestamps advance by `interval` per frame from `base_ts`. The frame index
    is NEVER stamped into the seconds field: doing that makes tcpreplay replay
    at the recorded rate, one frame per second, which silently disarms every
    rate-based finding. That bug cost cdpwatch its flood code once.
    """
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0,
                             65535, DLT_EN10MB))
        for i, data in enumerate(frames):
            t = base_ts + i * interval
            sec = int(t)
            usec = int(round((t - sec) * 1e6))
            if usec >= 1000000:          # carry, do not emit an illegal usec
                sec += 1
                usec -= 1000000
            fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            fh.write(data)


# --------------------------------------------------------------------------
# runners
# --------------------------------------------------------------------------
def run_offline(paths, cfg, emit):
    engine = Engine(cfg)
    for path in paths:
        for ts, raw in read_pcap(path):
            if not is_oam_frame(raw):
                continue
            pdu = parse_frame(raw, strict_tail=cfg.strict_tail, ts=ts)
            if pdu is None:
                continue
            for f in engine.observe(pdu):
                emit(f)
    return engine


def run_live(iface, cfg, emit, duration=None):
    """Receive-only AF_PACKET capture. Imported lazily so the offline path and
    the conformance harness never touch the socket module."""
    import socket

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(ETH_P_ALL))
    try:
        sock.bind((iface, 0))
        sock.settimeout(1.0)
        engine = Engine(cfg)
        deadline = None if duration is None else time.time() + duration
        while deadline is None or time.time() < deadline:
            try:
                raw = sock.recv(65535)
            except socket.timeout:
                continue
            if not is_oam_frame(raw):
                continue
            pdu = parse_frame(raw, strict_tail=cfg.strict_tail, ts=time.time())
            if pdu is None:
                continue
            for f in engine.observe(pdu):
                emit(f)
        return engine
    finally:
        sock.close()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _emitter(fmt, stream):
    if fmt == "json":
        def emit(f):
            stream.write(json.dumps(f.as_dict(), sort_keys=True) + "\n")
            stream.flush()
    else:
        def emit(f):
            stream.write("%-9s %-8s %-18s %s  %s\n"
                         % (f.code, f.severity, f.name, f.src, f.detail))
            stream.flush()
    return emit


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="oamwatch",
        description="Passive IEEE 802.3ah Link OAM abuse detector. "
                    "Receive-only; never transmits.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-i", "--interface", help="interface to capture on")
    src.add_argument("-r", "--read", nargs="+", metavar="PCAP",
                     help="read frames from pcap file(s) instead")
    src.add_argument("--list-codes", action="store_true",
                     help="print the finding registry and exit")
    ap.add_argument("-c", "--config", help="JSON configuration file")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    ap.add_argument("--duration", type=float,
                    help="stop live capture after N seconds")
    ap.add_argument("--strict-tail", action="store_true",
                    help="report every non-zero trailing octet as smuggled "
                         "data, disabling the probable-FCS allowance")
    ap.add_argument("--no-posture", action="store_true",
                    help="suppress the OAM-02x posture class")
    args = ap.parse_args(argv)

    if args.list_codes:
        try:
            for code in reg.CODES:
                name, klass, sev, summary = reg.REGISTRY[code]
                print("%-9s %-10s %-8s %-32s %s"
                      % (code, klass, sev, name, summary))
            sys.stdout.flush()
        except BrokenPipeError:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0

    try:
        cfg = Config.load(args.config) if args.config else Config()
    except (ConfigError, OSError, ValueError) as exc:
        print("oamwatch: configuration error: %s" % exc, file=sys.stderr)
        return 2
    if args.strict_tail:
        cfg.strict_tail = True
    if args.no_posture:
        cfg.posture_enabled = False

    emit = _emitter(args.format, sys.stdout)
    try:
        if args.read:
            engine = run_offline(args.read, cfg, emit)
        else:
            engine = run_live(args.interface, cfg, emit, args.duration)
    except PermissionError:
        print("oamwatch: need CAP_NET_RAW to open an AF_PACKET socket",
              file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError) as exc:
        print("oamwatch: %s" % exc, file=sys.stderr)
        return 2

    print("# %d OAM frames, %d finding(s), %d peer(s)"
          % (engine.frames_seen, len(engine.findings), len(engine.peers)),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
