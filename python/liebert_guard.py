#!/usr/bin/env python3
"""liebert_guard - passive Liebert/RomPager detector: Misfortune Cookie (CVE-2014-9222) and the
Liebert RDU101 / IS-UNITY stack overflow (CVE-2025-41426).

Receive-only. Reads HTTP traffic on one TCP port (80 by default) from a live tap/SPAN interface or a pcap.

Responses from the port (the Server: banner):
  LG-001  RomPager < 4.34   critical  banner indicates CVE-2014-9222 exposure
  LG-002  RomPager, version not parseable   low
  LG-003  RomPager >= 4.34  info      asset seen, banner not in the vulnerable range
Requests to the port (the request line):
  LG-101  method token longer than 64 bytes   high   CVE-2025-41426 trigger shape (an attempt, not exposure)

Dual-stack: IPv4 and IPv6 (extension headers walked in-process, no BPF dependence).
"""
import argparse
import json
import re
import socket
import struct
import sys
import time
from collections import OrderedDict

__version__ = "0.2.0-dev"
CVE = "CVE-2014-9222"
CVES = {"LG-001": CVE, "LG-101": "CVE-2025-41426"}
FIXED = (4, 34)

_SERVER = re.compile(rb"^server:[ \t]*([^\r\n]*)", re.I | re.M)
_ROMPAGER = re.compile(rb"(?<![A-Za-z0-9_])rompager", re.I)
_VERSION = re.compile(rb"(?<![A-Za-z0-9_])rompager/(\d+)\.(\d+)", re.I)
_HEAD_END = re.compile(rb"\r?\n\r?\n")   # a passive observer reads what is on the wire: bare LF too
_HTTP = b"HTTP/1."
_REQLINE = re.compile(rb"^([!#$%&'*+\-.^_`|~0-9A-Za-z]+) ([^\x00-\x20\x7f]+) HTTP/1\.[01]$")
SUPPORTED_LINKTYPES = {1: "ethernet", 12: "raw-ip", 14: "raw-ip", 101: "raw-ip", 113: "linux-sll",
                       228: "ipv4", 229: "ipv6", 276: "linux-sll2"}

NOTES = {
    "LG-001": ("RomPager banner is in the CVE-2014-9222 range (<4.34). Exploitable only if the "
               "cookie feature is enabled, and a vendor may have patched without changing the "
               "banner (Emerson fixed RPC-1000 in firmware 4.D40.1). Confirm card firmware."),
    "LG-002": "RomPager present but the version could not be parsed from the banner.",
    "LG-003": "RomPager >= 4.34: not in the vulnerable banner range. Asset presence logged.",
    "LG-101": ("HTTP request line with a method token over 64 bytes: the request shape that triggers the "
               "CVE-2025-41426 stack overflow in Liebert RDU101 (<=1.9.0.0, fixed 1.9.1.2) and IS-UNITY "
               "(<=8.4.1.0, fixed 8.4.3.1). An attempt detector: it does not show the target is a Liebert "
               "card or that it is unpatched."),
}
SEVERITY = {"LG-001": "critical", "LG-002": "low", "LG-003": "info", "LG-101": "high"}


def classify(server):
    """Server header value (bytes/str) -> (code, version tuple|None) or None."""
    if isinstance(server, str):
        server = server.encode("latin-1", "replace")
    if not _ROMPAGER.search(server):
        return None
    m = _VERSION.search(server)
    if not m:
        return "LG-002", None
    ver = (int(m.group(1)), int(m.group(2)))
    return ("LG-001" if ver < FIXED else "LG-003"), ver


def _version_text(banner):
    """Version exactly as the device wrote it ("4.07", not "4.7")."""
    m = _VERSION.search(banner)
    return "%s.%s" % (m.group(1).decode(), m.group(2).decode()) if m else None


def parse_frame(buf, linktype=1):
    """Frame -> (family, src, dst, sport, dport, seq, payload) or None. Never raises on junk."""
    try:
        return _parse(buf, linktype)
    except (struct.error, IndexError, ValueError):
        return None


def _parse(buf, linktype):
    off = 0
    if linktype == 1:
        if len(buf) < 14:
            return None
        et = struct.unpack_from("!H", buf, 12)[0]
        off = 14
        while et in (0x8100, 0x88A8, 0x9100):
            et = struct.unpack_from("!H", buf, off + 2)[0]
            off += 4
    elif linktype in (12, 14, 101):
        et = {4: 0x0800, 6: 0x86DD}.get(buf[0] >> 4, 0)
    elif linktype in (228, 229):     # LINKTYPE_IPV4 / LINKTYPE_IPV6
        et = 0x0800 if linktype == 228 else 0x86DD
    elif linktype == 113:            # Linux cooked v1 (tcpdump -i any)
        et = struct.unpack_from("!H", buf, 14)[0]
        off = 16
    elif linktype == 276:            # Linux cooked v2
        et = struct.unpack_from("!H", buf, 0)[0]
        off = 20
    else:
        return None

    if et == 0x0800:
        ihl = (buf[off] & 15) * 4
        if ihl < 20 or buf[off + 9] != 6:
            return None
        if struct.unpack_from("!H", buf, off + 6)[0] & 0x1FFF:
            return None  # non-first fragment
        tot = struct.unpack_from("!H", buf, off + 2)[0]
        end = off + tot if ihl <= tot and off + tot <= len(buf) else len(buf)
        src = socket.inet_ntop(socket.AF_INET, bytes(buf[off + 12:off + 16]))
        dst = socket.inet_ntop(socket.AF_INET, bytes(buf[off + 16:off + 20]))
        p, fam = off + ihl, "ipv4"
    elif et == 0x86DD:
        plen = struct.unpack_from("!H", buf, off + 4)[0]
        nh = buf[off + 6]
        src = socket.inet_ntop(socket.AF_INET6, bytes(buf[off + 8:off + 24]))
        dst = socket.inet_ntop(socket.AF_INET6, bytes(buf[off + 24:off + 40]))
        p, fam = off + 40, "ipv6"
        end = min(len(buf), p + plen) if plen else len(buf)
        for _ in range(8):
            if nh in (0, 43, 60):           # hop-by-hop, routing, destination options
                nxt = buf[p]
                p += (buf[p + 1] + 1) * 8
                nh = nxt
            elif nh == 44:                  # fragment: first fragment only
                if struct.unpack_from("!H", buf, p + 2)[0] & 0xFFF8:
                    return None
                nh = buf[p]
                p += 8
            elif nh == 51:                  # AH
                nxt = buf[p]
                p += (buf[p + 1] + 2) * 4
                nh = nxt
            else:
                break
        if nh != 6:
            return None
    else:
        return None

    if p + 20 > len(buf):
        return None
    sport, dport, seq = struct.unpack_from("!HHI", buf, p)
    doff = (buf[p + 12] >> 4) * 4
    if doff < 20:
        return None
    payload = bytes(buf[p + doff:end]) if end > p + doff else b""
    return fam, src, dst, sport, dport, seq, payload


class Detector:
    """Feed frames in; findings come out via emit(dict). Holds no sockets and sends nothing."""

    MAX_FLOW_BYTES = 16384
    MAX_HEAD = 8192
    MAX_SEEN = 65536
    MAX_METHOD = 64
    MAX_REQ = 8192

    def __init__(self, port=80, cooldown=3600, emit=None, max_flows=4096):
        self.port, self.cooldown, self.max_flows = port, cooldown, max_flows
        self.emit = emit or (lambda f: print(json.dumps(f), flush=True))
        self.flows = OrderedDict()
        self.reqs = OrderedDict()
        self.seen = OrderedDict()

    def feed(self, ts, frame, linktype=1):
        pkt = parse_frame(frame, linktype)
        if not pkt:
            return
        fam, src, dst, sport, dport, seq, payload = pkt
        if not payload:
            return
        if dport == self.port:
            self._request(ts, fam, src, dst, sport, dport, seq, payload)
        if sport != self.port:
            return
        key = (src, sport, dst, dport)
        fl = self.flows.get(key)
        if fl is None:
            fl = self.flows[key] = {"segs": {}, "size": 0, "fam": fam}
            if len(self.flows) > self.max_flows:
                self.flows.popitem(last=False)
        else:
            self.flows.move_to_end(key)
        old = fl["segs"].get(seq)
        if old is None or len(payload) > len(old):   # a longer retransmit of the same range wins
            fl["size"] += len(payload) - (len(old) if old else 0)
            fl["segs"][seq] = payload
        head = self._head(fl)
        if head is not None:
            del self.flows[key]
            self._inspect(ts, fam, src, dst, head)
        elif fl["size"] > self.MAX_FLOW_BYTES:
            del self.flows[key]

    def _request(self, ts, fam, src, dst, sport, dport, seq, payload):
        """Client -> server: judge the request line of the flow. The flow is anchored at the lowest sequence
        number seen (signed, wraparound-safe) and re-judged whenever a segment arrives, so a method token split
        across segments or arriving out of order is still measured whole."""
        key = (src, sport, dst, dport)
        fl = self.reqs.get(key)
        if fl is None:
            fl = self.reqs[key] = {"segs": {}, "size": 0, "first": seq}
            if len(self.reqs) > self.max_flows:
                self.reqs.popitem(last=False)
        else:
            self.reqs.move_to_end(key)
        payload = payload[:self.MAX_REQ]
        old = fl["segs"].get(seq)
        if old is None or len(payload) > len(old):
            fl["size"] += len(payload) - (len(old) if old else 0)
            fl["segs"][seq] = payload
        method = self._method(fl)
        if method is not None and len(method) > self.MAX_METHOD:
            del self.reqs[key]
            self._emit(ts, "LG-101", fam, dst, src, dport, None, None,
                       "method_len=%d sample=%s" % (len(method), method[:24].decode("ascii")))
        elif fl["size"] >= self.MAX_REQ:
            del self.reqs[key]

    def _method(self, fl):
        """Method token of the request line at the start of the flow, or None if there is no complete,
        well-formed request line (token SP target SP HTTP/1.x) yet."""
        first, segs = fl["first"], fl["segs"]
        start = min(segs, key=lambda s: ((s - first + 0x80000000) & 0xFFFFFFFF) - 0x80000000)
        buf, cur = b"", start
        while cur in segs and len(buf) < self.MAX_REQ:
            buf += segs[cur]
            cur = (cur + len(segs[cur])) & 0xFFFFFFFF
        buf = buf.lstrip(b"\r\n")                      # servers skip empty lines before the request line
        nl = buf.find(b"\n")
        if nl < 0:
            return None
        line = buf[:nl]
        m = _REQLINE.match(line[:-1] if line.endswith(b"\r") else line)
        return m.group(1) if m else None

    def _head(self, fl):
        """Reassemble from any segment that could begin an HTTP response; return head bytes or None.
        The anchor is prefix-tolerant: a first segment of 1-6 bytes ("H", "HTT") still anchors."""
        segs = fl["segs"]
        for start, data in segs.items():
            if not (data.startswith(_HTTP) or (len(data) < len(_HTTP) and _HTTP.startswith(data))):
                continue
            buf, cur = b"", start
            while cur in segs and len(buf) <= self.MAX_HEAD:
                buf += segs[cur]
                cur = (cur + len(segs[cur])) & 0xFFFFFFFF
                if len(buf) >= len(_HTTP) and not buf.startswith(_HTTP):
                    break
                m = _HEAD_END.search(buf)
                if m and buf.startswith(_HTTP):
                    return buf[:m.start()]
            if len(buf) > self.MAX_HEAD and buf.startswith(_HTTP):
                return buf
        return None

    def _inspect(self, ts, fam, src, dst, head):
        m = _SERVER.search(head)
        if not m:
            return
        banner = m.group(1).strip()
        res = classify(banner)
        if not res:
            return
        code, ver = res
        self._emit(ts, code, fam, src, dst, self.port, banner.decode("latin-1", "replace"),
                   _version_text(banner) if ver else None, None, key=(src, code, banner))

    def _emit(self, ts, code, fam, server, client, port, banner, version, detail, key=None):
        k = key or (server, client, code)
        if ts - self.seen.get(k, -1e18) < self.cooldown:
            return
        self.seen[k] = ts
        self.seen.move_to_end(k)
        while len(self.seen) > self.MAX_SEEN:
            self.seen.popitem(last=False)
        self.emit({
            "ts": ts, "module": "liebert_guard", "code": code, "severity": SEVERITY[code],
            "family": fam, "server": server, "client": client, "port": port,
            "banner": banner, "version": version, "cve": CVES.get(code), "note": NOTES[code],
            "detail": detail,
        })


def read_pcap(path):
    """Classic pcap (LE/BE, us/ns) -> yields (ts, frame, linktype)."""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError("pcapng is not supported; convert first: editcap -F pcap in.pcapng out.pcap")
        endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
                  b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(magic)
        if endian is None:
            raise ValueError("not a classic pcap file")
        div = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
        hdr = f.read(20)
        if len(hdr) < 20:
            raise ValueError("pcap header truncated")
        linktype = struct.unpack(endian + "I", hdr[16:20])[0]
        if linktype not in SUPPORTED_LINKTYPES:
            raise ValueError("unsupported pcap link type %d (supported: %s)" % (
                linktype, ", ".join("%d=%s" % kv for kv in sorted(SUPPORTED_LINKTYPES.items()))))
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            sec, frac, caplen, _ = struct.unpack(endian + "IIII", h)
            yield sec + frac / div, f.read(caplen), linktype


def live(iface, det, promisc=False, stop=None, idle=0.5):
    """Receive-only AF_PACKET loop. Opens the socket for reading; nothing is ever transmitted."""
    import select
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    try:
        if iface:
            s.bind((iface, 0))
            if promisc:
                idx = socket.if_nametoindex(iface)
                s.setsockopt(263, 1, struct.pack("iHH8s", idx, 1, 0, b""))  # PACKET_ADD_MEMBERSHIP
        while not (stop and stop.is_set()):
            if select.select([s], [], [], idle)[0]:
                det.feed(time.time(), s.recv(65535), 1)
    finally:
        s.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Passive RomPager / Misfortune Cookie detector")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("-i", "--iface")
    src.add_argument("-r", "--pcap")
    ap.add_argument("-p", "--port", type=int, default=80)
    ap.add_argument("--cooldown", type=int, default=3600)
    ap.add_argument("--promisc", action="store_true")
    ap.add_argument("-o", "--out", help="append JSON lines here")
    a = ap.parse_args(argv)

    out = open(a.out, "a", buffering=1) if a.out else None

    def emit(f):
        line = json.dumps(f)
        print(line, flush=True)
        if out:
            out.write(line + "\n")

    det = Detector(a.port, a.cooldown, emit)
    if a.pcap:
        try:
            for ts, frame, lt in read_pcap(a.pcap):
                det.feed(ts, frame, lt)
        except (OSError, ValueError) as e:
            print("liebert_guard: %s: %s" % (a.pcap, e), file=sys.stderr)
            return 2
    else:
        try:
            live(a.iface, det, a.promisc)
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
