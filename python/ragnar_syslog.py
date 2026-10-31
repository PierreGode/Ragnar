#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
ragnar_syslog - JSON-lines -> syslog/CEF/LEEF forwarder for the Ragnar suite.

Reads the JSON-lines any Ragnar *watch module emits on stdout and forwards it
to a SIEM/collector as CEF, LEEF, RFC 5424, or RFC 3164. Module-agnostic: it
keys off the suite's shared record conventions (module / type / status /
findings[].code), so one shim serves certwatch, dnswatch, ospfwatch, isiswatch
and the rest rather than each growing its own SIEM plumbing.

    certwatch.py -i mon0 --json | ragnar_syslog.py --transport udp \
        --host siem.example.net --port 514 --format cef --min-status WARN

This is the only component in the suite that transmits. The scanners stay
strictly passive; forwarding your own findings to your own collector is a
separate, deliberate act -- which is exactly why it lives in its own process
with its own systemd unit and its own egress rules.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import re
import socket
import sys
import time
from typing import Optional

VERSION = "1.0"
VENDOR = "Ragnar"

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------
# Ragnar status -> syslog severity (RFC 5424 numeric)
STATUS_SYSLOG = {"CRITICAL": 2, "WARN": 4, "INFO": 6, "OK": 7}
# Ragnar status -> CEF/LEEF severity (0-10)
STATUS_CEF = {"CRITICAL": 9, "WARN": 6, "INFO": 3, "OK": 0}
STATUS_RANK = {"OK": 0, "INFO": 1, "WARN": 2, "CRITICAL": 3}

FACILITIES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
    "lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


# ---------------------------------------------------------------------------
# CEF / LEEF encoding
# ---------------------------------------------------------------------------

def cef_escape_header(s) -> str:
    """CEF header fields: escape backslash and pipe. '=' is NOT special here."""
    return (str(s).replace("\\", "\\\\")
                  .replace("|", "\\|")
                  .replace("\n", " ")
                  .replace("\r", " "))


def cef_escape_ext(s) -> str:
    """CEF extension values: escape backslash, '=', and newlines.

    '|' is NOT special in extensions -- only in the header. Getting these two
    rulesets backwards is the classic CEF bug: it silently corrupts field
    boundaries at the collector rather than erroring.
    """
    return (str(s).replace("\\", "\\\\")
                  .replace("=", "\\=")
                  .replace("\r\n", "\\n")
                  .replace("\n", "\\n")
                  .replace("\r", "\\n"))


_KEYSAFE = re.compile(r"[^A-Za-z0-9]")


def _safe_key(k: str) -> str:
    """CEF extension keys must be alphanumeric-ish and start with a letter."""
    k = _KEYSAFE.sub("", str(k))
    return k if k[:1].isalpha() else "x" + k


def _epoch_ms(ts: Optional[str]) -> int:
    if not ts:
        return int(time.time() * 1000)
    try:
        return int(dt.datetime.fromisoformat(ts).timestamp() * 1000)
    except Exception:
        return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# Record -> extension mapping
# ---------------------------------------------------------------------------

# Fields consumed by the curated mapping / header; not repeated as passthrough.
_CONSUMED = {
    "ts", "module", "type", "status", "findings", "server", "server_ip",
    "server_port", "subject", "issuer", "sni", "serial", "not_after",
    "not_before", "days_left", "key", "sig_hash", "tls_version", "pcap",
    "note", "sans", "seen_in",
}


def worst_finding(rec: dict) -> Optional[dict]:
    """Highest-severity finding -- becomes the CEF signature ID.

    One record can carry several findings. Using the worst one as the
    signature means a SOC rule can alert on deviceEventClassId=EXPIRED
    directly instead of substring-matching a joined list.
    """
    best = None
    for f in rec.get("findings") or []:
        if not isinstance(f, dict) or "code" not in f:
            continue
        if best is None or (STATUS_RANK.get(f.get("severity"), 0) >
                            STATUS_RANK.get(best.get("severity"), 0)):
            best = f
    return best


def certwatch_ext(rec: dict) -> dict:
    """Curated CEF mapping for certwatch records (standard CEF keys)."""
    ext = {}
    if rec.get("server_ip"):
        ext["dst"] = rec["server_ip"]
    if rec.get("server_port"):
        ext["dpt"] = rec["server_port"]
    if rec.get("days_left") is not None:
        ext["cn1"] = rec["days_left"]
        ext["cn1Label"] = "DaysLeft"
    if rec.get("subject"):
        ext["cs2"] = rec["subject"]
        ext["cs2Label"] = "Subject"
    if rec.get("issuer"):
        ext["cs3"] = rec["issuer"]
        ext["cs3Label"] = "Issuer"
    if rec.get("sni"):
        ext["cs4"] = rec["sni"]
        ext["cs4Label"] = "SNI"
    if rec.get("key") or rec.get("sig_hash"):
        ext["cs5"] = f"{rec.get('key', '?')}/{rec.get('sig_hash', '?')}"
        ext["cs5Label"] = "KeyAndSig"
    if rec.get("tls_version"):
        ext["cs6"] = rec["tls_version"]
        ext["cs6Label"] = "TLSVersion"
    if rec.get("not_after"):
        ext["deviceCustomDate1"] = rec["not_after"]
        ext["deviceCustomDate1Label"] = "NotAfter"
    if rec.get("serial"):
        ext["externalId"] = rec["serial"]
    if rec.get("pcap"):
        ext["fname"] = rec["pcap"]
    return ext


MODULE_MAPS = {"certwatch": certwatch_ext}


def generic_ext(rec: dict) -> dict:
    """Best-effort mapping for any module without a curated map.

    Standard keys where the suite conventions allow, then remaining scalars
    passed through under sanitized names. Lossy-but-safe beats dropping data
    from the 20+ modules that don't have bespoke mappings yet.
    """
    ext = {}
    for src_key, cef_key in (("src", "src"), ("src_ip", "src"),
                             ("dst", "dst"), ("dst_ip", "dst"),
                             ("server_ip", "dst"), ("iface", "deviceInboundInterface"),
                             ("src_mac", "smac"), ("dst_mac", "dmac"),
                             ("src_port", "spt"), ("dst_port", "dpt"),
                             ("server_port", "dpt")):
        if rec.get(src_key) is not None and cef_key not in ext:
            ext[cef_key] = rec[src_key]
    skip = {"ts", "module", "type", "status", "findings"} | set(ext)
    for k, v in rec.items():
        if k in skip or k in ("src", "dst", "src_ip", "dst_ip", "server_ip",
                              "src_port", "dst_port", "server_port"):
            continue
        if isinstance(v, (str, int, float, bool)):
            ext[_safe_key(k)] = v
    return ext


def build_ext(rec: dict, module: str) -> dict:
    mapper = MODULE_MAPS.get(module)
    ext = mapper(rec) if mapper else generic_ext(rec)
    ext["rt"] = _epoch_ms(rec.get("ts"))
    if rec.get("status"):
        ext["outcome"] = rec["status"]
    codes = [f["code"] for f in (rec.get("findings") or [])
             if isinstance(f, dict) and "code" in f]
    if codes:
        ext["cs1"] = ",".join(codes)
        ext["cs1Label"] = "Findings"
    details = [f"{f.get('code')}: {f.get('detail')}"
               for f in (rec.get("findings") or [])
               if isinstance(f, dict) and f.get("detail")]
    msg = "; ".join(details) or rec.get("note") or rec.get("type", "")
    if msg:
        ext["msg"] = msg
    if rec.get("seen_count", 1) > 1:
        ext["cnt"] = rec["seen_count"]
    return ext


def to_cef(rec: dict, default_module: str, fan: Optional[dict] = None) -> str:
    module = rec.get("module") or default_module
    wf = fan if fan is not None else worst_finding(rec)
    sig = (wf or {}).get("code") or rec.get("type") or "event"
    name = (wf or {}).get("detail") or rec.get("note") or sig
    status = (wf or {}).get("severity") or rec.get("status") or "INFO"
    sev = STATUS_CEF.get(status, 3)
    ext = build_ext(rec, module)
    if fan is not None:                      # one event per finding
        ext["cs1"] = fan.get("code", "")
        ext["cs1Label"] = "Findings"
        if fan.get("detail"):
            ext["msg"] = fan["detail"]
    head = "|".join(["CEF:0", VENDOR, cef_escape_header(module),
                     VERSION, cef_escape_header(sig),
                     cef_escape_header(name), str(sev)])
    body = " ".join(f"{k}={cef_escape_ext(v)}" for k, v in ext.items())
    return f"{head}|{body}"


def leef_escape(s) -> str:
    return (str(s).replace("\\", "\\\\").replace("\t", " ")
                  .replace("\n", "\\n").replace("\r", "\\n"))


def to_leef(rec: dict, default_module: str, fan: Optional[dict] = None) -> str:
    module = rec.get("module") or default_module
    wf = fan if fan is not None else worst_finding(rec)
    sig = (wf or {}).get("code") or rec.get("type") or "event"
    status = (wf or {}).get("severity") or rec.get("status") or "INFO"
    ext = build_ext(rec, module)
    ext["sev"] = STATUS_CEF.get(status, 3)
    ext["cat"] = rec.get("type", "event")
    ext["devTime"] = rec.get("ts", "")
    ext["devTimeFormat"] = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX"
    # LEEF 2.0 with an explicit tab delimiter (x09).
    head = "|".join(["LEEF:2.0", VENDOR, module, VERSION,
                     str(sig), "x09"])
    body = "\t".join(f"{k}={leef_escape(v)}" for k, v in ext.items())
    return f"{head}|{body}"


def to_json(rec: dict, default_module: str, fan: Optional[dict] = None) -> str:
    out = dict(rec)
    out.setdefault("module", default_module)
    if fan is not None:
        out["findings"] = [fan]
    return json.dumps(out, separators=(",", ":"))


def to_text(rec: dict, default_module: str, fan: Optional[dict] = None) -> str:
    module = rec.get("module") or default_module
    wf = fan if fan is not None else worst_finding(rec)
    codes = (wf or {}).get("code") or ",".join(
        f["code"] for f in (rec.get("findings") or [])) or rec.get("type", "")
    return (f"{module} {rec.get('status', '?')} {rec.get('server', '')} "
            f"{codes} {rec.get('subject', '')}").strip()


FORMATTERS = {"cef": to_cef, "leef": to_leef, "json": to_json, "text": to_text}


# ---------------------------------------------------------------------------
# Syslog framing
# ---------------------------------------------------------------------------

# RFC 5424 MSGID is 1*32PRINTUSASCII (%d33-126) -- underscores and hyphens are
# legal. Only space and non-printables need removing. Stripping more would make
# msgid disagree with the CEF signature for codes like NAME_MISMATCH.
_MSGID_STRIP = re.compile(r"[^\x21-\x7e]")


def syslog_5424(pri: int, ts: dt.datetime, host: str, app: str,
                procid, msgid: str, msg: str) -> str:
    stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
    msgid = _MSGID_STRIP.sub("", str(msgid))[:32] or "-"
    return (f"<{pri}>1 {stamp} {host or '-'} {app or '-'} "
            f"{procid or '-'} {msgid} - {msg}")


def syslog_3164(pri: int, ts: dt.datetime, host: str, tag: str,
                procid, msg: str) -> str:
    # RFC 3164 wants a SPACE-padded day ("Jul  5"), not zero-padded. strftime
    # %e does this but isn't portable, so build it explicitly.
    stamp = (f"{MONTHS[ts.month - 1]} {ts.day:2d} "
             f"{ts.hour:02d}:{ts.minute:02d}:{ts.second:02d}")
    pid = f"[{procid}]" if procid else ""
    return f"<{pri}>{stamp} {host or '-'} {tag}{pid}: {msg}"


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------

def frame(msg: str, framing: str) -> bytes:
    b = msg.encode("utf-8", "replace")
    if framing == "octet":                 # RFC 6587 octet-counting
        return str(len(b)).encode() + b" " + b
    return b + b"\n"                       # non-transparent (LF) framing


class StdoutSink:
    def send(self, msg: str):
        print(msg, flush=True)

    def close(self):
        pass


class UdpSink:
    def __init__(self, host, port):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, msg: str):
        try:
            self.sock.sendto(msg.encode("utf-8", "replace"), self.addr)
        except OSError as e:
            print(f"ragnar_syslog: udp send failed: {e}", file=sys.stderr)

    def close(self):
        self.sock.close()


class TcpSink:
    """TCP with lazy connect, backoff, and a bounded queue.

    A SIEM restart must not kill the scanner pipeline or block it forever, so
    the queue is bounded and drops oldest-first: losing findings during an
    outage beats stalling the capture path or ballooning RAM on a Zero 2W.
    """

    def __init__(self, host, port, framing="lf", queue_max=1000):
        self.host, self.port, self.framing = host, port, framing
        self.sock = None
        self.q = collections.deque(maxlen=queue_max)
        self.next_try = 0.0
        self.backoff = 1.0
        self.dropped = 0

    def _ensure(self) -> bool:
        if self.sock:
            return True
        if time.time() < self.next_try:
            return False
        try:
            self.sock = socket.create_connection((self.host, self.port),
                                                 timeout=5)
            self.backoff = 1.0
            return True
        except OSError as e:
            self.sock = None
            self.next_try = time.time() + self.backoff
            self.backoff = min(self.backoff * 2, 30.0)
            print(f"ragnar_syslog: tcp connect failed ({e}); "
                  f"retry in {self.backoff:.0f}s", file=sys.stderr)
            return False

    def _down(self):
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None
        self.next_try = time.time() + self.backoff

    def send(self, msg: str):
        if len(self.q) == self.q.maxlen:
            self.dropped += 1
        self.q.append(msg)
        self._drain()

    def _drain(self):
        while self.q:
            if not self._ensure():
                return
            m = self.q[0]
            try:
                self.sock.sendall(frame(m, self.framing))
                self.q.popleft()
            except OSError:
                self._down()
                return

    def close(self):
        self._drain()
        if self.dropped:
            print(f"ragnar_syslog: dropped {self.dropped} messages while "
                  f"the collector was unreachable", file=sys.stderr)
        if self.sock:
            self.sock.close()


class UnixSink:
    """Local /dev/log (journald/rsyslog). Tries DGRAM then STREAM."""

    def __init__(self, path="/dev/log"):
        self.path = path
        self.sock = None
        self.stream = False
        self._connect()

    def _connect(self):
        for styp in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            try:
                s = socket.socket(socket.AF_UNIX, styp)
                s.connect(self.path)
                self.sock = s
                self.stream = (styp == socket.SOCK_STREAM)
                return
            except OSError:
                try:
                    s.close()
                except OSError:
                    pass
        raise SystemExit(f"ragnar_syslog: cannot connect to {self.path}")

    def send(self, msg: str):
        data = msg.encode("utf-8", "replace")
        if self.stream:
            data += b"\n"
        try:
            self.sock.sendall(data)
        except OSError as e:
            print(f"ragnar_syslog: unix send failed: {e}", file=sys.stderr)

    def close(self):
        if self.sock:
            self.sock.close()


def build_sink(args):
    if args.transport == "udp":
        return UdpSink(args.host, args.port)
    if args.transport == "tcp":
        return TcpSink(args.host, args.port, args.tcp_framing)
    if args.transport == "unix":
        return UnixSink(args.unix_path)
    return StdoutSink()


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class Forwarder:
    def __init__(self, args):
        self.args = args
        self.fmt = FORMATTERS[args.format]
        self.facility = FACILITIES[args.facility]
        self.host = args.hostname or socket.gethostname()
        self.floor = STATUS_RANK[args.min_status]
        self.stats = collections.Counter()

    def render(self, rec: dict) -> list:
        status = rec.get("status", "INFO")
        if STATUS_RANK.get(status, 1) < self.floor:
            self.stats["filtered"] += 1
            return []
        module = rec.get("module") or self.args.module
        fans = [None]
        if self.args.fanout and rec.get("findings"):
            fans = [f for f in rec["findings"] if isinstance(f, dict)]
        out = []
        for fan in fans:
            payload = self.fmt(rec, self.args.module, fan)
            if len(payload) > self.args.max_len:
                payload = payload[:self.args.max_len - 14] + "...TRUNCATED"
                self.stats["truncated"] += 1
            sev = STATUS_SYSLOG.get(
                (fan or {}).get("severity") or status, 6)
            pri = self.facility * 8 + sev
            now = dt.datetime.now(dt.timezone.utc)
            if self.args.syslog == "none":
                out.append(payload)
            elif self.args.syslog == "3164":
                out.append(syslog_3164(pri, now, self.host, module,
                                       self.args.procid, payload))
            else:
                msgid = (fan or worst_finding(rec) or {}).get("code") \
                    or rec.get("type", "event")
                out.append(syslog_5424(pri, now, self.host, module,
                                       self.args.procid, msgid, payload))
            self.stats["sent"] += 1
        return out

    def run(self, stream, sink) -> int:
        for line in stream:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except (ValueError, TypeError):
                self.stats["malformed"] += 1
                if self.stats["malformed"] <= 5:
                    print(f"ragnar_syslog: skipping malformed JSON line: "
                          f"{line[:80]!r}", file=sys.stderr)
                continue
            if not isinstance(rec, dict):
                self.stats["malformed"] += 1
                continue
            for msg in self.render(rec):
                sink.send(msg)
        return 0


def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Forward Ragnar JSON-lines to syslog/CEF/LEEF.",
        epilog="example: certwatch.py -i mon0 --json | %(prog)s "
               "--transport udp --host siem --port 514 --min-status WARN")
    p.add_argument("--format", choices=sorted(FORMATTERS), default="cef")
    p.add_argument("--transport", choices=("stdout", "udp", "tcp", "unix"),
                   default="stdout")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=514)
    p.add_argument("--unix-path", default="/dev/log")
    p.add_argument("--syslog", choices=("5424", "3164", "none"),
                   default="5424", help="syslog framing (default RFC 5424)")
    p.add_argument("--tcp-framing", choices=("lf", "octet"), default="lf",
                   help="TCP framing: LF-delimited (default, what most "
                        "collectors expect) or RFC 6587 octet-counting")
    p.add_argument("--facility", choices=sorted(FACILITIES), default="local0")
    p.add_argument("--min-status", choices=("OK", "INFO", "WARN", "CRITICAL"),
                   default="INFO")
    p.add_argument("--module", default="ragnar",
                   help="fallback module name for records lacking one")
    p.add_argument("--fanout", action="store_true",
                   help="emit one event per finding instead of per record")
    p.add_argument("--hostname", default=None)
    p.add_argument("--procid", default=None)
    p.add_argument("--max-len", type=int, default=8192)
    p.add_argument("--selftest", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.selftest:
        import ragnar_syslog_selftest
        return ragnar_syslog_selftest.run()
    sink = build_sink(args)
    fwd = Forwarder(args)
    try:
        return fwd.run(sys.stdin, sink)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0
    finally:
        sink.close()
        if fwd.stats:
            print(f"ragnar_syslog: {dict(fwd.stats)}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
