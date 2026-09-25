"""
IRC protocol DPI for Ragnar (server mode).

Cleartext IRC (port 6667, 6697-without-STARTTLS, common alternates) is
historically the most popular botnet C2 channel. This module reconstructs
IRC sessions from packet payloads so the operator can see *what* a host is
actually doing on IRC: NICK, USER, JOIN, PRIVMSG content, channel names,
server NOTICE banners.

Two consumption modes are supported:

1. Sidecar tshark process (preferred when available):

        tshark -i <iface> -l -n
            -Y "tcp.port==6667 or tcp.port==6697"
            -T fields -E separator='\t'
            -e frame.time_epoch
            -e ip.src -e ip.dst
            -e tcp.srcport -e tcp.dstport
            -e tcp.payload

   We hex-decode `tcp.payload` ourselves so the parser is independent of
   tshark's text-formatting flags.

2. Direct payload feeding via `feed_payload(src, dst, sport, dport, ts, data)`
   for unit tests or integration with another packet pipeline (scapy,
   pyshark, etc.).

The parser is line-oriented per (src, dst, sport, dport) flow and tolerates
partial frames by buffering until a CR or LF separator arrives.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# IRC commands of forensic interest. Anything else is counted but not stored.
_INTERESTING_CMDS = frozenset({
    'NICK', 'USER', 'JOIN', 'PART', 'QUIT', 'PRIVMSG', 'NOTICE',
    'TOPIC', 'MODE', 'PASS', 'OPER', 'KICK', 'INVITE',
})

# Server welcome / banner numerics we want to remember for fingerprinting.
_BANNER_NUMERICS = frozenset({'001', '002', '003', '004', '005', '375', '372', '376'})

# Max parsed messages retained per session (ring buffer)
_SESSION_RING = 100


@dataclass
class IRCMessage:
    ts: float
    direction: str    # 'c2s' (client->server) or 's2c'
    prefix: str
    command: str
    params: List[str]
    raw: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'ts': datetime.fromtimestamp(self.ts).isoformat(),
            'direction': self.direction,
            'prefix': self.prefix,
            'command': self.command,
            'params': self.params,
            'raw': self.raw[:500],
        }


@dataclass
class IRCSession:
    """One observed IRC session = one (client_ip, server_ip, server_port)."""
    client_ip: str
    server_ip: str
    server_port: int
    first_seen: float
    last_seen: float
    nick: Optional[str] = None
    user: Optional[str] = None
    channels: set = field(default_factory=set)
    server_banner: List[str] = field(default_factory=list)
    cmd_counts: Dict[str, int] = field(default_factory=dict)
    messages: deque = field(default_factory=lambda: deque(maxlen=_SESSION_RING))

    def to_dict(self) -> Dict[str, Any]:
        return {
            'client_ip': self.client_ip,
            'server_ip': self.server_ip,
            'server_port': self.server_port,
            'first_seen': datetime.fromtimestamp(self.first_seen).isoformat(),
            'last_seen': datetime.fromtimestamp(self.last_seen).isoformat(),
            'nick': self.nick,
            'user': self.user,
            'channels': sorted(self.channels),
            'server_banner': self.server_banner[:8],
            'cmd_counts': dict(self.cmd_counts),
            'recent_messages': [m.to_dict() for m in list(self.messages)[-25:]],
        }


def parse_irc_line(line: str) -> Optional[Tuple[str, str, List[str]]]:
    """Parse a single IRC protocol line per RFC 1459 grammar.

    Returns (prefix, command, params) or None on malformed input.
    """
    if not line:
        return None
    s = line.strip('\r\n')
    if not s:
        return None
    prefix = ''
    if s.startswith(':'):
        space = s.find(' ')
        if space < 0:
            return None
        prefix = s[1:space]
        s = s[space + 1:]
    # Trailing parameter starts at ' :' and grabs the rest verbatim.
    trailing = None
    if ' :' in s:
        head, trailing = s.split(' :', 1)
    else:
        head = s
    tokens = head.split()
    if not tokens:
        return None
    command = tokens[0].upper()
    params = tokens[1:]
    if trailing is not None:
        params.append(trailing)
    return prefix, command, params


class IRCDPIParser:
    """Reassembles IRC traffic into sessions and exposes summaries."""

    # Default IRC ports we attentively listen on.
    DEFAULT_PORTS = frozenset({6667, 6668, 6669, 6697, 7000, 7001})

    MAX_SESSIONS = 1000
    MAX_BUFFER_PER_FLOW = 16 * 1024  # drop oversized garbage rather than grow forever

    def __init__(
        self,
        interface: str = 'any',
        ports: Optional[frozenset] = None,
        on_session_event: Optional[Callable[[IRCSession, IRCMessage], None]] = None,
        tshark_path: Optional[str] = None,
    ) -> None:
        self.interface = interface
        self.ports = ports if ports is not None else self.DEFAULT_PORTS
        self._on_event = on_session_event
        self._tshark = tshark_path or shutil.which('tshark')

        self._sessions: Dict[Tuple[str, str, int], IRCSession] = {}
        # Per-flow line buffer keyed by (src, dst, sport, dport)
        self._buffers: Dict[Tuple[str, str, int, int], bytearray] = {}
        self._lock = threading.Lock()

        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def is_available(self) -> bool:
        return bool(self._tshark)

    def start(self) -> bool:
        if not self.is_available():
            logger.warning("tshark not found; IRC DPI disabled.")
            return False
        if self._running:
            return True
        self._running = True
        self._thread = threading.Thread(target=self._capture_loop,
                                        name="IRCDPI", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._running = False
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    # ------------------------------------------------------------------ #
    # Capture
    # ------------------------------------------------------------------ #

    def _build_cmd(self) -> List[str]:
        port_filter = ' or '.join(f'tcp.port=={p}' for p in sorted(self.ports))
        return [
            'sudo', self._tshark, '-i', self.interface, '-l', '-n',
            '-Y', port_filter,
            '-T', 'fields', '-E', 'separator=\t',
            '-e', 'frame.time_epoch',
            '-e', 'ip.src', '-e', 'ip.dst',
            '-e', 'tcp.srcport', '-e', 'tcp.dstport',
            '-e', 'tcp.payload',
        ]

    def _capture_loop(self) -> None:
        try:
            self._proc = subprocess.Popen(
                self._build_cmd(),
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1,
            )
        except Exception as exc:
            logger.error("Failed to spawn tshark for IRC DPI: %s", exc)
            self._running = False
            return

        try:
            assert self._proc.stdout is not None
            for line in self._proc.stdout:
                if not self._running:
                    break
                self._handle_tshark_line(line.rstrip('\n'))
        finally:
            self.stop()

    def _handle_tshark_line(self, line: str) -> None:
        parts = line.split('\t')
        if len(parts) < 6:
            return
        ts_str, src, dst, sport, dport, hexpay = parts[:6]
        if not hexpay:
            return
        try:
            ts = float(ts_str) if ts_str else time.time()
        except ValueError:
            ts = time.time()
        try:
            sport_i = int(sport)
            dport_i = int(dport)
        except ValueError:
            return
        try:
            # tshark's tcp.payload field is a colon-separated hex string
            payload = bytes.fromhex(hexpay.replace(':', ''))
        except ValueError:
            return
        try:
            self.feed_payload(src, dst, sport_i, dport_i, ts, payload)
        except Exception as exc:
            logger.debug("IRC payload feed error: %s", exc)

    # ------------------------------------------------------------------ #
    # Core: reassemble payloads -> IRC lines -> sessions
    # ------------------------------------------------------------------ #

    def feed_payload(self, src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int,
                     ts: float, payload: bytes) -> List[IRCMessage]:
        """Append `payload` to the per-flow buffer and parse complete lines.

        Returns the list of parsed `IRCMessage` objects produced by this
        call (zero or more).
        """
        if not payload:
            return []

        # Determine direction by which port matches a configured IRC port.
        if dst_port in self.ports and src_port not in self.ports:
            direction = 'c2s'
            client_ip, server_ip, server_port = src_ip, dst_ip, dst_port
        elif src_port in self.ports and dst_port not in self.ports:
            direction = 's2c'
            client_ip, server_ip, server_port = dst_ip, src_ip, src_port
        else:
            # Neither side looks like IRC — bail.
            return []

        flow_key = (src_ip, dst_ip, src_port, dst_port)
        buf = self._buffers.setdefault(flow_key, bytearray())
        if len(buf) + len(payload) > self.MAX_BUFFER_PER_FLOW:
            # Garbage / binary protocol on this port — reset to avoid OOM.
            buf.clear()
        buf += payload

        out: List[IRCMessage] = []
        while True:
            # IRC lines terminate with CRLF, but be lenient and accept LF.
            idx = buf.find(b'\n')
            if idx < 0:
                break
            line_bytes = bytes(buf[:idx]).rstrip(b'\r')
            del buf[:idx + 1]
            if not line_bytes:
                continue
            # Reject obviously-non-text frames quickly (likely TLS or junk).
            if any(b < 9 for b in line_bytes[:8]):
                # Binary control chars at the start -> not IRC
                buf.clear()
                break
            try:
                text = line_bytes.decode('utf-8', errors='replace')
            except Exception:
                continue
            parsed = parse_irc_line(text)
            if parsed is None:
                continue
            prefix, command, params = parsed
            msg = IRCMessage(ts=ts, direction=direction, prefix=prefix,
                             command=command, params=params, raw=text)
            sess = self._update_session(client_ip, server_ip, server_port,
                                        ts, msg)
            out.append(msg)
            if self._on_event:
                try:
                    self._on_event(sess, msg)
                except Exception as exc:
                    logger.debug("IRC on_event failed: %s", exc)
        return out

    def _update_session(self, client_ip: str, server_ip: str,
                        server_port: int, ts: float,
                        msg: IRCMessage) -> IRCSession:
        skey = (client_ip, server_ip, server_port)
        with self._lock:
            sess = self._sessions.get(skey)
            if sess is None:
                if len(self._sessions) >= self.MAX_SESSIONS:
                    # Drop oldest by last_seen
                    oldest = min(self._sessions.values(), key=lambda s: s.last_seen)
                    self._sessions.pop(
                        (oldest.client_ip, oldest.server_ip, oldest.server_port),
                        None,
                    )
                sess = IRCSession(
                    client_ip=client_ip, server_ip=server_ip,
                    server_port=server_port,
                    first_seen=ts, last_seen=ts,
                )
                self._sessions[skey] = sess
            sess.last_seen = ts
            sess.cmd_counts[msg.command] = sess.cmd_counts.get(msg.command, 0) + 1
            if msg.command in _INTERESTING_CMDS:
                sess.messages.append(msg)
            self._apply_message(sess, msg)
        return sess

    @staticmethod
    def _apply_message(sess: IRCSession, msg: IRCMessage) -> None:
        cmd = msg.command
        params = msg.params
        if cmd == 'NICK' and params and msg.direction == 'c2s':
            sess.nick = params[0]
        elif cmd == 'USER' and params and msg.direction == 'c2s':
            sess.user = params[0]
        elif cmd == 'JOIN' and params:
            for ch in params[0].split(','):
                ch = ch.strip()
                if ch:
                    sess.channels.add(ch)
        elif cmd == 'PART' and params:
            for ch in params[0].split(','):
                sess.channels.discard(ch.strip())
        elif cmd in _BANNER_NUMERICS and params:
            # Last param is the human-readable banner text
            sess.server_banner.append(params[-1][:200])

    # ------------------------------------------------------------------ #
    # Accessors
    # ------------------------------------------------------------------ #

    def get_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            sessions = list(self._sessions.values())
        sessions.sort(key=lambda s: s.last_seen, reverse=True)
        return [s.to_dict() for s in sessions[:limit]]

    def get_session(self, client_ip: str, server_ip: str,
                    server_port: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            sess = self._sessions.get((client_ip, server_ip, server_port))
            return sess.to_dict() if sess else None

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._buffers.clear()
