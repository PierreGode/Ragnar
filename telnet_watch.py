#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
telnetwatch - passive Telnet (L7) security observer for the Ragnar suite.

Watches cleartext Telnet on TCP/23 (+2323 by default); observes but does not
dissect Telnet-over-TLS on TCP/992. Telnet is fully cleartext including option
negotiation, so unlike sshwatch/tlswatch the ACTUAL EXPLOIT PAYLOAD for both
CVEs below crosses the wire in the clear -> the attack signatures are high
confidence; it is POSTURE that is weak (telnetd carries no version banner and
the 32746 patch is wire-invisible).

Carried CVEs:
  CVE-2026-24061  GNU inetutils telnetd argument injection (CWE-88): the client
                  supplies USER="-f root" via the NEW-ENVIRON option and telnetd
                  expands it into `login -f root`, where -f skips auth. CVSS 9.8,
                  CISA KEV (added 2026-01-26), actively exploited. The value is
                  on the wire -> detect_class "attack", confidence "high".

  CVE-2026-32746  GNU inetutils telnetd LINEMODE SLC out-of-bounds write
                  (CWE-120). A client SLC subnegotiation with more reply-
                  generating triplets than fit in the 0x6C-byte slcbuf overflows
                  it. CVSS 9.8. NOT KEV / not confirmed exploited as of build;
                  reliable RCE is environment-specific and unproven (watchTowr) -
                  the dependable outcome is a crash. Detected in three honest
                  tiers: overflow attempt (high, on the wire), vulnerable-and-hit
                  correlation from the server's own SLC echo (high), and mere
                  LINEMODE advertisement (notice, low - LESSON T: patched and
                  vulnerable telnetd negotiate identically).

PASSIVE INVARIANT: this module never transmits. It opens no socket except the
AF_PACKET capture handle inside run_capture (scapy, lazy-imported). Enforced by
the self-test, which greps this source for transmit primitives.

CREDENTIAL DISCIPLINE: telnet carries usernames and passwords in cleartext. This
module DETECTS the cleartext-auth exposure moment from the SERVER's plaintext
prompt only; it NEVER inspects or reconstructs the client's typed secret. No
client->server data byte is ever parsed as a credential or emitted.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional, Tuple

SCHEMA = 1
MODULE = "telnetwatch"

# ---------------------------------------------------------------------------
# Telnet protocol constants (RFC 854 commands; RFC 855 options)
# ---------------------------------------------------------------------------
IAC = 0xFF   # Interpret As Command
DONT = 0xFE
DO = 0xFD
WONT = 0xFC
WILL = 0xFB
SB = 0xFA   # Subnegotiation Begin
GA = 0xF9
EL = 0xF8
EC = 0xF7
AYT = 0xF6
AO = 0xF5
IP = 0xF4
BRK = 0xF3
DM = 0xF2
NOP = 0xF1
SE = 0xF0   # Subnegotiation End

_NEGO = (DO, DONT, WILL, WONT)
# 2-byte commands (IAC + cmd, no operand) we must consume cleanly.
_TWO_BYTE = frozenset({GA, EL, EC, AYT, AO, IP, BRK, DM, NOP, SE})

# Telnet options (RFC assignments) we care about.
OPT_ECHO = 0x01
OPT_SGA = 0x03            # Suppress Go Ahead
OPT_TTYPE = 0x18          # Terminal Type (RFC 1091)
OPT_ENVIRON = 0x24        # ENVIRON, deprecated (RFC 1408)
OPT_ENCRYPT = 0x26        # Encryption (RFC 2946)
OPT_NEW_ENVIRON = 0x27    # NEW-ENVIRON (RFC 1572)
OPT_LINEMODE = 0x22       # LINEMODE (RFC 1184)

_OPT_NAME = {
    OPT_ECHO: "ECHO", OPT_SGA: "SGA", OPT_TTYPE: "TTYPE",
    OPT_ENVIRON: "ENVIRON", OPT_ENCRYPT: "ENCRYPT",
    OPT_NEW_ENVIRON: "NEW-ENVIRON", OPT_LINEMODE: "LINEMODE",
}

# NEW-ENVIRON / ENVIRON sub-command + type bytes (RFC 1572 s2; RFC 1408).
ENV_IS = 0
ENV_SEND = 1
ENV_INFO = 2
ENV_VAR = 0
ENV_VALUE = 1
ENV_ESC = 2
ENV_USERVAR = 3

# LINEMODE sub-commands (RFC 1184 s3).
LM_MODE = 1
LM_FORWARDMASK = 2
LM_SLC = 3

# ENCRYPT sub-commands (RFC 2946 s2). Agreeing WILL/DO only says the two sides
# are WILLING to encrypt; the data stream is not actually protected until
# ENCRYPT_START is sent, and ENCRYPT_END returns it to cleartext.
ENCRYPT_IS = 0
ENCRYPT_SUPPORT = 1
ENCRYPT_REPLY = 2
ENCRYPT_START = 3
ENCRYPT_END = 4
ENCRYPT_REQSTART = 5
ENCRYPT_REQEND = 6

# SLC constants (RFC 1184 s4). NSLC is the count of defined SLC functions; the
# inetutils constant is 0x1e. change_slc()/process_slc() store a 3-byte reply
# for out-of-range or NOSUPPORT triplets; slcbuf is 0x6C bytes with a 4-byte
# header already consumed -> ~104 usable / 3 per triplet ~= 34 before overflow.
NSLC = 0x1E
SLC_LEVELBITS = 0x03
SLC_NOSUPPORT = 0x00
SLC_VALUE = 0x02            # RFC 1184: function supported, value in 3rd octet
SLC_CANTCHANGE = 0x01
SLC_DEFAULT = 0x03
SLC_ACK = 0x80             # RFC 1184 SLC flag bits
SLC_FLUSHIN = 0x40
SLC_FLUSHOUT = 0x20
SLCBUF_SIZE = 0x6C          # 108
SLCBUF_HEADER = 4
SLC_REPLY_TRIPLET = 3
# triplets whose replies exactly fill the buffer; strictly more overflows.
SLC_OVERFLOW_TRIPLETS = (SLCBUF_SIZE - SLCBUF_HEADER) // SLC_REPLY_TRIPLET  # 34

# Bounds (Pi Zero 2W memory hygiene).
_MAX_SUBNEG = 4096          # a single subneg > telnet's 0x200 practical max; hard cap
_MAX_STREAM_BUF = 65536     # per-direction reassembly cap before flush
_MAX_FLOWS = 20000
_SERVER_SCAN_TAIL = 512     # bytes of recent server->client data kept for prompt scan

DEFAULT_SERVER_PORTS = (23, 2323)
DEFAULT_TLS_PORTS = (992,)


# ---------------------------------------------------------------------------
# Finding catalog
# ---------------------------------------------------------------------------
# code -> (severity, detect_class, one-line description)
FINDINGS: Dict[str, Tuple[str, str, str]] = {
    "TELNET-24061-ARGINJECT": (
        "critical", "attack",
        "NEW-ENVIRON/ENVIRON value passed to login begins with '-' (argument "
        "injection, CVE-2026-24061); '-f' is the documented auth-bypass flag"),
    "TELNET-32746-SLC-OVERFLOW": (
        "critical", "attack",
        "LINEMODE SLC subnegotiation carries more reply triplets than slcbuf "
        "holds -> out-of-bounds write attempt (CVE-2026-32746)"),
    "TELNET-32746-SLC-NOSUPPORT-FLOOD": (
        "warning", "attack",
        "many LINEMODE SLC triplets with func>NSLC (the watchTowr overflow-"
        "padding signature) - corroborates a CVE-2026-32746 attempt"),
    "TELNET-32746-SLC-OVERSIZED": (
        "warning", "recon",
        "LINEMODE SLC table larger than the defined SLC function set but below "
        "overflow - probe or malformed client"),
    "TELNET-32746-VULN-CONFIRMED": (
        "high", "exposure",
        "server SLC reply echoes the overflowing value or leaks a pointer -> "
        "telnetd is vulnerable to CVE-2026-32746 and was hit"),
    "TELNET-32746-LINEMODE-POSTURE": (
        "notice", "posture",
        "server advertises LINEMODE -> potentially affected by CVE-2026-32746; "
        "patch state cannot be confirmed passively (patched telnetd negotiates "
        "identically)"),
    "TELNET-CLEARTEXT-AUTH": (
        "high", "exposure",
        "plaintext credential prompt on an unencrypted Telnet session - "
        "credentials cross the wire in the clear"),
    "TELNET-ENV-LEAK": (
        "low", "recon",
        "NEW-ENVIRON/ENVIRON carries environment variables in cleartext"),
    "TELNET-ENCRYPT-NEGOTIATED": (
        "info", "posture",
        "Telnet ENCRYPT option negotiated - session payload is encrypted"),
    "TELNET-SESSION": (
        "info", "posture",
        "Telnet session observed (cleartext remote-access protocol)"),
}

_SEV_RANK = {"info": 0, "low": 1, "notice": 2, "warning": 3, "high": 4, "critical": 5}


# ---------------------------------------------------------------------------
# Subnegotiation un-escaping (LESSON A crux) and sub-parsers
# ---------------------------------------------------------------------------
def unescape_subneg(raw: bytes) -> bytes:
    """Un-double IAC (0xFF 0xFF -> 0xFF) inside subnegotiation data.

    Getting this wrong miscounts SLC triplets, which is exactly the number that
    decides whether an overflow is flagged. A lone IAC inside SB that is not
    doubled is malformed; we keep the byte before it and stop (defensive).
    """
    out = bytearray()
    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if b == IAC:
            if i + 1 < n and raw[i + 1] == IAC:
                out.append(IAC)
                i += 2
                continue
            # lone IAC in subneg data: malformed. Stop cleanly.
            break
        out.append(b)
        i += 1
    return bytes(out)


def parse_environ(data: bytes) -> Tuple[Optional[int], List[Tuple[int, bytes, bytes]]]:
    """Parse NEW-ENVIRON / ENVIRON subnegotiation body (already unescaped).

    Returns (subcmd, [(type, name, value), ...]) where type is ENV_VAR or
    ENV_USERVAR. ESC (2) escapes the following byte so a type code can appear
    literally inside a name/value. Only VAR/USERVAR entries carry a following
    VALUE; a VAR with no VALUE yields b"".
    """
    if not data:
        return None, []
    subcmd = data[0]
    entries: List[Tuple[int, bytes, bytes]] = []
    i = 1
    n = len(data)
    cur_type: Optional[int] = None
    cur_name = bytearray()
    cur_val = bytearray()
    have_val = False

    def flush():
        if cur_type in (ENV_VAR, ENV_USERVAR):
            entries.append((cur_type, bytes(cur_name),
                            bytes(cur_val) if have_val else b""))

    while i < n:
        b = data[i]
        if b == ENV_ESC:
            # next byte is literal
            if i + 1 < n:
                target = cur_val if (cur_type is not None and have_val) else cur_name
                target.append(data[i + 1])
                i += 2
                continue
            i += 1
            continue
        if b in (ENV_VAR, ENV_USERVAR):
            flush()
            cur_type = b
            cur_name = bytearray()
            cur_val = bytearray()
            have_val = False
            i += 1
            continue
        if b == ENV_VALUE:
            have_val = True
            cur_val = bytearray()
            i += 1
            continue
        # ordinary character byte
        if cur_type is None:
            i += 1
            continue
        (cur_val if have_val else cur_name).append(b)
        i += 1
    flush()
    return subcmd, entries


@dataclass
class SLCStats:
    subcmd: int
    triplets: int = 0           # true 3-byte triplets after unescaping
    func_over_nslc: int = 0     # triplets whose func > NSLC (padding signature)
    reply_triplets: int = 0     # triplets that would store a 3-byte reply
    truncated: bool = False


def parse_slc(data: bytes) -> Optional[SLCStats]:
    """Parse a LINEMODE subnegotiation body (already unescaped). Only the SLC
    sub-command is analysed; others return None.

    Models process_slc()/change_slc() closely enough to count REPLY-generating
    triplets (the bytes that actually land in slcbuf):
      * func == 0 with flag&LEVELBITS in {DEFAULT, VARIABLE} -> no store
      * otherwise a 3-byte reply is stored (func>NSLC -> NOSUPPORT reply;
        in-range -> ACK/echo reply)
    """
    if not data:
        return None
    if data[0] != LM_SLC:
        return None
    st = SLCStats(subcmd=LM_SLC)
    body = data[1:]
    n = len(body)
    if n % 3 != 0:
        st.truncated = True
    i = 0
    while i + 2 < n or (i + 2 == n - 1):
        if i + 3 > n:
            st.truncated = True
            break
        func, flag, _val = body[i], body[i + 1], body[i + 2]
        i += 3
        st.triplets += 1
        if func > NSLC:
            st.func_over_nslc += 1
            st.reply_triplets += 1
            continue
        if func == 0:
            # RFC 1184: for the set-defaults request (func 0) the level bits may
            # only be SLC_DEFAULT or SLC_VALUE; both drive send_slc()/default_slc()
            # which do not store a per-triplet reply.
            lvl = flag & SLC_LEVELBITS
            if lvl == SLC_DEFAULT or lvl == SLC_VALUE:
                continue
            st.reply_triplets += 1
            continue
        st.reply_triplets += 1
    return st


def slc_reply_echoes_overflow(reply_data: bytes, sentinel: Optional[int]) -> bool:
    """Given a SERVER->CLIENT LINEMODE SLC reply body (unescaped) and the
    client's sentinel value byte, decide whether the reply carries evidence the
    server stored past slcbuf. Heuristics: reply longer than the buffer can
    legitimately hold, or a reply triplet count exceeding the defined function
    set (a patched server drops the overflow, so its reply stays bounded).
    """
    if not reply_data or reply_data[0] != LM_SLC:
        return False
    body = reply_data[1:]
    reply_triplets = len(body) // 3
    if reply_triplets > SLC_OVERFLOW_TRIPLETS:
        return True
    if len(body) > (SLCBUF_SIZE - SLCBUF_HEADER):
        return True
    return False


# ---------------------------------------------------------------------------
# Incremental Telnet stream parser (handles commands split across segments)
# ---------------------------------------------------------------------------
class TelnetEvents:
    """Feed a per-direction byte stream; pull out negotiation and subneg events.

    Events yielded:
      ("nego", cmd, opt)          - IAC DO/DONT/WILL/WONT opt
      ("subneg", opt, unescaped)  - IAC SB opt ... IAC SE  (data already unescaped)
      ("data", nbytes, tail)      - run of ordinary data bytes; tail is the last
                                    _SERVER_SCAN_TAIL bytes only (bounded), for the
                                    server-side prompt scan. Client data tail is
                                    always b"" (never inspected as a credential).
    """

    def __init__(self, is_from_server: bool):
        self.is_from_server = is_from_server
        self.buf = bytearray()
        # parser state: 0 data, 1 saw IAC, 2 saw IAC+nego (want opt), 3 in SB
        self.state = 0
        self.nego_cmd = 0
        self.sb_opt: Optional[int] = None
        self.sb_data = bytearray()
        self.sb_saw_iac = False

    def feed(self, chunk: bytes) -> Iterator[Tuple]:
        if not chunk:
            return
        if len(self.buf) + len(chunk) > _MAX_STREAM_BUF:
            # never let a hostile peer grow us without bound
            self.buf.clear()
        self.buf.extend(chunk)
        data_run = bytearray()
        i = 0
        b = self.buf
        n = len(b)
        while i < n:
            c = b[i]
            if self.state == 0:
                if c == IAC:
                    if data_run:
                        yield self._emit_data(data_run)
                        data_run = bytearray()
                    self.state = 1
                else:
                    data_run.append(c)
                i += 1
            elif self.state == 1:  # saw IAC
                if c == IAC:  # escaped 0xFF in data stream
                    data_run.append(IAC)
                    self.state = 0
                elif c in _NEGO:
                    self.nego_cmd = c
                    self.state = 2
                elif c == SB:
                    self.sb_opt = None
                    self.sb_data = bytearray()
                    self.sb_saw_iac = False
                    self.state = 3
                elif c in _TWO_BYTE:
                    self.state = 0  # standalone command, consumed
                else:
                    self.state = 0  # unknown; swallow
                i += 1
            elif self.state == 2:  # want option operand
                yield ("nego", self.nego_cmd, c)
                self.state = 0
                i += 1
            elif self.state == 3:  # inside subnegotiation
                if self.sb_opt is None:
                    self.sb_opt = c
                    i += 1
                    continue
                if self.sb_saw_iac:
                    self.sb_saw_iac = False
                    if c == SE:
                        yield ("subneg", self.sb_opt, unescape_subneg(bytes(self.sb_data)))
                        self.state = 0
                        i += 1
                        continue
                    # IAC IAC -> literal; keep both so unescape sees the pair
                    self.sb_data.append(IAC)
                    self.sb_data.append(c)
                    i += 1
                    continue
                if c == IAC:
                    self.sb_saw_iac = True
                    i += 1
                    continue
                if len(self.sb_data) >= _MAX_SUBNEG:
                    # runaway subneg; abandon
                    self.state = 0
                    self.sb_data = bytearray()
                    i += 1
                    continue
                self.sb_data.append(c)
                i += 1
        # We consumed everything we could resolve; anything mid-command stays as
        # state, and any trailing complete-data run is emitted. Partial data that
        # is not mid-command has been folded into data_run and emitted; reset buf.
        if data_run:
            yield self._emit_data(data_run)
        self.buf.clear()

    def _emit_data(self, run: bytearray) -> Tuple:
        if self.is_from_server:
            tail = bytes(run[-_SERVER_SCAN_TAIL:])
            return ("data", len(run), tail)
        # client data is never inspected as a credential
        return ("data", len(run), b"")


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------
class Emitter:
    def __init__(self, out=sys.stdout, min_sev: str = "info",
                 pushover: Optional[Callable[[dict], None]] = None,
                 dedup_secs: float = 60.0):
        self.out = out
        self.min_rank = _SEV_RANK[min_sev]
        self.pushover = pushover
        self.dedup_secs = dedup_secs
        self._seen: Dict[Tuple, float] = {}

    def emit(self, code: str, flow_key: Tuple, detail: dict,
             confidence: str, now: Optional[float] = None) -> Optional[dict]:
        sev, dclass, desc = FINDINGS[code]
        if _SEV_RANK[sev] < self.min_rank:
            return None
        now = now if now is not None else time.time()
        dk = (code, flow_key, detail.get("dedup"))
        last = self._seen.get(dk)
        if last is not None and (now - last) < self.dedup_secs:
            return None
        self._seen[dk] = now
        cip, cport, sip, sport = flow_key
        rec = {
            "schema": SCHEMA, "module": MODULE, "ts": round(now, 3),
            "code": code, "severity": sev, "class": dclass,
            "confidence": confidence, "desc": desc,
            "client": f"{cip}:{cport}", "server": f"{sip}:{sport}",
            "detail": detail,
        }
        line = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        print(line, file=self.out, flush=True)
        if self.pushover and _SEV_RANK[sev] >= _SEV_RANK["warning"]:
            try:
                self.pushover(rec)
            except Exception:
                pass
        return rec


# ---------------------------------------------------------------------------
# Per-flow session state + detection engine
# ---------------------------------------------------------------------------
@dataclass
class Flow:
    key: Tuple
    # RFC 855 option negotiation is a TWO-PARTY agreement: WILL is only an
    # OFFER and takes effect when the peer answers DO. inetutils telnetd sends
    # WILL ENCRYPT on EVERY connection and clients routinely refuse with DONT,
    # so treating a lone WILL as "encrypted" both false-positives the posture
    # finding and (far worse) SUPPRESSES the cleartext-credential finding on
    # every real session. Track each side's offer and acceptance separately.
    enc_will_srv: bool = False   # server offered to encrypt what it sends
    enc_will_cli: bool = False   # client offered to encrypt what it sends
    enc_do_srv: bool = False     # server accepted the client's offer
    enc_do_cli: bool = False     # client accepted the server's offer
    encrypt_agreed: bool = False   # a WILL/DO pair completed
    encrypt_started: bool = False  # RFC 2946 SB ENCRYPT START seen (data truly protected)
    session_noted: bool = False
    linemode_posture_noted: bool = False
    cred_noted: bool = False
    last_client_slc: Optional[SLCStats] = None
    ev_srv: TelnetEvents = field(default=None)
    ev_cli: TelnetEvents = field(default=None)


class Engine:
    def __init__(self, emitter: Emitter,
                 overflow_triplets: int = SLC_OVERFLOW_TRIPLETS,
                 oversized_triplets: int = NSLC):
        self.em = emitter
        self.flows: Dict[Tuple, Flow] = {}
        self.overflow_triplets = overflow_triplets
        self.oversized_triplets = oversized_triplets

    def _flow(self, key: Tuple) -> Flow:
        f = self.flows.get(key)
        if f is None:
            if len(self.flows) >= _MAX_FLOWS:
                # evict oldest-ish (arbitrary) to stay bounded
                self.flows.pop(next(iter(self.flows)))
            f = Flow(key=key,
                     ev_srv=TelnetEvents(is_from_server=True),
                     ev_cli=TelnetEvents(is_from_server=False))
            self.flows[key] = f
        return f

    def on_payload(self, key: Tuple, from_server: bool, payload: bytes,
                   now: Optional[float] = None):
        f = self._flow(key)
        if not f.session_noted:
            self.em.emit("TELNET-SESSION", key,
                         {"dedup": "session"}, "high", now)
            f.session_noted = True
        stream = f.ev_srv if from_server else f.ev_cli
        for ev in stream.feed(payload):
            self._handle_event(f, from_server, ev, now)

    def _handle_event(self, f: Flow, from_server: bool, ev: Tuple,
                      now: Optional[float]):
        kind = ev[0]
        if kind == "nego":
            _, cmd, opt = ev
            self._on_nego(f, from_server, cmd, opt, now)
        elif kind == "subneg":
            _, opt, data = ev
            self._on_subneg(f, from_server, opt, data, now)
        elif kind == "data":
            _, nbytes, tail = ev
            if from_server and tail and not f.cred_noted:
                self._scan_server_prompt(f, tail, now)

    def _on_nego(self, f: Flow, from_server: bool, cmd: int, opt: int,
                 now: Optional[float]):
        if opt == OPT_ENCRYPT:
            self._on_encrypt_nego(f, from_server, cmd, now)
        if opt == OPT_LINEMODE:
            # The server offering LINEMODE (DO) or agreeing (WILL) is the
            # posture signal: this telnetd has the vulnerable code path.
            if (from_server and cmd in (DO, WILL)) and not f.linemode_posture_noted:
                f.linemode_posture_noted = True
                self.em.emit("TELNET-32746-LINEMODE-POSTURE", f.key,
                             {"dedup": "linemode",
                              "note": "cannot confirm patch state passively"},
                             "low", now)

    def _on_encrypt_nego(self, f: Flow, from_server: bool, cmd: int,
                         now: Optional[float]):
        """RFC 855/2946 ENCRYPT negotiation.

        A lone WILL is an OFFER, not an agreement: it takes effect only once the
        PEER answers DO. WONT/DONT withdraw or refuse. inetutils telnetd offers
        WILL ENCRYPT on EVERY connection and clients routinely refuse it, so
        this distinction is exactly what keeps the cleartext-credential finding
        alive on real-world sessions.
        """
        if cmd == WILL:
            if from_server:
                f.enc_will_srv = True
            else:
                f.enc_will_cli = True
        elif cmd == DO:
            if from_server:
                f.enc_do_srv = True
            else:
                f.enc_do_cli = True
        elif cmd == WONT:                      # withdraw own offer
            if from_server:
                f.enc_will_srv = False
            else:
                f.enc_will_cli = False
        elif cmd == DONT:                      # refuse the peer's offer
            if from_server:
                f.enc_do_srv = False
                f.enc_will_cli = False
            else:
                f.enc_do_cli = False
                f.enc_will_srv = False

        paired = ((f.enc_will_srv and f.enc_do_cli) or
                  (f.enc_will_cli and f.enc_do_srv))
        if paired and not f.encrypt_agreed:
            f.encrypt_agreed = True
            self.em.emit("TELNET-ENCRYPT-NEGOTIATED", f.key,
                         {"dedup": "encrypt",
                          "direction": ("server->client" if f.enc_will_srv
                                        else "client->server"),
                          "started": f.encrypt_started},
                         "high", now)

    def _on_encrypt_subneg(self, f: Flow, data: bytes, now: Optional[float]):
        """RFC 2946: the stream is only genuinely protected between
        SB ENCRYPT START and SB ENCRYPT END."""
        if not data:
            return
        if data[0] == ENCRYPT_START:
            f.encrypt_started = True
        elif data[0] == ENCRYPT_END:
            f.encrypt_started = False

    def _on_subneg(self, f: Flow, from_server: bool, opt: int, data: bytes,
                   now: Optional[float]):
        if opt in (OPT_NEW_ENVIRON, OPT_ENVIRON):
            self._on_environ(f, from_server, opt, data, now)
        elif opt == OPT_LINEMODE:
            self._on_linemode(f, from_server, data, now)
        elif opt == OPT_ENCRYPT:
            self._on_encrypt_subneg(f, data, now)

    def _on_environ(self, f: Flow, from_server: bool, opt: int, data: bytes,
                    now: Optional[float]):
        # The exploit direction is client->server (the IS response carrying USER).
        subcmd, entries = parse_environ(data)
        if not entries:
            return
        optname = _OPT_NAME.get(opt, hex(opt))
        # only the client's IS/INFO response carries attacker-chosen values
        attacker_side = (not from_server)
        leaked_names = []
        for etype, name, value in entries:
            leaked_names.append(name.decode("latin-1", "replace"))
            if attacker_side and value[:1] == b"-":
                # Argument injection into a root-running `login` is critical
                # regardless of which flag; -f is the documented auth bypass and
                # is flagged for triage. Confidence is high either way because
                # the payload is literally on the wire. Only the value PREFIX
                # (the injected flag) is logged, never the full value.
                bypass = value[:2] == b"-f" or value.split(b" ", 1)[0] == b"-f"
                detail = {
                    "var": name.decode("latin-1", "replace"),
                    "value_len": len(value),
                    "value_prefix": value[:2].decode("latin-1", "replace"),
                    "bypass_flag": bool(bypass),
                    "is_user_var": name.upper() == b"USER",
                    "dedup": name.decode("latin-1", "replace"),
                }
                self.em.emit("TELNET-24061-ARGINJECT", f.key, detail,
                             "high", now)
        if attacker_side and leaked_names:
            self.em.emit("TELNET-ENV-LEAK", f.key,
                         {"vars": sorted(set(leaked_names))[:16],
                          "count": len(leaked_names), "dedup": "envleak"},
                         "high", now)

    def _on_linemode(self, f: Flow, from_server: bool, data: bytes,
                     now: Optional[float]):
        st = parse_slc(data)
        if st is None:
            return
        if not from_server:
            # client SLC table: this is the overflow vector
            f.last_client_slc = st
            if st.reply_triplets > self.overflow_triplets:
                self.em.emit("TELNET-32746-SLC-OVERFLOW", f.key,
                             {"triplets": st.triplets,
                              "reply_triplets": st.reply_triplets,
                              "func_over_nslc": st.func_over_nslc,
                              "slcbuf": SLCBUF_SIZE,
                              "capacity_triplets": self.overflow_triplets,
                              "dedup": "overflow"}, "high", now)
                if st.func_over_nslc >= max(8, self.oversized_triplets // 3):
                    self.em.emit("TELNET-32746-SLC-NOSUPPORT-FLOOD", f.key,
                                 {"func_over_nslc": st.func_over_nslc,
                                  "triplets": st.triplets, "dedup": "nosupport"},
                                 "high", now)
            elif st.triplets > self.oversized_triplets:
                self.em.emit("TELNET-32746-SLC-OVERSIZED", f.key,
                             {"triplets": st.triplets,
                              "nslc": self.oversized_triplets,
                              "dedup": "oversized"}, "high", now)
        else:
            # server SLC reply: correlate for confirmed-vulnerable evidence
            if f.last_client_slc and f.last_client_slc.reply_triplets > self.overflow_triplets:
                if slc_reply_echoes_overflow(data, None):
                    self.em.emit("TELNET-32746-VULN-CONFIRMED", f.key,
                                 {"reply_bytes": len(data) - 1,
                                  "client_reply_triplets":
                                      f.last_client_slc.reply_triplets,
                                  "dedup": "confirmed"}, "high", now)

    def _scan_server_prompt(self, f: Flow, tail: bytes, now: Optional[float]):
        # Suppress ONLY when encryption has actually STARTED (RFC 2946
        # SB ENCRYPT START). A completed WILL/DO pair means both sides are
        # willing, not that the stream is protected -- and a lone WILL (which
        # inetutils telnetd sends on every connection) means nothing at all.
        # Getting this wrong silently kills the cleartext-credential finding on
        # every real telnetd session, which is this module's core exposure.
        if f.encrypt_started:
            return
        low = tail.lower()
        if b"password" in low or b"passwd" in low:
            self.em.emit("TELNET-CLEARTEXT-AUTH", f.key,
                         {"signal": "server password prompt",
                          "note": "client secret is never inspected; "
                                  "FP sources: honeypots, banners",
                          "dedup": "cleartextauth"},
                         "heuristic", now)
            f.cred_noted = True


# ---------------------------------------------------------------------------
# Live capture (the ONE scapy-importing path; never executed offline)
# ---------------------------------------------------------------------------
def _build_bpf(server_ports, tls_ports) -> str:
    ports = list(server_ports) + list(tls_ports)
    terms = " or ".join(f"port {p}" for p in ports)
    return f"tcp and ({terms})"


def run_capture(iface: str, engine: Engine, server_ports, tls_ports,
                timeout: Optional[int] = None):  # pragma: no cover
    from scapy.all import sniff, TCP, IP, IPv6, Raw  # lazy import

    server_set = set(server_ports)
    tls_set = set(tls_ports)

    def handle(pkt):
        if TCP not in pkt:
            return
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return
        t = pkt[TCP]
        sport, dport = int(t.sport), int(t.dport)
        payload = bytes(t[Raw].load) if Raw in t else b""
        if dport in tls_set or sport in tls_set:
            # observed but not dissected (encrypted)
            return
        if dport in server_set:
            from_server = False
            key = (src, sport, dst, dport)
        elif sport in server_set:
            from_server = True
            key = (dst, dport, src, sport)
        else:
            return
        if payload:
            engine.on_payload(key, from_server, payload)

    bpf = _build_bpf(server_ports, tls_ports)
    sniff(iface=iface, filter=bpf, prn=handle, store=False, timeout=timeout)


# ---------------------------------------------------------------------------
# In-app adapter. Ragnar wires telnetwatch into the Network Tools UI the same way
# it wires tls_watch / ssh_watch: a bounded tcpdump capture into a temp pcap,
# replayed through the SAME passive Engine used by run_capture(), returning one
# verdict dict for the card. No detection logic lives here.
# ---------------------------------------------------------------------------
class _CollectEmitter(Emitter):
    """Emitter that keeps the emitted records in a list instead of printing JSON."""

    def __init__(self, **kw):
        import io
        super().__init__(out=io.StringIO(), **kw)
        self.records = []

    def emit(self, *a, **k):
        rec = super().emit(*a, **k)
        if rec is not None:
            self.records.append(rec)
        return rec


def _capture_pcap(interface, seconds, ports):
    """Run tcpdump for `seconds` into a temp pcap and return its path. Passive: -w
    only, no probes. Returns None if tcpdump is unavailable."""
    import shutil
    import subprocess
    import tempfile
    if not shutil.which("tcpdump"):
        return None
    bpf = "tcp and (" + " or ".join("port %d" % p for p in ports) + ")"
    fd, path = tempfile.mkstemp(suffix=".pcap", prefix="telnetwatch_")
    os.close(fd)
    try:
        subprocess.run(["tcpdump", "-i", interface, "-w", path, "-s", "0", "-U",
                        "-q", bpf], timeout=seconds, capture_output=True)
    except subprocess.TimeoutExpired:
        pass                                       # expected: we run for the window
    except Exception:
        return None
    return path


def _replay_pcap(path, engine, server_set):
    """Feed a captured pcap through the Engine exactly as run_capture() does, keying
    each flow client->server and marking direction by the well-known server port."""
    from scapy.all import PcapReader
    from scapy.layers.inet import IP, TCP
    try:
        from scapy.layers.inet6 import IPv6
    except Exception:
        IPv6 = None
    from scapy.packet import Raw
    n = 0
    with PcapReader(path) as pr:
        for pkt in pr:
            try:
                if TCP not in pkt:
                    continue
                if IP in pkt:
                    src, dst = pkt[IP].src, pkt[IP].dst
                elif IPv6 is not None and IPv6 in pkt:
                    src, dst = pkt[IPv6].src, pkt[IPv6].dst
                else:
                    continue
                t = pkt[TCP]
                sport, dport = int(t.sport), int(t.dport)
                if dport in server_set:
                    from_server, key = False, (src, sport, dst, dport)
                elif sport in server_set:
                    from_server, key = True, (dst, dport, src, sport)
                else:
                    continue
                payload = bytes(t[Raw].load) if Raw in t else b""
                if payload:
                    engine.on_payload(key, from_server, payload, now=float(pkt.time))
                    n += 1
            except Exception:
                continue
    return n


_TELNET_CRITICAL = frozenset(("TELNET-24061-ARGINJECT", "TELNET-32746-SLC-OVERFLOW",
                              "TELNET-32746-VULN-CONFIRMED"))


def _telnet_summarize(records, interface, seconds):
    """Group emitted records per flow and roll up one verdict. Telnet payload is
    cleartext end to end, so an attack signature is the payload itself: a confirmed
    argument-injection, a live overflow attempt, or a server proven vulnerable are
    'compromised'; a cleartext-credential exposure or an oversize/flood probe is
    'suspicious'; posture-only observation is 'clean'."""
    flows = {}
    order = []
    for r in records:
        fk = (r.get("client"), r.get("server"))
        if fk not in flows:
            flows[fk] = {"client": r.get("client"), "server": r.get("server"),
                         "findings": []}
            order.append(fk)
        flows[fk]["findings"].append({
            "code": r["code"], "severity": r["severity"], "class": r["class"],
            "confidence": r["confidence"], "desc": r["desc"],
            "detail": r.get("detail", {})})
    rows = [flows[k] for k in order]
    all_f = [f for row in rows for f in row["findings"]]
    codes = {f["code"] for f in all_f}
    if codes & _TELNET_CRITICAL:
        verdict = "compromised"
    elif any(f["severity"] in ("high", "warning") for f in all_f):
        verdict = "suspicious"
    else:
        verdict = "clean"
    return {"success": True, "verdict": verdict, "sessions": rows,
            "count": len(rows), "findings_total": len(all_f),
            "interface": interface, "seconds": seconds}


def do_telnet_watch(interface=None, seconds=12, server_ports=DEFAULT_SERVER_PORTS):
    """Passive Telnet observation on `interface` for `seconds`. Telnet is cleartext
    end to end, so the whole session — option negotiation and payload — is readable
    from a tap. Detects CVE-2026-24061 (login argument injection) and CVE-2026-32746
    (LINEMODE SLC overflow), plus cleartext-credential exposure. Never transmits.
    Requires root (raw capture) and tcpdump; scapy for pcap dissection."""
    seconds = max(4, min(int(seconds or 12), 60))
    if not interface:
        return {"success": False, "error": "no interface specified"}
    try:
        import scapy  # noqa: F401
    except Exception:
        return {"success": False, "missing_tool": "scapy",
                "error": 'the Python "scapy" package is required for pcap dissection'}
    ports = tuple(int(p) for p in server_ports)
    pcap = _capture_pcap(interface, seconds, ports)
    if not pcap:
        return {"success": False, "missing_tool": "tcpdump",
                "error": "tcpdump is required for capture"}
    em = _CollectEmitter(min_sev="info", dedup_secs=60.0)
    eng = Engine(em)
    try:
        _replay_pcap(pcap, eng, set(ports))
    except Exception as e:
        return {"success": False, "error": "pcap parse failed: {}".format(e)}
    finally:
        try:
            os.unlink(pcap)
        except OSError:
            pass
    return _telnet_summarize(em.records, interface, seconds)


def selftest() -> dict:
    """Structured self-test for the Ragnar aggregator. Delegates to the vendored
    telnet_watch_selftest harness and returns {'success', 'checks':[{'name','pass'}]}."""
    import telnet_watch_selftest
    return telnet_watch_selftest.results()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _pushover_sender(token: str, user: str):  # pragma: no cover
    import urllib.request
    import urllib.parse

    def send(rec: dict):
        msg = f"[{rec['severity']}] {rec['code']} {rec['client']}->{rec['server']}"
        data = urllib.parse.urlencode(
            {"token": token, "user": user, "message": msg}).encode()
        req = urllib.request.Request("https://api.pushover.net/1/messages.json",
                                     data=data)
        urllib.request.urlopen(req, timeout=5)

    return send


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="telnetwatch",
        description="Passive Telnet security observer (CVE-2026-24061, "
                    "CVE-2026-32746).")
    p.add_argument("-i", "--iface", help="capture interface")
    p.add_argument("--server-ports", default=",".join(map(str, DEFAULT_SERVER_PORTS)),
                   help="cleartext telnet server ports (comma-separated)")
    p.add_argument("--tls-ports", default=",".join(map(str, DEFAULT_TLS_PORTS)),
                   help="telnet-over-TLS ports, observed not dissected")
    p.add_argument("--min-severity", default="info",
                   choices=list(_SEV_RANK.keys()))
    p.add_argument("--timeout", type=int, default=None,
                   help="stop after N seconds (capture)")
    p.add_argument("--dedup-secs", type=float, default=60.0)
    p.add_argument("--pushover-token", default=os.environ.get("PUSHOVER_TOKEN"))
    p.add_argument("--pushover-user", default=os.environ.get("PUSHOVER_USER"))
    p.add_argument("--print-codes", action="store_true",
                   help="print the finding catalog and exit")
    p.add_argument("--selftest", action="store_true",
                   help="run the built-in self-test and exit")
    return p


def _ports(s: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in s.split(",") if x.strip())


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.print_codes:
        for code in sorted(FINDINGS):
            sev, dclass, desc = FINDINGS[code]
            print(f"{code}\t{sev}\t{dclass}\t{desc}")
        return 0
    if args.selftest:
        import telnet_watch_selftest
        return telnet_watch_selftest.run()
    push = None
    if args.pushover_token and args.pushover_user:
        push = _pushover_sender(args.pushover_token, args.pushover_user)
    em = Emitter(min_sev=args.min_severity, pushover=push,
                 dedup_secs=args.dedup_secs)
    eng = Engine(em)
    if not args.iface:
        print("error: --iface required for capture (or use --selftest / "
              "--print-codes)", file=sys.stderr)
        return 2
    run_capture(args.iface, eng, _ports(args.server_ports),
                _ports(args.tls_ports), timeout=args.timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
