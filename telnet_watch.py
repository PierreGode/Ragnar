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
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, Iterator, List, Optional, Set, Tuple

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
ENCRYPT_ENC_KEYID = 7
ENCRYPT_DEC_KEYID = 8

# CVE-2011-4862: libtelnet/encrypt.c holds the key id in
# `unsigned char keyid[MAXKEYLEN]` with MAXKEYLEN == 64. Both
# encrypt_enc_keyid() (sub-command 7) and encrypt_dec_keyid() (sub-command 8)
# funnel into encrypt_keyid(), which copied `len` bytes with no bound. The MIT
# fix adds `if (len > MAXKEYLEN) len = MAXKEYLEN;`, so a key id LONGER than
# MAXKEYLEN is exactly the vulnerable condition -- and it is countable on the
# wire.
MAXKEYLEN = 64

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

# --- serial-console posture (RFC 2217 + raw TCP) ----------------------------
# In a carrier-neutral colo, console servers carry OTHER TENANTS' device
# consoles. A console session is root-equivalent access to a carrier's gear and
# usually sits outside whatever authentication the device itself enforces, so a
# cleartext one crossing shared or tenant space is an exposure in its own right
# -- posture, not a CVE.
#
# Two carriers, very different confidence:
#   RFC 2217 (Telnet COM-PORT-OPTION 44) is NEGOTIATED ON THE WIRE. The option
#     code is unambiguous, so this is a read-not-inferred, high-confidence
#     identification of a serial console gateway.
#   Raw TCP console has NO protocol framing at all. It can only ever be a
#     heuristic on port plus terminal-shaped content, and is capped accordingly.
OPT_COM_PORT = 0x2C          # 44, RFC 2217

# RFC 2217 command codes. Client->server as listed; the access server's
# responses are the SAME value + 100.
CPO_SIGNATURE = 0
CPO_SET_BAUDRATE = 1
CPO_SET_DATASIZE = 2
CPO_SET_PARITY = 3
CPO_SET_STOPSIZE = 4
CPO_SET_CONTROL = 5
CPO_NOTIFY_LINESTATE = 6
CPO_NOTIFY_MODEMSTATE = 7
CPO_FLOWCONTROL_SUSPEND = 8
CPO_FLOWCONTROL_RESUME = 9
CPO_SET_LINESTATE_MASK = 10
CPO_SET_MODEMSTATE_MASK = 11
CPO_PURGE_DATA = 12
CPO_SERVER_OFFSET = 100

# SET-CONTROL value table (RFC 2217 s3). NOTE 4 is *Request* BREAK State --
# only 5 actually asserts it. Getting this off by one would both miss the
# attack and fire on a harmless query.
CPO_CTRL_BREAK_REQUEST = 4
CPO_CTRL_BREAK_ON = 5
CPO_CTRL_BREAK_OFF = 6
CPO_CTRL_DTR_ON = 8
CPO_CTRL_RTS_ON = 11

# NOTIFY-LINESTATE bit 4 = Break-detect Error: the access server reporting that
# a BREAK was seen on the physical line.
CPO_LINESTATE_BREAK_DETECT = 0x10

# Console-server raw-TCP port ranges seen in the field (Lantronix, Opengear,
# Digi, Cisco terminal servers). Wide and shared with plenty of unrelated
# services, which is exactly why the raw-TCP finding is capped at notice/low.
DEFAULT_CONSOLE_PORTS = tuple(range(2001, 2100)) + tuple(range(3001, 3100)) + \
                        tuple(range(7001, 7100))

# A raw-TCP session only counts as console-shaped with this much terminal-ish
# evidence; the port alone is never enough.
_CONSOLE_MIN_SIGNALS = 2

# --- r-services (RFC 1282 rlogin) -------------------------------------------
# Folded into telnetwatch rather than given its own module: same cleartext
# remote-access threat model, same tap, same finding pipeline. It is a SEPARATE
# parser path and never touches the Telnet IAC state machine -- rlogin has no
# IAC framing and running its bytes through telrcv-style logic would be wrong.
RLOGIN_PORT = 513
RSH_PORT = 514
REXEC_PORT = 512
DEFAULT_RSERVICES_PORTS = (RLOGIN_PORT, RSH_PORT, REXEC_PORT)

# rsh's stderr channel is a SEPARATE TCP connection in the REVERSE direction:
# the client advertises a port in handshake field 0 and the SERVER connects
# back to it from a privileged source port. Measured with the real rsh-redone
# client: session  client:1023 -> server:514
#                  stderr   server:1010 -> client:1022
# Both ends of the back-connect are privileged, so admitting this range is what
# makes the correlation capturable at all -- `tcp port 514` alone never sees it.
PRIV_PORTRANGE = (512, 1023)

# rcp wire records (BSD rcp protocol, run as a command over rsh)
#   C<mode> <size> <name>\n   file      D<mode> <size> <name>\n   directory
#   E\n                       dir end   T<mt> 0 <at> 0\n           times
_RCP_MAX_LINE = 1024
_RCP_MAX_RECORDS = 512
NEWLINE = bytes([0x0A])
RCP_ACK = bytes([0x00])

# rlogin's trust model rests on the client binding a PRIVILEGED source port:
# in.rlogind accepts .rhosts trust only from ports below 1024, because on a
# classic multi-user host only root could bind one.
PRIV_PORT_MAX = 1023
FTP_DATA_PORT = 20           # CVE-1999-0185: an FTP data connection is
                             # privileged-sourced and can be aimed at rlogind

# Handshake field caps. Real fields are short; a hostile peer must not be able
# to grow our state without bound.
_RL_MAX_FIELD = 256
_RL_MAX_HANDSHAKE = 1024

# rlogin window-size control sequence (RFC 1282 s2): 0xFF 0xFF 's' 's' + 8 bytes
_RL_WINDOW_MAGIC = b"\xff\xffss"
_RL_WINDOW_LEN = len(_RL_WINDOW_MAGIC) + 8

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
    "TELNET-4862-KEYID-OVERFLOW": (
        "critical", "attack",
        "Telnet ENCRYPT ENC_KEYID/DEC_KEYID sub-option carries a key id longer "
        "than MAXKEYLEN(64) - encrypt_keyid() heap overflow attempt "
        "(CVE-2011-4862)"),
    "TELNET-39028-EC-EL-PREAUTH": (
        "warning", "attack",
        "IAC EC/EL received before any session data - telrcv() NULL pointer "
        "dereference, the 2-byte telnetd DoS (CVE-2022-39028)"),
    "TELNET-39028-CRASH-LOOP": (
        "high", "attack",
        "repeated pre-session IAC EC/EL to the same server - sustained "
        "CVE-2022-39028 crash attempts; inetd disables a service that loops"),
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
    "CONSOLE-RFC2217-SESSION": (
        "warning", "posture",
        "RFC 2217 COM-PORT-OPTION negotiated - this Telnet session is a serial "
        "console gateway carrying device console traffic in cleartext"),
    "CONSOLE-RFC2217-BREAK": (
        "high", "attack",
        "RFC 2217 SET-CONTROL asserted BREAK on the serial line - on Cisco, "
        "Juniper and Arista consoles a BREAK during boot drops to "
        "ROMmon/loader, the documented password-recovery path"),
    "CONSOLE-RAW-TCP-SUSPECTED": (
        "notice", "posture",
        "cleartext terminal-shaped session on a console-server port with no "
        "protocol framing - probable raw-TCP serial console; heuristic, port "
        "alone is never sufficient"),
    "RSVC-RSH-SESSION": (
        "info", "posture",
        "rsh session observed - cleartext remote command execution with "
        "trust-based authentication; only the command's first token is recorded"),
    "RSVC-REXEC-CLEARTEXT-CRED": (
        "critical", "exposure",
        "rexec handshake carries a PASSWORD in cleartext on the wire - the "
        "credential is exposed to anyone on path; the value is never logged"),
    "RSVC-RCP-7282-DOTNAME": (
        "high", "attack",
        "rcp server sent a file record whose name is '.' or empty - "
        "CVE-2019-7282, netkit rcp accepts it and writes outside the intended "
        "target"),
    "RSVC-RCP-7283-UNREQUESTED": (
        "high", "attack",
        "rcp server sent a file the client never requested - CVE-2019-7283, "
        "the rcp twin of CVE-2019-6111; a malicious server overwrites arbitrary "
        "files in the client's target directory"),
    "RSVC-RCP-7283-TRAVERSAL": (
        "high", "attack",
        "rcp server sent a file record whose name contains a path separator or "
        "'..' - directory traversal out of the client's target directory "
        "(corroborates CVE-2019-7283)"),
    "RSVC-RLOGIN-SESSION": (
        "info", "posture",
        "rlogin session observed (RFC 1282) - cleartext, trust-based remote "
        "access with no cryptographic authentication"),
    "RSVC-RLOGIN-ARGINJECT": (
        "critical", "attack",
        "rlogin handshake user field begins with '-' - argument injection into "
        "login (CVE-1999-0113); '-f' skips authentication entirely"),
    "RSVC-TRUST-AUTH": (
        "high", "exposure",
        "rlogin session reached the data phase with no password prompt - "
        ".rhosts/hosts.equiv trust authentication, defeated by source-address "
        "spoofing or any privileged-port foothold"),
    "RSVC-UNPRIV-SRCPORT": (
        "warning", "recon",
        "rlogin connection from an unprivileged source port (>=1024) - a "
        "conformant rlogind rejects this; indicates a probe or a permissive "
        "daemon"),
    "RSVC-FTPDATA-SRCPORT": (
        "critical", "attack",
        "connection to rlogin from TCP source port 20 - an FTP data channel "
        "aimed at the r-services trust port to borrow its privileged source "
        "port (CVE-1999-0185)"),
    "TELNET-SESSION": (
        "info", "posture",
        "Telnet session observed (cleartext remote-access protocol)"),
}

_SEV_RANK = {"info": 0, "low": 1, "notice": 2, "warning": 3, "high": 4, "critical": 5}


def fmt_endpoint(ip: str, port: int) -> str:
    """Render an address:port pair unambiguously across both families.

    IPv4 is `10.0.0.1:23`. IPv6 MUST use RFC 3986 bracket notation -- a bare
    f"{ip}:{port}" on an IPv6 address yields `2001:db8::9:51000`, which is
    ambiguous (that trailing group could be part of the address) and cannot be
    split back into host and port by any consumer. Detection is unaffected, but
    every emitted record, the mesh, the web UI and the PDF reporter all consume
    these strings, so the wrong form corrupts the whole downstream chain.
    """
    return f"[{ip}]:{port}" if ":" in str(ip) else f"{ip}:{port}"


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
      ("cmd", cmd)                - standalone IAC <cmd> (EC, EL, AYT, ...)
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
                    # Standalone command. These were consumed silently before
                    # CVE-2022-39028 was carried; EC (0xF7) and EL (0xF8) are
                    # the 2-byte DoS trigger, so the engine must see them.
                    self.state = 0
                    yield ("cmd", c)
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
            "client": fmt_endpoint(cip, cport),
            "server": fmt_endpoint(sip, sport),
            "af": "ipv6" if ":" in str(cip) else "ipv4",
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
    # CVE-2022-39028: telrcv()'s EC/EL path dereferences a pointer that is NULL
    # until the session has actually carried data. EC/EL are LEGITIMATE RFC 854
    # commands (backspace / erase-line), so the exploit is distinguished by
    # arriving BEFORE any ordinary data byte -- not by the bytes themselves.
    client_data_seen: bool = False
    ec_el_preauth: int = 0
    keyid_overflow_noted: bool = False
    # RFC 2217 serial-console posture
    comport_noted: bool = False
    comport_params: Dict[str, object] = field(default_factory=dict)
    cred_noted: bool = False
    last_client_slc: Optional[SLCStats] = None
    ev_srv: TelnetEvents = field(default=None)
    ev_cli: TelnetEvents = field(default=None)


class Engine:
    def __init__(self, emitter: Emitter,
                 overflow_triplets: int = SLC_OVERFLOW_TRIPLETS,
                 oversized_triplets: int = NSLC,
                 crash_loop_threshold: int = 5):
        self.em = emitter
        self.flows: Dict[Tuple, Flow] = {}
        # CVE-2022-39028 crash attempts per SERVER, across flows: each attempt
        # kills one telnetd, so the damage is cumulative rather than per-session.
        self._ecel_hosts: Dict[str, int] = {}
        self.crash_loop_threshold = crash_loop_threshold
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
        elif kind == "cmd":
            _, cmd = ev
            self._on_cmd(f, from_server, cmd, now)
        elif kind == "data":
            _, nbytes, tail = ev
            if (not from_server) and nbytes > 0:
                f.client_data_seen = True
            if from_server and tail and not f.cred_noted:
                self._scan_server_prompt(f, tail, now)

    def _on_nego(self, f: Flow, from_server: bool, cmd: int, opt: int,
                 now: Optional[float]):
        if opt == OPT_ENCRYPT:
            self._on_encrypt_nego(f, from_server, cmd, now)
        if opt == OPT_COM_PORT and cmd in (DO, WILL):
            self._note_comport(f, now)
        if opt == OPT_LINEMODE:
            # The server offering LINEMODE (DO) or agreeing (WILL) is the
            # posture signal: this telnetd has the vulnerable code path.
            if (from_server and cmd in (DO, WILL)) and not f.linemode_posture_noted:
                f.linemode_posture_noted = True
                self.em.emit("TELNET-32746-LINEMODE-POSTURE", f.key,
                             {"dedup": "linemode",
                              "note": "cannot confirm patch state passively"},
                             "low", now)

    def _on_cmd(self, f: Flow, from_server: bool, cmd: int,
                now: Optional[float]):
        """CVE-2022-39028: telrcv()'s EC/EL path dereferences a NULL pointer
        when the session has not yet carried data, crashing telnetd in two
        bytes (GNU Inetutils <=2.3, MIT krb5-appl <=1.0.3, netkit/freebsd/
        netbsd telnetd).

        EC and EL are ordinary RFC 854 commands -- a real client emits them on
        backspace and Ctrl-U -- so matching the bytes alone would fire on every
        interactive session. The exploit is distinguished by arriving BEFORE
        any client data, which is exactly the state in which the pointer is
        still NULL.
        """
        if from_server or cmd not in (EC, EL):
            return
        if f.client_data_seen:
            return                      # ordinary erase during a live session
        f.ec_el_preauth += 1
        self.em.emit("TELNET-39028-EC-EL-PREAUTH", f.key,
                     {"cmd": "EC" if cmd == EC else "EL",
                      "cmd_byte": cmd,
                      "preauth_count": f.ec_el_preauth,
                      "dedup": "ecel"}, "high", now)
        # inetd disables a service that crashes repeatedly ("server failing
        # (looping), service terminated"), so sustained attempts against one
        # server are the finding that actually matters operationally.
        server_ip = f.key[2]
        self._ecel_hosts[server_ip] = self._ecel_hosts.get(server_ip, 0) + 1
        n = self._ecel_hosts[server_ip]
        if n >= self.crash_loop_threshold:
            self.em.emit("TELNET-39028-CRASH-LOOP", f.key,
                         {"server": server_ip, "attempts": n,
                          "threshold": self.crash_loop_threshold,
                          "dedup": f"loop:{server_ip}:{n // self.crash_loop_threshold}"},
                         "high", now)

    def _note_comport(self, f: Flow, now: Optional[float]):
        """RFC 2217 option 44 seen -> this Telnet session is a serial console
        gateway. Read-not-inferred: the option code is on the wire."""
        if f.comport_noted:
            return
        f.comport_noted = True
        self.em.emit("CONSOLE-RFC2217-SESSION", f.key,
                     {"option": OPT_COM_PORT, "dedup": "comport"}, "high", now)

    def _on_comport_subneg(self, f: Flow, from_server: bool, data: bytes,
                           now: Optional[float]):
        """Parse RFC 2217 sub-options.

        A subnegotiation implies the option is in use even if the WILL/DO was
        missed (a mid-session tap joins after negotiation), so this also raises
        the session finding.

        The one that matters operationally is SET-CONTROL = 5, Set BREAK State
        ON. A BREAK during boot drops Cisco to ROMmon and Juniper/Arista to
        their loaders -- the documented password-recovery path, i.e. full device
        takeover from a console session. Value 4 is only a REQUEST for the
        current break state and must NOT fire; 6 clears it.
        """
        if not data:
            return
        self._note_comport(f, now)
        cmd = data[0]
        body = data[1:]
        # normalise the access server's echo (client code + 100) to one space
        base = cmd - CPO_SERVER_OFFSET if cmd >= CPO_SERVER_OFFSET else cmd

        if base == CPO_SET_BAUDRATE and len(body) >= 4:
            baud = int.from_bytes(body[:4], "big")
            if baud:
                f.comport_params["baud"] = baud
        elif base == CPO_SET_DATASIZE and body:
            f.comport_params["datasize"] = body[0]
        elif base == CPO_SET_PARITY and body:
            f.comport_params["parity"] = body[0]
        elif base == CPO_SET_STOPSIZE and body:
            f.comport_params["stopsize"] = body[0]
        elif base == CPO_SET_CONTROL and body:
            if body[0] == CPO_CTRL_BREAK_ON:
                self.em.emit("CONSOLE-RFC2217-BREAK", f.key,
                             {"set_control": body[0],
                              "direction": "server->client" if from_server
                                           else "client->server",
                              "params": dict(f.comport_params),
                              "dedup": "break"}, "high", now)
        elif base == CPO_NOTIFY_LINESTATE and body:
            if body[0] & CPO_LINESTATE_BREAK_DETECT:
                # the access server reporting a BREAK observed on the line
                self.em.emit("CONSOLE-RFC2217-BREAK", f.key,
                             {"linestate": body[0],
                              "signal": "break-detect",
                              "direction": "server->client",
                              "params": dict(f.comport_params),
                              "dedup": "break"}, "high", now)

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

    def _on_encrypt_subneg(self, f: Flow, data: bytes, now: Optional[float],
                           from_server: bool = False):
        """RFC 2946 ENCRYPT sub-options.

        START/END gate the cleartext-credential finding. ENC_KEYID/DEC_KEYID
        carry CVE-2011-4862: libtelnet's encrypt_keyid() copied the supplied key
        id into a fixed 64-byte buffer with no bound, so a key id longer than
        MAXKEYLEN is the vulnerable condition, countable directly on the wire.
        """
        if not data:
            return
        sub = data[0]
        if sub == ENCRYPT_START:
            f.encrypt_started = True
            return
        if sub == ENCRYPT_END:
            f.encrypt_started = False
            return
        if sub in (ENCRYPT_ENC_KEYID, ENCRYPT_DEC_KEYID):
            keyid = data[1:]
            if len(keyid) > MAXKEYLEN and not f.keyid_overflow_noted:
                f.keyid_overflow_noted = True
                self.em.emit("TELNET-4862-KEYID-OVERFLOW", f.key,
                             {"subcmd": ("ENC_KEYID" if sub == ENCRYPT_ENC_KEYID
                                         else "DEC_KEYID"),
                              "keyid_len": len(keyid),
                              "maxkeylen": MAXKEYLEN,
                              "overflow_bytes": len(keyid) - MAXKEYLEN,
                              "from_server": from_server,
                              "dedup": "keyid"}, "high", now)

    def _on_subneg(self, f: Flow, from_server: bool, opt: int, data: bytes,
                   now: Optional[float]):
        if opt in (OPT_NEW_ENVIRON, OPT_ENVIRON):
            self._on_environ(f, from_server, opt, data, now)
        elif opt == OPT_LINEMODE:
            self._on_linemode(f, from_server, data, now)
        elif opt == OPT_ENCRYPT:
            self._on_encrypt_subneg(f, data, now, from_server=from_server)
        elif opt == OPT_COM_PORT:
            self._on_comport_subneg(f, from_server, data, now)

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
# rlogin (RFC 1282) -- a SEPARATE parser path
# ---------------------------------------------------------------------------
# rlogin has no IAC framing. Its handshake is four NUL-terminated fields sent
# by the client in one burst:
#
#     <NUL> client-user <NUL> server-user <NUL> term/speed <NUL>
#
# the server answers with a single 0x00 byte, and the session becomes a raw
# byte stream. The ONLY in-band framing after that is the window-size control
# sequence 0xFF 0xFF 's' 's' + 8 bytes, which must be skipped rather than read
# as data.
#
# in.rlogind hands the SERVER-USER field to login(1). If it begins with '-' the
# shell expands it as an option, and `-f` tells login to skip authentication --
# CVE-1999-0113, the same argument-injection shape as CVE-2007-0882 and
# CVE-2026-24061, a quarter-century apart.

@dataclass
class RloginHandshake:
    complete: bool = False
    truncated: bool = False
    client_user: bytes = b""
    server_user: bytes = b""
    term: bytes = b""


def parse_rlogin_handshake(data: bytes) -> RloginHandshake:
    """Parse the client's opening burst. Never raises on malformed input.

    RFC 1282 puts a leading NUL before the first field. Some clients omit it,
    so a missing leading NUL is tolerated rather than treated as a parse
    failure -- refusing to parse would silently drop the exploit case.
    """
    hs = RloginHandshake()
    if not data:
        return hs
    buf = data[:_RL_MAX_HANDSHAKE]
    if len(data) > _RL_MAX_HANDSHAKE:
        hs.truncated = True
    i = 1 if buf[:1] == b"\x00" else 0
    fields: List[bytes] = []
    cur = bytearray()
    while i < len(buf) and len(fields) < 3:
        b = buf[i]
        if b == 0:
            fields.append(bytes(cur[:_RL_MAX_FIELD]))
            cur = bytearray()
        else:
            if len(cur) < _RL_MAX_FIELD:
                cur.append(b)
            else:
                hs.truncated = True
        i += 1
    if len(fields) >= 1:
        hs.client_user = fields[0]
    if len(fields) >= 2:
        hs.server_user = fields[1]
    if len(fields) >= 3:
        hs.term = fields[2]
        hs.complete = True
    return hs


def strip_rlogin_window(data: bytes) -> bytes:
    """Remove RFC 1282 window-size control sequences from a byte run.

    RFC 1282 s2 defines this sequence as CLIENT->SERVER: the client announces a
    terminal resize as 0xFF 0xFF 's' 's' followed by four 16-bit values. It is
    in-band control, not session data.

    Two places it matters, both real:
      * the client handshake buffer -- a resize arriving in the same segment as
        the opening burst would otherwise be parsed as handshake field bytes and
        corrupt the user fields the CVE-1999-0113 check reads;
      * any byte COUNT -- 12 control bytes must never be mistaken for session
        data, or a server that only ever sends control traffic would satisfy a
        data threshold it never actually met.
    """
    if _RL_WINDOW_MAGIC not in data:
        return data
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        if data[i:i + 4] == _RL_WINDOW_MAGIC:
            i += _RL_WINDOW_LEN
            continue
        out.append(data[i])
        i += 1
    return bytes(out)


@dataclass
class RloginFlow:
    key: Tuple
    session_noted: bool = False
    handshake_done: bool = False
    hs_buf: bytearray = field(default_factory=bytearray)
    server_bytes: int = 0
    password_prompted: bool = False
    trust_noted: bool = False
    srcport_noted: bool = False
    cred_noted: bool = False


class RloginEngine:
    """Per-flow rlogin observer. Deliberately independent of the Telnet
    Engine: shared emitter, shared flow-key shape, separate state."""

    def __init__(self, emitter: Emitter, trust_data_threshold: int = 16):
        self.em = emitter
        self.flows: Dict[Tuple, RloginFlow] = {}
        # Bytes of server->client data, after the handshake ack and with no
        # password prompt, that make "this session authenticated without a
        # password" a safe call rather than a guess. Its only job is to
        # distinguish real shell/MOTD output from the single 0x00 ack, so it is
        # deliberately low -- a short banner like "Last login: ...\n$ " must
        # still count, or trust auth goes unreported on terse hosts.
        self.trust_data_threshold = trust_data_threshold

    def _flow(self, key: Tuple) -> RloginFlow:
        f = self.flows.get(key)
        if f is None:
            if len(self.flows) >= _MAX_FLOWS:
                self.flows.pop(next(iter(self.flows)))
            f = RloginFlow(key=key)
            self.flows[key] = f
        return f

    def on_payload(self, key: Tuple, from_server: bool, payload: bytes,
                   now: Optional[float] = None):
        f = self._flow(key)
        if not f.session_noted:
            f.session_noted = True
            self.em.emit("RSVC-RLOGIN-SESSION", key, {"dedup": "session"},
                         "high", now)
            self._check_source_port(f, now)
        if from_server:
            self._on_server(f, payload, now)
        else:
            self._on_client(f, payload, now)

    # -- source-port trust checks (CVE-1999-0185 and the unprivileged case) --
    def _check_source_port(self, f: RloginFlow, now: Optional[float]):
        if f.srcport_noted:
            return
        f.srcport_noted = True
        sport = f.key[1]
        if sport == FTP_DATA_PORT:
            # An FTP server's data channel originates from port 20, which is
            # privileged. Pointing one at rlogind borrows that privilege and
            # satisfies the .rhosts source-port test without ever holding root
            # on the client.
            self.em.emit("RSVC-FTPDATA-SRCPORT", f.key,
                         {"src_port": sport, "dedup": "ftpdata"}, "high", now)
        elif sport > PRIV_PORT_MAX:
            self.em.emit("RSVC-UNPRIV-SRCPORT", f.key,
                         {"src_port": sport, "priv_max": PRIV_PORT_MAX,
                          "dedup": "unpriv"}, "high", now)

    # -- client side: the handshake carries the injection ---------------------
    def _on_client(self, f: RloginFlow, payload: bytes, now: Optional[float]):
        if f.handshake_done:
            return                      # session data is never inspected
        # strip resize control BEFORE parsing: a resize sharing a segment with
        # the opening burst would otherwise corrupt the user fields.
        clean = strip_rlogin_window(payload)
        if len(f.hs_buf) < _RL_MAX_HANDSHAKE:
            f.hs_buf.extend(clean[:_RL_MAX_HANDSHAKE - len(f.hs_buf)])
        hs = parse_rlogin_handshake(bytes(f.hs_buf))
        if not hs.complete:
            return                      # wait for more segments
        f.handshake_done = True
        for label, value in (("client_user", hs.client_user),
                             ("server_user", hs.server_user)):
            if value[:1] == b"-":
                bypass = value[:2] == b"-f"
                self.em.emit("RSVC-RLOGIN-ARGINJECT", f.key,
                             {"field": label,
                              "value_len": len(value),
                              "value_prefix": value[:2].decode("latin-1", "replace"),
                              "bypass_flag": bool(bypass),
                              "dedup": label}, "high", now)

    # -- server side: absence of a password prompt is the trust signal --------
    def _on_server(self, f: RloginFlow, payload: bytes, now: Optional[float]):
        # Defensive on this side too: the sequence is client->server per RFC
        # 1282, but stripping keeps the byte COUNT below honest -- control
        # bytes must never be counted as the shell output that proves a
        # password-free login.
        data = strip_rlogin_window(payload)
        low = data.lower()
        if b"password" in low or b"passwd" in low:
            f.password_prompted = True
            if not f.cred_noted:
                f.cred_noted = True
                self.em.emit("TELNET-CLEARTEXT-AUTH", f.key,
                             {"signal": "rlogin server password prompt",
                              "protocol": "rlogin",
                              "note": "client secret is never inspected",
                              "dedup": "cleartextauth"}, "heuristic", now)
            return
        # the handshake ack is a single 0x00 and is not session data
        f.server_bytes += len(data.lstrip(b"\x00"))
        if (f.handshake_done and not f.password_prompted
                and not f.trust_noted
                and f.server_bytes >= self.trust_data_threshold):
            f.trust_noted = True
            self.em.emit("RSVC-TRUST-AUTH", f.key,
                         {"server_bytes": f.server_bytes,
                          "threshold": self.trust_data_threshold,
                          "dedup": "trust"}, "high", now)




# ---------------------------------------------------------------------------
# rsh (514) / rexec (512) and the rcp records that ride over rsh
# ---------------------------------------------------------------------------
# Both handshakes are four NUL-terminated fields sent by the client in one
# burst, but field 2 means something VERY different in each:
#
#   rsh   : <stderr-port> \0 <local-user>  \0 <remote-user> \0 <command> \0
#   rexec : <stderr-port> \0 <username>    \0 <PASSWORD>    \0 <command> \0
#
# rexec therefore puts a password on the wire in cleartext. Its LENGTH is
# recorded; the value never is.
#
# rcp is not a protocol of its own -- it is the COMMAND rsh runs. When the
# command's first token is `rcp` in source mode (-f), the SERVER streams file
# records back and the client writes them. netkit's rcp trusts those records,
# which is CVE-2019-7282 and CVE-2019-7283.

@dataclass
class RcpState:
    """Record-stream position for an rcp -f transfer (server -> client)."""
    requested: bytes = b""          # the path the client asked for
    glob: bool = False              # request contained a wildcard
    recursive: bool = False         # request had -r, so D records are legal
    buf: bytearray = field(default_factory=bytearray)
    skip: int = 0                   # bytes of file payload still to skip
    files_seen: int = 0
    records: int = 0


@dataclass
class RshFlow:
    key: Tuple
    is_rexec: bool = False
    session_noted: bool = False
    session_emitted: bool = False
    handshake_done: bool = False
    hs_buf: bytearray = field(default_factory=bytearray)
    stderr_port: int = 0
    srcport_noted: bool = False
    password_prompted: bool = False
    trust_noted: bool = False
    server_bytes: int = 0
    rcp: Optional[RcpState] = None
    backconnect_seen: bool = False


def parse_rsh_handshake(data: bytes) -> Optional[List[bytes]]:
    """Return the four NUL-terminated fields, or None until all four arrive.
    Never raises; fields are capped."""
    if not data:
        return None
    buf = data[:_RL_MAX_HANDSHAKE]
    fields: List[bytes] = []
    cur = bytearray()
    for b in buf:
        if b == 0:
            fields.append(bytes(cur[:_RL_MAX_FIELD]))
            cur = bytearray()
            if len(fields) == 4:
                return fields
        elif len(cur) < _RL_MAX_FIELD:
            cur.append(b)
    return None


def rcp_request_info(command: bytes) -> Optional[Tuple[bytes, bool, bool]]:
    """If `command` is an rcp SOURCE-mode invocation, return
    (requested_path, has_glob, recursive); otherwise None.

    Only source mode (-f) matters: that is the direction in which the SERVER
    chooses what to send, which is exactly what CVE-2019-7283 abuses.
    """
    toks = command.split()
    if not toks:
        return None
    prog = toks[0].rsplit(b"/", 1)[-1]
    if prog != b"rcp":
        return None
    flags = [t for t in toks[1:] if t.startswith(b"-")]
    if not any(b"f" in f for f in flags):
        return None               # sink mode (-t) or something else
    recursive = any(b"r" in f for f in flags)
    paths = [t for t in toks[1:] if not t.startswith(b"-")]
    if not paths:
        return None
    path = paths[-1]
    glob = any(c in path for c in (b"*", b"?", b"["))
    return path, glob, recursive


class RshEngine:
    """rsh / rexec observer, plus the rcp record stream carried over rsh.

    Independent of the Telnet and rlogin parsers; shares only the emitter and
    the flow-key shape.
    """

    def __init__(self, emitter: Emitter, trust_data_threshold: int = 16):
        self.em = emitter
        self.flows: Dict[Tuple, RshFlow] = {}
        self.trust_data_threshold = trust_data_threshold
        # Advertised stderr ports awaiting a back-connect, keyed exactly as the
        # preflight settled: (family, canonical client address, port). A
        # port-only key collides -- rsh draws from the same small privileged
        # range, so two clients routinely advertise the same number.
        self.pending_stderr: Dict[Tuple[str, str, int], Tuple] = {}

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _famkey(addr: str, port: int) -> Tuple[str, str, int]:
        fam = "ipv6" if ":" in str(addr) else "ipv4"
        try:
            import ipaddress
            canon = ipaddress.ip_address(addr).compressed
        except Exception:
            canon = str(addr)
        return (fam, canon, port)

    def _flow(self, key: Tuple, is_rexec: bool) -> RshFlow:
        f = self.flows.get(key)
        if f is None:
            if len(self.flows) >= _MAX_FLOWS:
                self.flows.pop(next(iter(self.flows)))
            f = RshFlow(key=key, is_rexec=is_rexec)
            self.flows[key] = f
        return f

    # -- entry points -----------------------------------------------------
    def on_payload(self, key: Tuple, from_server: bool, payload: bytes,
                   now: Optional[float] = None, is_rexec: bool = False):
        f = self._flow(key, is_rexec)
        if not f.session_noted:
            # Source-port checks are flow-level and fire immediately. The
            # SESSION finding is deliberately NOT emitted here: it is worth
            # more once the handshake has been parsed, and emitting in both
            # places produced a duplicate that only the 60s dedup window
            # happened to hide in production.
            f.session_noted = True
            self._check_source_port(f, now)
        if from_server:
            self._on_server(f, payload, now)
        else:
            self._on_client(f, payload, now)

    def on_backconnect(self, client_addr: str, port: int,
                       now: Optional[float] = None) -> bool:
        """A reverse-direction flow arrived at an advertised stderr port.
        Returns True if it correlated to a known session."""
        k = self._famkey(client_addr, port)
        sess = self.pending_stderr.get(k)
        if sess is None:
            return False
        f = self.flows.get(sess)
        if f is not None:
            f.backconnect_seen = True
        return True

    # -- source-port trust checks -----------------------------------------
    def _check_source_port(self, f: RshFlow, now: Optional[float]):
        if f.srcport_noted:
            return
        f.srcport_noted = True
        sport = f.key[1]
        if sport == FTP_DATA_PORT:
            self.em.emit("RSVC-FTPDATA-SRCPORT", f.key,
                         {"src_port": sport, "dst_port": f.key[3],
                          "dedup": "ftpdata"}, "high", now)
        elif sport > PRIV_PORT_MAX:
            self.em.emit("RSVC-UNPRIV-SRCPORT", f.key,
                         {"src_port": sport, "priv_max": PRIV_PORT_MAX,
                          "dst_port": f.key[3], "dedup": "unpriv"}, "high", now)

    # -- client side -------------------------------------------------------
    def _on_client(self, f: RshFlow, payload: bytes, now: Optional[float]):
        if f.handshake_done:
            return                      # command output / keystrokes: not read
        if len(f.hs_buf) < _RL_MAX_HANDSHAKE:
            f.hs_buf.extend(payload[:_RL_MAX_HANDSHAKE - len(f.hs_buf)])
        fields = parse_rsh_handshake(bytes(f.hs_buf))
        if fields is None:
            return
        f.handshake_done = True
        port_s, user_a, user_b, command = fields

        try:
            f.stderr_port = int(port_s or b"0")
        except ValueError:
            f.stderr_port = 0
        if f.stderr_port:
            self.pending_stderr[self._famkey(f.key[0], f.stderr_port)] = f.key

        if f.is_rexec:
            # field 2 is the PASSWORD. Length only, never the value.
            self.em.emit("RSVC-REXEC-CLEARTEXT-CRED", f.key,
                         {"username_len": len(user_a),
                          "password_len": len(user_b),
                          "stderr_port": f.stderr_port,
                          "note": "credential value is never inspected or "
                                  "logged",
                          "dedup": "rexeccred"}, "high", now)

        # argument injection reuses the rlogin shape: a user field starting '-'
        for label, value in (("local_user", user_a), ("remote_user", user_b)):
            if (not f.is_rexec) and value[:1] == b"-":
                self.em.emit("RSVC-RLOGIN-ARGINJECT", f.key,
                             {"field": label, "value_len": len(value),
                              "value_prefix": value[:2].decode("latin-1",
                                                               "replace"),
                              "bypass_flag": value[:2] == b"-f",
                              "protocol": "rsh", "dedup": label}, "high", now)

        # record ONLY the command's first token plus its length: the full
        # command line routinely carries paths and secrets.
        first = command.split()[0] if command.split() else b""
        if not f.is_rexec and not f.session_emitted:
            f.session_emitted = True
            self.em.emit("RSVC-RSH-SESSION", f.key,
                         {"cmd_first_token": first.decode("latin-1", "replace"),
                          "cmd_len": len(command),
                          "stderr_port": f.stderr_port,
                          "dedup": "session"}, "high", now)

        info = rcp_request_info(command)
        if info is not None:
            path, glob, recursive = info
            f.rcp = RcpState(requested=path, glob=glob, recursive=recursive)

    # -- server side -------------------------------------------------------
    def _on_server(self, f: RshFlow, payload: bytes, now: Optional[float]):
        # Mid-session tap: we joined after the handshake, so it will never
        # parse. Still report the session, with nothing claimed about it.
        if (not f.is_rexec) and not f.session_emitted and not f.handshake_done:
            f.session_emitted = True
            self.em.emit("RSVC-RSH-SESSION", f.key,
                         {"note": "handshake not observed (mid-session tap)",
                          "dedup": "session"}, "high", now)
        low = payload.lower()
        if b"password" in low or b"passwd" in low:
            f.password_prompted = True
        if f.rcp is not None:
            self._on_rcp(f, payload, now)
            return
        f.server_bytes += len(payload.lstrip(b"\x00"))
        if (f.handshake_done and not f.password_prompted and not f.trust_noted
                and f.server_bytes >= self.trust_data_threshold):
            f.trust_noted = True
            self.em.emit("RSVC-TRUST-AUTH", f.key,
                         {"server_bytes": f.server_bytes,
                          "protocol": "rexec" if f.is_rexec else "rsh",
                          "dedup": "trust"}, "high", now)

    # -- rcp record stream -------------------------------------------------
    def _on_rcp(self, f: RshFlow, payload: bytes, now: Optional[float]):
        """Walk the server's rcp records.

        File PAYLOAD is skipped by its declared size. That is load-bearing: a
        transferred file whose CONTENT contains a line like `C0644 0 evil` would
        otherwise be parsed as a record and fabricate findings from data.
        """
        st = f.rcp
        data = payload
        while data:
            if st.skip:
                n = min(st.skip, len(data))
                st.skip -= n
                data = data[n:]
                continue
            # rcp separates records with a bare 0x00 ACK byte, which is NOT
            # newline-terminated. Glueing it onto the next record makes that
            # record's tag 0x00 instead of C/D, so EVERY record is silently
            # dropped -- a failure that reads as a clean transfer rather than
            # as a parse error, and which made an earlier "legit transfer is
            # quiet" check pass vacuously.
            if not st.buf and data[:1] == RCP_ACK:
                data = data[1:]
                continue
            nl = data.find(NEWLINE)
            if nl < 0:
                if len(st.buf) < _RCP_MAX_LINE:
                    st.buf.extend(data[:_RCP_MAX_LINE - len(st.buf)])
                return
            line = (bytes(st.buf) + data[:nl]).lstrip(RCP_ACK)
            st.buf = bytearray()
            data = data[nl + 1:]
            if st.records >= _RCP_MAX_RECORDS:
                return
            st.records += 1
            self._rcp_record(f, st, line, now)

    def _rcp_record(self, f: RshFlow, st: RcpState, line: bytes,
                    now: Optional[float]):
        if not line:
            return
        tag = line[:1]
        if tag not in (b"C", b"D"):
            return                       # T times, E end, \0 ack, \x01 warning
        parts = line[1:].split(b" ", 2)
        if len(parts) < 3:
            return
        _mode, size_s, name = parts
        try:
            size = int(size_s)
        except ValueError:
            size = 0
        if tag == b"C":
            st.files_seen += 1
            st.skip = max(0, size)       # skip the file body, never parse it

        detail_base = {"name_len": len(name),
                       "requested": st.requested.decode("latin-1", "replace"),
                       "record": tag.decode()}

        # CVE-2019-7282: '.' or an empty name
        if name in (b".", b"", b".."):
            self.em.emit("RSVC-RCP-7282-DOTNAME", f.key,
                         {**detail_base,
                          "name": name.decode("latin-1", "replace"),
                          "dedup": "dotname"}, "high", now)

        # traversal: a separator or a .. component
        if b"/" in name or b".." in name.split(b"/"):
            self.em.emit("RSVC-RCP-7283-TRAVERSAL", f.key,
                         {**detail_base,
                          "name_prefix": name[:24].decode("latin-1", "replace"),
                          "dedup": "traversal"}, "high", now)

        # CVE-2019-7283: the server sent something that was not asked for.
        # A globbed request legitimately returns many differently-named files,
        # so it is reported at reduced confidence rather than suppressed.
        want = st.requested.rsplit(b"/", 1)[-1]
        unrequested = False
        reason = ""
        if tag == b"D" and not st.recursive:
            unrequested, reason = True, "directory record without -r"
        elif not st.glob:
            if name != want:
                unrequested, reason = True, "name does not match the request"
            elif st.files_seen > 1:
                unrequested, reason = True, "more files than requested"
        elif st.files_seen > 1 and tag == b"C":
            pass                        # glob: multiple files are expected
        if unrequested:
            self.em.emit("RSVC-RCP-7283-UNREQUESTED", f.key,
                         {**detail_base, "reason": reason,
                          "files_seen": st.files_seen,
                          "glob_request": st.glob,
                          "name_prefix": name[:24].decode("latin-1", "replace"),
                          "dedup": "unrequested"},
                         "heuristic" if st.glob else "high", now)


# ---------------------------------------------------------------------------
# Raw-TCP serial console (no protocol framing) -- heuristic posture only
# ---------------------------------------------------------------------------
# A raw console server just pipes bytes between a TCP socket and a UART. There
# is NOTHING to parse: no option negotiation, no handshake, no version string.
# So this can only ever be inference, and it is capped at notice/low.
#
# The failure mode to avoid is obvious: 2001-2099, 3001-3099 and 7001-7099 also
# carry Java RMI, app servers, media streams and plenty else. Port alone is
# therefore NEVER sufficient -- a session must also LOOK like a terminal, and
# must not be a protocol we already recognise.

@dataclass
class ConsoleFlow:
    key: Tuple
    noted: bool = False
    signals: Set[str] = field(default_factory=set)
    server_bytes: int = 0
    disqualified: bool = False


def console_signals(data: bytes) -> Set[str]:
    """Terminal-shaped evidence in a server->client byte run.

    Each signal is something a serial console emits and a binary protocol does
    not. Requiring several independent ones is what keeps the port ranges from
    turning into a false-positive generator.
    """
    sig: Set[str] = set()
    if not data:
        return sig
    if b"\x1b[" in data:
        sig.add("ansi-csi")                       # ANSI cursor/colour control
    if b"\r\n" in data:
        sig.add("crlf")                           # UART line discipline
    low = data.lower()
    for pat, name in ((b"login:", "login-prompt"),
                      (b"username:", "login-prompt"),
                      (b"password", "password-prompt"),
                      (b"press return to get started", "vendor-banner"),
                      (b"press enter to activate", "vendor-banner"),
                      (b"rommon", "vendor-banner"),
                      (b"loader>", "vendor-banner"),
                      (b"u-boot", "vendor-banner"),
                      (b"would you like to enter the initial configuration",
                       "vendor-banner")):
        if pat in low:
            sig.add(name)
    # a bare shell/enable prompt at the end of a run
    tail = data.rstrip()[-2:]
    if tail[-1:] in (b"#", b"$", b">", b"%") and b"\n" in data:
        sig.add("shell-prompt")
    # printable-heavy content: a UART stream is text, a binary protocol is not
    if len(data) >= 16:
        printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
        if printable / len(data) >= 0.9:
            sig.add("printable")
    return sig


class ConsoleEngine:
    """Raw-TCP console posture. Shares the emitter and flow-key shape; keeps
    its own state and never touches the Telnet or rlogin parsers."""

    def __init__(self, emitter: Emitter, min_signals: int = _CONSOLE_MIN_SIGNALS):
        self.em = emitter
        self.flows: Dict[Tuple, ConsoleFlow] = {}
        self.min_signals = min_signals

    def _flow(self, key: Tuple) -> ConsoleFlow:
        f = self.flows.get(key)
        if f is None:
            if len(self.flows) >= _MAX_FLOWS:
                self.flows.pop(next(iter(self.flows)))
            f = ConsoleFlow(key=key)
            self.flows[key] = f
        return f

    def on_payload(self, key: Tuple, from_server: bool, payload: bytes,
                   now: Optional[float] = None):
        f = self._flow(key)
        if f.noted or f.disqualified:
            return
        # If this is actually Telnet or rlogin wearing an odd port, the
        # dedicated parsers own it -- do not also call it a raw console.
        if payload[:1] == bytes([IAC]) or payload[:2] == bytes([IAC, IAC]):
            f.disqualified = True
            return
        if not from_server:
            return                      # client keystrokes are never inspected
        f.server_bytes += len(payload)
        f.signals |= console_signals(payload)
        if len(f.signals) >= self.min_signals:
            f.noted = True
            self.em.emit("CONSOLE-RAW-TCP-SUSPECTED", f.key,
                         {"signals": sorted(f.signals),
                          "signal_count": len(f.signals),
                          "server_bytes": f.server_bytes,
                          "note": "heuristic: no protocol framing exists on a "
                                  "raw console; port alone is not sufficient",
                          "dedup": "console"}, "low", now)


# ---------------------------------------------------------------------------
# Live capture (the ONE scapy-importing path; never executed offline)
# ---------------------------------------------------------------------------
def _build_bpf(server_ports, tls_ports, rservices_ports=(),
                console_ports=()) -> str:
    """Dual-stack capture filter.

    IPv4 keeps precise `port N` terms -- IPv4 options are skippable via the IHL
    field, so that primitive has no blind spot.

    IPv6 is admitted BROADLY with a bare `ip6`, because libpcap's `port N`
    primitive assumes a fixed-offset path to the L4 header and cannot walk an
    IPv6 extension-header chain. MEASURED in this repo against real libpcap
    (see the conformance tier's bpf_matrix check):

        filter                                   plain HBH Rtg Frag Dest IPv4
        tcp and (port 23)                          1    0   0    0    0    1
        (tcp port 23) or (ip6 and tcp port 23)     1    0   0    0    0    1
        (tcp port 23) or ip6                       1    1   1    1    1    1
        ip6                                        1    1   1    1    1    0

    Note the second row: adding an `(ip6 and tcp port N)` clause is a MEASURED
    NO-OP -- it still relies on the same `port` primitive that cannot chase the
    chain, so it captures 0/4 extension-header types. Only a bare `ip6` works.

    The cost is that ALL IPv6 traffic reaches Python; run_capture's handler
    re-applies the real port gate in software. Telnet is a low-volume
    management-plane protocol, so that over-admission is cheap here.
    """
    ports = list(server_ports) + list(tls_ports) + list(rservices_ports) \
            + list(console_ports)
    terms = " or ".join(f"port {p}" for p in ports)
    if rservices_ports:
        # rsh's stderr channel lands on a port in no configured set. Both ends
        # of that back-connect are privileged, so admitting the range is what
        # makes the correlation capturable at all. MEASURED: `tcp port 514`
        # alone sees 0 of it; adding portrange 512-1023 sees it on both
        # families while still excluding ordinary ephemeral traffic.
        lo, hi = PRIV_PORTRANGE
        terms += f" or portrange {lo}-{hi}"
    ipv4 = f"tcp and ({terms})"
    return f"({ipv4}) or ip6"


def run_capture(iface: str, engine: Engine, server_ports, tls_ports,
                timeout: Optional[int] = None,
                offline: Optional[str] = None,
                rservices_ports=(),
                rlogin_engine: "Optional[RloginEngine]" = None,
                console_ports=(),
                console_engine: "Optional[ConsoleEngine]" = None,
                rsh_engine: "Optional[RshEngine]" = None):  # pragma: no cover
    """Passive capture. With `offline`, read frames from a pcap instead of a
    live interface -- scapy still compiles and applies the SAME BPF through
    real libpcap, so offline replay is a genuine test of the capture path
    (measured: a filter that drops IPv6 extension headers drops them offline
    too). Used by the dual-stack replay tier on hosts without an IPv6 stack."""
    from scapy.all import sniff, TCP, IP, IPv6, Raw  # lazy import

    server_set = set(server_ports)
    tls_set = set(tls_ports)
    rsvc_set = set(rservices_ports)
    console_set = set(console_ports)

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
        # r-services first: a separate protocol on its own ports, dispatched
        # by port and handed to its own parser. rlogin has no IAC framing, so
        # feeding it to the Telnet state machine would be actively wrong.
        # rsh / rexec, and the stderr back-connect they spawn
        if rsh_engine is not None and (dport in (RSH_PORT, REXEC_PORT)
                                       or sport in (RSH_PORT, REXEC_PORT)):
            if dport in (RSH_PORT, REXEC_PORT):
                r_from_server, r_key = False, (src, sport, dst, dport)
                is_rexec = dport == REXEC_PORT
            else:
                r_from_server, r_key = True, (dst, dport, src, sport)
                is_rexec = sport == REXEC_PORT
            if payload:
                rsh_engine.on_payload(r_key, r_from_server, payload,
                                      is_rexec=is_rexec)
            return
        if rsh_engine is not None and PRIV_PORTRANGE[0] <= dport <= PRIV_PORTRANGE[1]:
            # possible stderr back-connect: server -> client's advertised port
            if rsh_engine.on_backconnect(dst, dport):
                return
        if rlogin_engine is not None and (dport in rsvc_set or sport in rsvc_set):
            if dport in rsvc_set:
                rl_from_server, rl_key = False, (src, sport, dst, dport)
            else:
                rl_from_server, rl_key = True, (dst, dport, src, sport)
            if payload:
                rlogin_engine.on_payload(rl_key, rl_from_server, payload)
            return
        if console_engine is not None and (dport in console_set
                                           or sport in console_set):
            if dport in console_set:
                c_from_server, c_key = False, (src, sport, dst, dport)
            else:
                c_from_server, c_key = True, (dst, dport, src, sport)
            if payload:
                console_engine.on_payload(c_key, c_from_server, payload)
            return
        if dport in server_set:
            from_server = False
            key = (src, sport, dst, dport)
        elif sport in server_set:
            from_server = True
            key = (dst, dport, src, sport)
        else:
            # LOAD-BEARING under the dual-stack BPF: the filter admits ALL IPv6
            # traffic (it must -- see _build_bpf), so this software gate is the
            # only thing rejecting non-telnet IPv6. Removing it would flood the
            # engine with every IPv6 packet on the tap.
            return
        if payload:
            engine.on_payload(key, from_server, payload)

    bpf = _build_bpf(server_ports, tls_ports, rservices_ports,
                     console_ports)
    if offline:
        sniff(offline=offline, filter=bpf, prn=handle, store=False)
    else:
        sniff(iface=iface, filter=bpf, prn=handle, store=False, timeout=timeout)


# ---------------------------------------------------------------------------
# In-app adapter. Ragnar wires telnetwatch into the Network Tools UI the same way
# it wires tls_watch / ssh_watch: a bounded tcpdump capture into a temp pcap,
# replayed through run_capture(offline=...) — the SAME dispatcher, engines and BPF
# the live path uses (Telnet, rlogin, rsh/rexec + the stderr back-connect), so
# the in-app path can never drift from upstream detection. No detection logic
# lives here. (The passive-invariant AST guard in the self-test bans packet
# transmit primitives; tcpdump via subprocess is capture, not transmit.)
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


def _capture_pcap(interface, seconds, server_ports, tls_ports, rservices_ports):
    """Run tcpdump for `seconds` into a temp pcap and return its path. Passive: -w
    only, no probes. Uses the module's own dual-stack BPF (bare `ip6` for extension-
    header chains, plus the privileged portrange the rsh stderr back-connect lands
    on). Returns None if tcpdump is unavailable."""
    import shutil
    import subprocess
    import tempfile
    if not shutil.which("tcpdump"):
        return None
    bpf = _build_bpf(server_ports, tls_ports, rservices_ports)
    fd, path = tempfile.mkstemp(suffix=".pcap", prefix="telnetwatch_")
    os.close(fd)
    try:
        subprocess.run(["tcpdump", "-i", interface, "-w", path, "-s", "0", "-U",
                        "-q", "-c", "20000", bpf], timeout=seconds, capture_output=True)
    except subprocess.TimeoutExpired:
        pass                                       # expected: we run for the window
    except Exception:
        return None
    return path


def _telnet_verdict(findings):
    """compromised: a critical ATTACK-class finding (the payload is the evidence —
    argument injection, SLC/key-id overflow, rlogin -f injection, ftp-data bounce)
    or a server proven vulnerable; suspicious: any critical/high/warning finding
    (cleartext credentials, trust auth, recon/flood probes); else clean."""
    if any((f["severity"] == "critical" and f["class"] == "attack")
           or f["code"] == "TELNET-32746-VULN-CONFIRMED" for f in findings):
        return "compromised"
    if any(f["severity"] in ("critical", "high", "warning") for f in findings):
        return "suspicious"
    return "clean"


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def _telnet_summarize(records, interface, seconds):
    """Group emitted records per flow and roll up one verdict."""
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
            "cves": sorted(set(_CVE_RE.findall(r.get("desc") or ""))),
            "detail": r.get("detail", {})})
    rows = [flows[k] for k in order]
    all_f = [f for row in rows for f in row["findings"]]
    return {"success": True, "verdict": _telnet_verdict(all_f), "sessions": rows,
            "count": len(rows), "findings_total": len(all_f),
            "interface": interface, "seconds": seconds}


# --- Watchtower feed: append findings as JSON-lines so the unified alert pane tails them ---
_WT_LOG_DIR = os.environ.get("RAGNAR_WATCH_LOG_DIR", "/var/log/ragnar")
_WT_DEDUP_S = 300.0                    # don't re-log the same standing finding within 5 min
_WT_EMIT_SEV = frozenset(("critical", "high"))   # posture/recon stay off the alert pane
_wt_lock = threading.Lock()
_wt_seen = {}                         # (code, server) -> last-emitted epoch


def _emit_watchtower(result):
    """Append each HIGH/CRITICAL Telnet / r-services finding to
    <log-dir>/telnet_watch.jsonl in the shape Watchtower.normalize() reads, so the
    unified alert pane and its single Pushover path fold them in. Time-window
    deduplicated per (code, server). Best-effort: the scan never fails because
    logging did."""
    if not result.get("success"):
        return
    verdict = result.get("verdict", "clean")
    iface = result.get("interface")
    now = time.time()
    iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = []
    with _wt_lock:
        for row in result.get("sessions", []):
            server, client = row.get("server"), row.get("client")
            for f in row.get("findings", []):
                sev = f.get("severity")
                if sev not in _WT_EMIT_SEV:
                    continue
                code = f.get("code")
                key = (code, server)
                last = _wt_seen.get(key)
                if last is not None and now - last < _WT_DEDUP_S:
                    continue
                _wt_seen[key] = now
                lines.append(json.dumps({
                    "module": "telnet_watch", "ts": now, "iso": iso, "iface": iface,
                    "severity": sev, "code": code, "codes": [code],
                    "class": f.get("class"), "confidence": f.get("confidence"),
                    "src": server, "target": client, "cves": f.get("cves") or [],
                    "summary": f.get("desc"), "verdict": verdict}))
        if len(_wt_seen) > 4096:
            cutoff = now - _WT_DEDUP_S
            for k in [k for k, t in _wt_seen.items() if t < cutoff]:
                _wt_seen.pop(k, None)
    if not lines:
        return
    try:
        os.makedirs(_WT_LOG_DIR, exist_ok=True)
        with open(os.path.join(_WT_LOG_DIR, "telnet_watch.jsonl"), "a") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


def do_telnet_watch(interface=None, seconds=12, server_ports=DEFAULT_SERVER_PORTS,
                    rservices_ports=DEFAULT_RSERVICES_PORTS, quick=False):
    """Passive Telnet + r-services observation on `interface` for `seconds`. Both are
    cleartext end to end, so the whole session is readable from a tap. Telnet:
    CVE-2026-24061 (login -f argument injection), CVE-2026-32746 (LINEMODE SLC
    overflow), CVE-2011-4862 (encrypt key-id overflow), CVE-2022-39028 (EC/EL
    pre-auth crash). r-services: rlogin -froot injection (CVE-1999-0113), rsh
    ftp-data trust bounce (CVE-1999-0185), rcp dot-name / unrequested / traversal
    (CVE-2019-7282 / CVE-2019-7283), rexec cleartext credentials and .rhosts trust.
    Never transmits. Requires tcpdump; scapy for pcap dissection."""
    seconds = max(4, min(int(seconds or 12), 60))
    if not interface:
        return {"success": False, "error": "no interface specified"}
    try:
        import scapy  # noqa: F401
    except Exception:
        return {"success": False, "missing_tool": "scapy",
                "error": 'the Python "scapy" package is required for pcap dissection'}
    ports = tuple(int(p) for p in server_ports)
    tls = tuple(DEFAULT_TLS_PORTS)
    rsvc = tuple(int(p) for p in (rservices_ports or ()))
    pcap = _capture_pcap(interface, seconds, ports, tls, rsvc)
    if not pcap:
        return {"success": False, "missing_tool": "tcpdump",
                "error": "tcpdump is required for capture"}
    em = _CollectEmitter(min_sev="info", dedup_secs=60.0)
    eng = Engine(em)
    try:
        run_capture(None, eng, ports, tls, offline=pcap,
                    rservices_ports=rsvc,
                    rlogin_engine=RloginEngine(em) if rsvc else None,
                    rsh_engine=RshEngine(em) if rsvc else None)
    except Exception as e:
        return {"success": False, "error": "pcap parse failed: {}".format(e)}
    finally:
        try:
            os.unlink(pcap)
        except OSError:
            pass
    result = _telnet_summarize(em.records, interface, seconds)
    if not quick:
        _emit_watchtower(result)
    return result


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
    p.add_argument("--console-ports", default="",
                   help="raw-TCP console-server ports (e.g. 2001-2099); "
                        "empty disables. Heuristic posture only")
    p.add_argument("--rservices-ports",
                   default=",".join(map(str, DEFAULT_RSERVICES_PORTS)),
                   help="r-services ports (rlogin); empty string disables")
    p.add_argument("--min-severity", default="info",
                   choices=list(_SEV_RANK.keys()))
    p.add_argument("--timeout", type=int, default=None,
                   help="stop after N seconds (capture)")
    p.add_argument("--dedup-secs", type=float, default=60.0)
    p.add_argument("--pushover-token", default=os.environ.get("PUSHOVER_TOKEN"))
    p.add_argument("--pushover-user", default=os.environ.get("PUSHOVER_USER"))
    p.add_argument("--offline", default=None,
                   help="replay a pcap instead of live capture (same BPF)")
    p.add_argument("--print-codes", action="store_true",
                   help="print the finding catalog and exit")
    p.add_argument("--selftest", action="store_true",
                   help="run the built-in self-test and exit")
    return p


def _port_ranges(s: str) -> Tuple[int, ...]:
    """Parse a comma list that may contain `a-b` ranges (console port blocks
    are naturally ranges, unlike the single service ports elsewhere)."""
    out: List[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                continue
            if lo <= hi and hi - lo <= 4096:
                out.extend(range(lo, hi + 1))
        else:
            try:
                out.append(int(part))
            except ValueError:
                continue
    return tuple(out)


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
    if not args.iface and not args.offline:
        print("error: --iface or --offline required (or use --selftest / "
              "--print-codes)", file=sys.stderr)
        return 2
    rsvc = _ports(args.rservices_ports)
    rl_eng = RloginEngine(em) if rsvc else None
    rsh_eng = RshEngine(em) if rsvc else None
    cons = _port_ranges(args.console_ports)
    cons_eng = ConsoleEngine(em) if cons else None
    run_capture(args.iface, eng, _ports(args.server_ports),
                _ports(args.tls_ports), timeout=args.timeout,
                offline=args.offline, rservices_ports=rsvc,
                rlogin_engine=rl_eng, console_ports=cons,
                console_engine=cons_eng, rsh_engine=rsh_eng)
    return 0


if __name__ == "__main__":
    sys.exit(main())
