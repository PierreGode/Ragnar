#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
sshwatch — passive SSH observer (Ragnar suite), built around CVE-2024-6387 (regreSSHion).

Design contract, shared with the rest of Ragnar:
  * Sniff-only. Scapy is a capture front-end; zero TX, inject, probe or connect. sshwatch
    NEVER initiates an SSH connection — everything here is read off traffic that was
    already flowing. This matters more than usual for SSH, because almost every published
    "detection" for CVE-2024-6387 is a banner GRAB, which means connecting, which is
    active. The suite already corrected exactly this mistake once, for CVE-2015-5434.
  * Security-critical parsing is hand-rolled from raw bytes: the identification string,
    the SSH binary packet framing, and the KEXINIT name-lists.
  * JSON-lines out, systemd unit with least privilege, self-test harness pinned to bytes
    captured from a real OpenSSH server rather than hand-built fixtures.
  * Pi Zero 2W is the floor. No crypto is performed; sshwatch reads only the cleartext
    prologue of a connection, which is everything before the first KEXDH packet.

WHAT IS AND IS NOT VISIBLE
  The SSH identification string and both KEXINIT messages are sent in cleartext, before
  any key exchange. Everything after that is encrypted. So sshwatch can see software
  versions, every offered algorithm, and the negotiation outcome — and can see nothing at
  all about authentication, usernames, or session content. That boundary is what makes
  the CVE-2024-6387 story below work the way it does.

THE HONEST POSITION ON CVE-2024-6387
  regreSSHion is a signal-handler race in sshd's LoginGraceTime handling. The vulnerable
  versions are OpenSSH 8.5p1 through 9.7p1, plus anything before 4.4p1 that never received
  the CVE-2006-5051 fix. Fixed in 9.8/9.8p1.

  A banner version in that range is NOT evidence that a host is vulnerable, and sshwatch
  refuses to report it as though it were. Every major distribution backports security
  fixes without changing the upstream version in the identification string. The machine
  this module was developed on runs `OpenSSH_9.6p1 Ubuntu-3ubuntu13.18` — inside the
  affected range, and patched against regreSSHion since 3ubuntu13.4. Its banner is
  indistinguishable from a genuinely vulnerable 9.6p1.

  Nor does the ABSENCE of a distribution suffix mean upstream: Red Hat ships `OpenSSH_8.7`
  with no comment field at all and backports fixes into it.

  So the version finding is capped at `notice`, says plainly that it cannot establish
  patch state, and names the distribution when it can see one. The finding that carries
  real weight is the behavioural one: regreSSHion needs thousands of connections that are
  each held open until LoginGraceTime expires without authenticating, and that pattern IS
  visible from the outside.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone

SCHEMA_VERSION = 1
MODULE = "sshwatch"

SEVERITY_ORDER = {"info": 0, "notice": 1, "warn": 2, "high": 3}

# ---------------------------------------------------------------------------
# CVE catalog. `detect` follows the ciscoguard/tlswatch convention — an honest
# statement of what a passive tap can actually establish, not what we wish it could.
# ---------------------------------------------------------------------------
CVE_CATALOG = {
    "CVE-2024-6387": {
        "title": "regreSSHion: signal-handler race in OpenSSH sshd leading to "
                 "unauthenticated RCE as root",
        "cvss": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_source": "NVD (NIST); Red Hat and Ubuntu record the same vector",
        "severity_word": "HIGH",
        "score_confidence": "agreed",
        "score_note": (
            "8.1 is HIGH, not Critical — Critical begins at 9.0, and secondary trackers "
            "that call this Critical are wrong. Note AC:H: the attack is a race needing "
            "roughly ten thousand attempts over hours, and Unit 42 reported being unable "
            "to make the public proof-of-concept work at all."
        ),
        "affected": "OpenSSH 8.5p1 through 9.7p1; also before 4.4p1 unless backport-patched "
                    "for CVE-2006-5051 / CVE-2008-4109. Fixed in 9.8/9.8p1.",
        "platform": "glibc-based Linux (sshd server side)",
        "detect": "posture-only-by-version, behaviour-for-attack",
        "detect_note": (
            "The identification string is cleartext and passively readable, but it cannot "
            "establish patch state because distributions backport without bumping it. "
            "Version matching is therefore a NOTICE that a host is worth checking, never "
            "an assertion of vulnerability. The attack itself has a distinct passive "
            "shape — repeated connections held to the LoginGraceTime expiry without "
            "authenticating — and that is where the confidence lives."
        ),
        "cwe": "CWE-364",
        "refs": ("https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt",
                 "https://nvd.nist.gov/vuln/detail/CVE-2024-6387"),
    },
    "CVE-2023-48795": {
        "title": "Terrapin: SSH transport prefix truncation via handshake packet deletion",
        "cvss": 5.9,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "cvss_source": "NVD (NIST)",
        "score_confidence": "agreed",
        "score_note": "Requires an active machine-in-the-middle on the TCP path.",
        "affected": "Any SSH implementation negotiating ChaCha20-Poly1305 or a CBC cipher "
                    "with an Encrypt-then-MAC MAC, where strict key exchange is not in use.",
        "detect": "exposure",
        "detect_note": (
            "Unusually clean for a passive tap: both KEXINIT messages are cleartext, the "
            "strict-KEX extension either appears in them or does not, and the negotiated "
            "cipher and MAC follow deterministically from RFC 4253 name-list rules. The "
            "vulnerable condition is therefore READ, not inferred."
        ),
        "cwe": "CWE-354",
        "refs": ("https://terrapin-attack.com/",
                 "https://nvd.nist.gov/vuln/detail/CVE-2023-48795"),
    },
}

# ---------------------------------------------------------------------------
# CVE-2024-6387 affected-version model.
# Versions are compared as (major, minor, portable) with portable None meaning a
# non-portable OpenBSD release, which sorts before pN of the same major.minor.
# ---------------------------------------------------------------------------
REGRESSHION_LOW = (8, 5, 1)      # 8.5p1, first affected in the modern range
REGRESSHION_HIGH = (9, 7, 1)     # 9.7p1, last affected; 9.8p1 is fixed
REGRESSHION_ANCIENT = (4, 4, 1)  # before 4.4p1, unless backport-patched for CVE-2006-5051

# Distribution markers that appear in the comment field of the identification string.
# Presence PROVES distribution packaging. Absence proves nothing — Red Hat ships a bare
# "OpenSSH_8.7" and backports into it — which is why this only ever downgrades confidence
# and never upgrades it.
DISTRO_MARKERS = (
    "ubuntu", "debian", "raspbian", "freebsd", "openbsd", "netbsd", "sunssh",
    "amazon", "el7", "el8", "el9", "rhel", "centos", "fips", "suse", "alpine",
    "gentoo", "arch", "photon", "deb", "+deb", "mindrot",
)

# ---------------------------------------------------------------------------
# Terrapin (CVE-2023-48795) parameters.
# ---------------------------------------------------------------------------
STRICT_KEX_CLIENT = "kex-strict-c-v00@openssh.com"
STRICT_KEX_SERVER = "kex-strict-s-v00@openssh.com"
TERRAPIN_CIPHERS = ("chacha20-poly1305@openssh.com",)

# ---------------------------------------------------------------------------
# Legacy / weak algorithm posture. Curated, with the reason carried alongside so an
# operator never has to look up why a name is on a list.
# ---------------------------------------------------------------------------
# Each entry carries its own severity, because "weaker than current practice" and
# "actually broken" are different operational facts and must not share a severity.
#
# The distinction is load-bearing. umac-64-etm@openssh.com is a 64-bit authentication
# tag AND it is OpenSSH's default first preference, so scoring it `warn` would put a
# warning on essentially every SSH connection on a healthy network. A feed that warns
# about the default configuration of the commonest implementation is a feed operators
# learn to ignore, which costs more than the finding is worth. It is `notice`.
WEAK_KEX = {
    "diffie-hellman-group1-sha1": ("warn", "1024-bit MODP group with SHA-1 (Logjam-class)"),
    "gss-group1-sha1-": ("warn", "1024-bit MODP group with SHA-1"),
    "rsa1024-sha1": ("warn", "1024-bit RSA transport key with SHA-1"),
    "diffie-hellman-group-exchange-sha1": ("notice", "SHA-1 group exchange"),
    "diffie-hellman-group14-sha1": ("notice", "SHA-1 key derivation over a 2048-bit group"),
}
WEAK_HOSTKEY = {
    "ssh-dss": ("warn", "DSA, fixed 1024-bit, removed from OpenSSH defaults"),
    "ssh-rsa": ("warn", "RSA with SHA-1 signatures; disabled by default since OpenSSH 8.8"),
}
WEAK_CIPHER = {
    "none": ("high", "no confidentiality"),
    "des-cbc": ("high", "single DES, 56-bit key"),
    "arcfour": ("warn", "RC4"),
    "arcfour128": ("warn", "RC4"),
    "arcfour256": ("warn", "RC4"),
    "3des-cbc": ("warn", "64-bit block in CBC; the SWEET32 birthday bound applies"),
    "blowfish-cbc": ("warn", "64-bit block in CBC"),
    "cast128-cbc": ("warn", "64-bit block in CBC"),
    "rijndael-cbc@lysator.liu.se": ("notice", "superseded non-standard AES-CBC name"),
}
WEAK_MAC = {
    "none": ("high", "no integrity protection"),
    "hmac-md5": ("warn", "MD5"),
    "hmac-md5-etm@openssh.com": ("warn", "MD5"),
    "hmac-md5-96": ("warn", "MD5, truncated to 96 bits"),
    "hmac-md5-96-etm@openssh.com": ("warn", "MD5, truncated to 96 bits"),
    "hmac-sha1-96": ("notice", "SHA-1 truncated to 96 bits"),
    "hmac-sha1-96-etm@openssh.com": ("notice", "SHA-1 truncated to 96 bits"),
    "umac-64@openssh.com": ("notice", "64-bit authentication tag"),
    "umac-64-etm@openssh.com": ("notice", "64-bit authentication tag; OpenSSH's default "
                                          "first preference, so this is informational"),
}

# AEAD ciphers carry their own integrity, so when one is negotiated the MAC name-lists
# are IGNORED and there is no separate MAC algorithm at all. OpenSSH prints "MAC:
# <implicit>" in that case. Computing a negotiated MAC anyway — which this module did
# until the cross-check compared its answer against OpenSSH's own report — produces a MAC
# that is not in use, and then happily raises weak-MAC findings about it. Every modern
# OpenSSH connection defaults to chacha20-poly1305, so that false positive would have
# fired on essentially every session observed.
AEAD_CIPHERS = frozenset((
    "chacha20-poly1305@openssh.com",
    "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
    "AEAD_AES_128_GCM", "AEAD_AES_256_GCM",
))
IMPLICIT_MAC = "<implicit>"


def effective_mac(cipher, mac):
    """The MAC actually in use. None when the cipher is an AEAD."""
    if cipher in AEAD_CIPHERS:
        return None
    return mac


SSH_MSG_KEXINIT = 20
KEXINIT_LIST_NAMES = (
    "kex_algorithms", "server_host_key_algorithms",
    "encryption_algorithms_c2s", "encryption_algorithms_s2c",
    "mac_algorithms_c2s", "mac_algorithms_s2c",
    "compression_algorithms_c2s", "compression_algorithms_s2c",
    "languages_c2s", "languages_s2c",
)


# ---------------------------------------------------------------------------
# Bounds-checked reader. Same shape as tlswatch's: a malformed packet raises and is
# rejected per-flow rather than taking down the sniffer.
# ---------------------------------------------------------------------------
class Reader:
    __slots__ = ("d", "o")

    def __init__(self, data, off=0):
        self.d = data
        self.o = off

    def _need(self, n):
        if n < 0 or self.o + n > len(self.d):
            raise ValueError("short read")

    def u8(self):
        self._need(1)
        v = self.d[self.o]
        self.o += 1
        return v

    def u32(self):
        self._need(4)
        v = int.from_bytes(self.d[self.o:self.o + 4], "big")
        self.o += 4
        return v

    def take(self, n):
        self._need(n)
        v = self.d[self.o:self.o + n]
        self.o += n
        return bytes(v)

    def name_list(self):
        """RFC 4251 name-list: uint32 length then comma-separated US-ASCII."""
        n = self.u32()
        raw = self.take(n)
        if not raw:
            return []
        return raw.decode("ascii", "replace").split(",")

    def rem(self):
        return len(self.d) - self.o


# ---------------------------------------------------------------------------
# Identification string (RFC 4253 s4.2):
#     SSH-protoversion-softwareversion [SP comments] CR LF
# The comment field is where distributions put their packaging string.
# ---------------------------------------------------------------------------
# RFC 4253 s4.2 says softwareversion must not contain a space or a MINUS SIGN. Real
# implementations violate the minus rule routinely and it would be wrong to refuse to
# parse what is actually on the wire: Cisco IOS identifies as "SSH-2.0-Cisco-1.25" and
# several libssh builds as "SSH-2.0-libssh-0.7.0". Enforcing the RFC here silently
# discarded every Cisco SSH server — which, on a carrier network, is a lot of them.
# Any printable non-space run is accepted; the comment field still splits on the first
# space, which is the part that carries packaging information.
_IDENT_RE = re.compile(r"^SSH-(?P<proto>[0-9]+\.[0-9]+)-(?P<software>[!-~]+)"
                       r"(?: (?P<comments>[ -~]*))?$")
_OPENSSH_RE = re.compile(r"^OpenSSH_(?P<major>\d+)\.(?P<minor>\d+)"
                         r"(?:p(?P<portable>\d+))?")


def parse_ident(line):
    """Parse one identification string. Returns a dict, or None if it is not one.

    `line` is the bytes of a single line WITHOUT the trailing CR LF. RFC 4253 permits a
    server to send other lines before the identification string; the caller handles that
    by trying each line in turn.
    """
    try:
        s = line.decode("ascii")
    except UnicodeDecodeError:
        return None
    m = _IDENT_RE.match(s)
    if not m:
        return None
    proto = m.group("proto")
    software = m.group("software")
    comments = m.group("comments") or ""
    out = {
        "raw": s,
        "protocol": proto,
        "software": software,
        "comments": comments,
        "vendor": None,
        "version": None,
        "distro_packaged": False,
        "distro": None,
    }
    om = _OPENSSH_RE.match(software)
    if om:
        out["vendor"] = "OpenSSH"
        out["version"] = (int(om.group("major")), int(om.group("minor")),
                          int(om.group("portable")) if om.group("portable") else None)
    hay = (software + " " + comments).lower()
    for marker in DISTRO_MARKERS:
        if marker in hay:
            out["distro_packaged"] = True
            out["distro"] = comments.strip() or software
            break
    return out


def _cmp_version(v):
    """Sort key. A non-portable release (portable None) precedes pN of the same
    major.minor, which is the real release order."""
    return (v[0], v[1], -1 if v[2] is None else v[2])


def regresshion_affected(version):
    """Is this OpenSSH version inside the CVE-2024-6387 affected set?

    Returns (affected: bool, which: str). `which` distinguishes the modern range from the
    pre-4.4p1 tail, because the tail carries an extra caveat: those releases are only
    affected if they never received the CVE-2006-5051 fix, which most vendors backported
    two decades ago.

    MEMBERSHIP IS BY (major, minor), NOT BY p-LEVEL. "8.5" and "8.5p1" are the same
    upstream release — portable builds simply append the pN suffix — so there is no
    p-level of 8.5 that is fixed while another is vulnerable. Comparing with the p-level
    included made `OpenSSH_8.5` read as SAFE while `OpenSSH_8.5p1` read as affected, and
    inverted the same way at the other bound, where `4.4` read as affected and `4.4p1` did
    not. The fix landed in a release, so the release is the unit.
    """
    if version is None:
        return False, ""
    mm = (version[0], version[1])
    if (REGRESSHION_LOW[0], REGRESSHION_LOW[1]) <= mm <= (REGRESSHION_HIGH[0],
                                                          REGRESSHION_HIGH[1]):
        return True, "modern"
    if mm < (REGRESSHION_ANCIENT[0], REGRESSHION_ANCIENT[1]):
        return True, "ancient"
    return False, ""


def fmt_version(v):
    if v is None:
        return "unknown"
    return "%d.%d%s" % (v[0], v[1], "" if v[2] is None else "p%d" % v[2])


# ---------------------------------------------------------------------------
# SSH binary packet protocol (RFC 4253 s6), cleartext phase only:
#     uint32 packet_length; byte padding_length; byte[n1] payload; byte[n2] padding
# Before the first NEWKEYS there is no MAC and no encryption, which is exactly the window
# sshwatch reads. Anything after that is opaque and is only counted, never parsed.
# ---------------------------------------------------------------------------
MAX_SSH_PACKET = 35000  # RFC 4253 s6.1 requires support for at least 32768 payload bytes


SSH_MSG_NEWKEYS = 21


def parse_packets(buf, strict=True):
    """Frame as many complete cleartext binary packets as `buf` holds.

    Returns (packets, consumed, done) where `done` is True once SSH_MSG_NEWKEYS has been
    framed — everything after that point on this direction is encrypted and must not be
    parsed as packets.

    STOPPING AT NEWKEYS IS NOT OPTIONAL. A real connection continues straight into
    encrypted data in the same TCP segment, and encrypted bytes read as an SSH length
    field are arbitrary. An earlier version raised on those bytes and the caller discarded
    the whole batch — throwing away the KEXINIT it had already framed correctly. A
    banner-plus-KEXINIT fixture never reaches that code path; a real handshake does, which
    is why this module's fixtures are captured rather than built.

    With strict=True an implausible length still terminates framing, but whatever was
    framed before it is returned rather than lost.
    """
    out = []
    off = 0
    done = False
    while len(buf) - off >= 4:
        plen = int.from_bytes(buf[off:off + 4], "big")
        if plen < 5 or plen > MAX_SSH_PACKET:
            if strict and not out:
                raise ValueError("implausible packet_length %d" % plen)
            break
        if len(buf) - off < 4 + plen:
            break
        pad = buf[off + 4]
        if pad < 4 or pad > plen - 1:
            if strict and not out:
                raise ValueError("implausible padding_length %d" % pad)
            break
        payload = bytes(buf[off + 5:off + 4 + plen - pad])
        out.append(payload)
        off += 4 + plen
        if payload and payload[0] == SSH_MSG_NEWKEYS:
            done = True
            break
    return out, off, done


def parse_kexinit(payload):
    """Parse an SSH_MSG_KEXINIT payload into its ten name-lists plus trailing fields."""
    r = Reader(payload)
    mtype = r.u8()
    if mtype != SSH_MSG_KEXINIT:
        raise ValueError("not KEXINIT (msg type %d)" % mtype)
    cookie = r.take(16)
    out = {"cookie": cookie.hex()}
    for name in KEXINIT_LIST_NAMES:
        out[name] = r.name_list()
    out["first_kex_packet_follows"] = bool(r.u8())
    out["reserved"] = r.u32()
    return out


def negotiate(client_list, server_list):
    """RFC 4253 s7.1: the chosen algorithm is the first on the CLIENT's list that also
    appears on the SERVER's list. Returns None when there is no overlap."""
    srv = set(server_list)
    for name in client_list:
        if name in srv:
            return name
    return None


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
def _finding(sev, code, msg, **extra):
    d = {"severity": sev, "code": code, "message": msg}
    d.update(extra)
    return d


def evaluate_findings(sess, cfg=None):
    """Score one observed SSH session. `sess` carries whatever has been seen so far;
    every check tolerates the pieces it needs being absent."""
    cfg = cfg or {}
    findings = []
    server = sess.get("server_ident")
    client = sess.get("client_ident")
    ckex = sess.get("client_kexinit")
    skex = sess.get("server_kexinit")

    # ---- SSH-1.x ----
    for who, ident in (("server", server), ("client", client)):
        if ident and ident["protocol"].startswith("1."):
            # 1.99 means "2.0 available, 1.x also offered" — still an exposure.
            findings.append(_finding(
                "high", "ssh_protocol_1x",
                "%s offers SSH protocol %s; SSH-1 is structurally broken and must not be "
                "enabled" % (who, ident["protocol"]),
                side=who, protocol=ident["protocol"]))

    # ---- CVE-2024-6387, version posture (server side only; the flaw is in sshd) ----
    if server and server.get("vendor") == "OpenSSH":
        affected, which = regresshion_affected(server["version"])
        if affected:
            meta = CVE_CATALOG["CVE-2024-6387"]
            ver = fmt_version(server["version"])
            if which == "ancient":
                detail = ("%s predates 4.4p1, which is affected only if it never received "
                          "the CVE-2006-5051 fix — backported by most vendors long ago"
                          % ver)
            else:
                detail = "%s falls in the affected range 8.5p1-9.7p1" % ver
            if server["distro_packaged"]:
                caveat = ("this build is distribution-packaged (%s), and distributions "
                          "backport this fix WITHOUT changing the version string, so the "
                          "banner cannot tell you whether it is patched"
                          % (server["distro"] or "unknown packaging"))
            else:
                caveat = ("no packaging string is present, which does NOT imply an "
                          "upstream build — Red Hat and others ship a bare version and "
                          "backport into it, so the banner still cannot tell you whether "
                          "it is patched")
            findings.append(_finding(
                # Capped at notice on purpose. This is "worth checking", not "vulnerable".
                "notice", "cve_2024_6387_version_in_range",
                "sshd reports OpenSSH %s — %s; %s" % (ver, detail, caveat),
                cve="CVE-2024-6387", cvss=meta["cvss"], cvss_source=meta["cvss_source"],
                severity_word=meta["severity_word"],
                detect_class="posture", confidence="low",
                confidence_reason="version string cannot establish backport state",
                version=ver, distro_packaged=server["distro_packaged"],
                distro=server["distro"], range=which))

    # ---- CVE-2023-48795 Terrapin ----
    if ckex and skex:
        c_strict = STRICT_KEX_CLIENT in ckex["kex_algorithms"]
        s_strict = STRICT_KEX_SERVER in skex["kex_algorithms"]
        cipher = negotiate(ckex["encryption_algorithms_c2s"],
                           skex["encryption_algorithms_c2s"])
        mac = negotiate(ckex["mac_algorithms_c2s"], skex["mac_algorithms_c2s"])
        vulnerable_mode = None
        if cipher in TERRAPIN_CIPHERS:
            vulnerable_mode = "%s (ChaCha20-Poly1305)" % cipher
        elif cipher and cipher.endswith("-cbc") and mac and mac.endswith("-etm@openssh.com"):
            vulnerable_mode = "%s with %s (CBC plus Encrypt-then-MAC)" % (cipher, mac)
        if vulnerable_mode and not (c_strict and s_strict):
            missing = []
            if not c_strict:
                missing.append("client")
            if not s_strict:
                missing.append("server")
            meta = CVE_CATALOG["CVE-2023-48795"]
            findings.append(_finding(
                "warn", "cve_2023_48795_terrapin_exposed",
                "Negotiated %s without strict key exchange (not offered by: %s) — an "
                "on-path attacker can delete handshake packets undetected"
                % (vulnerable_mode, ", ".join(missing)),
                cve="CVE-2023-48795", cvss=meta["cvss"],
                cvss_source=meta["cvss_source"], detect_class="exposure",
                confidence="high",
                confidence_reason="the vulnerable condition is read directly from both "
                                  "cleartext KEXINIT messages",
                cipher=cipher, mac=mac, strict_kex_missing=missing))
        elif not (c_strict and s_strict):
            findings.append(_finding(
                "info", "ssh_strict_kex_absent",
                "Strict key exchange not offered by both sides; the negotiated mode "
                "(%s) is not Terrapin-vulnerable, so this is posture only"
                % (cipher or "unknown"),
                cipher=cipher, mac=mac))

    # ---- algorithm posture, from the negotiated choice where possible ----
    if ckex and skex:
        checks = (
            ("kex_algorithms", "kex_algorithms", WEAK_KEX, "ssh_weak_kex",
             "key exchange"),
            ("server_host_key_algorithms", "server_host_key_algorithms", WEAK_HOSTKEY,
             "ssh_weak_hostkey", "host key algorithm"),
            ("encryption_algorithms_c2s", "encryption_algorithms_c2s", WEAK_CIPHER,
             "ssh_weak_cipher", "cipher"),
            ("mac_algorithms_c2s", "mac_algorithms_c2s", WEAK_MAC, "ssh_weak_mac", "MAC"),
        )
        neg_cipher = negotiate(ckex["encryption_algorithms_c2s"],
                               skex["encryption_algorithms_c2s"])
        for cfield, sfield, table, code, label in checks:
            chosen = negotiate(ckex[cfield], skex[sfield])
            if code == "ssh_weak_mac" and neg_cipher in AEAD_CIPHERS:
                # No separate MAC is negotiated under an AEAD cipher; whatever the MAC
                # name-lists happen to agree on is never used.
                continue
            if chosen in table:
                sev, reason = table[chosen]
                findings.append(_finding(
                    sev, code,
                    "Negotiated %s %s: %s" % (label, chosen, reason),
                    algorithm=chosen, kind=label, detect_class="posture",
                    confidence="high",
                    confidence_reason="the negotiated algorithm follows deterministically "
                                      "from both cleartext KEXINIT messages"))

    # ---- CVE-2024-6387 behavioural signal ----
    burst = sess.get("grace_burst")
    if burst:
        meta = CVE_CATALOG["CVE-2024-6387"]
        n = burst["count"]
        sev = "high" if n >= burst["high_threshold"] else "warn"
        findings.append(_finding(
            sev, "cve_2024_6387_grace_timeout_pattern",
            "%d SSH connections from %s completed the cleartext handshake and were then "
            "held to the login-grace expiry (~%ds) without carrying a session, within "
            "%ds — the access pattern regreSSHion exploitation produces"
            % (n, burst["source"], burst["grace"], burst["window"]),
            cve="CVE-2024-6387", cvss=meta["cvss"], cvss_source=meta["cvss_source"],
            detect_class="attack", confidence="heuristic",
            confidence_reason="connection timing is observable but authentication is "
                              "encrypted, so a successful login cannot be ruled out "
                              "directly; benign causes include idle clients, scanners "
                              "and monitoring probes",
            source=burst["source"], count=n, window_seconds=burst["window"],
            grace_seconds=burst["grace"]))
    return findings


# ---------------------------------------------------------------------------
# Stream handling
# ---------------------------------------------------------------------------
def looks_like_ssh_start(payload):
    """True if `payload` plausibly begins an SSH stream.

    Three ways to qualify, in order of strength:
      * the segment starts with "SSH-";
      * the segment is shorter than the token and is a PREFIX of it, so a stream whose
        opening byte arrives alone still anchors (tlswatch learned this the hard way when
        requiring a full token silently broke one- and two-byte segmentation);
      * the segment contains "SSH-" at a LINE BOUNDARY, because RFC 4253 permits a server
        to send banner lines before its identification string and both usually arrive in
        the same write.

    Accepting any printable data instead — which an earlier draft of this did — is wrong:
    the tail of a reordered identification string is printable too, so the stream anchors
    mid-token and the real opening is discarded as old data. Requiring the token itself,
    at a line boundary, keeps the pre-banner case working without that.
    """
    if not payload:
        return False
    if payload.startswith(b"SSH-"):
        return True
    if len(payload) < 4 and b"SSH-".startswith(payload):
        return True
    head = payload[:512]
    return b"\nSSH-" in head or b"\rSSH-" in head


def _seq_gt(a, b):
    return a != b and ((a - b) & 0xFFFFFFFF) < 0x80000000


class DirReassembler:
    """In-order TCP payload reassembler for one direction, with the stream-anchor guard
    tlswatch grew after a real bug: anchoring on whatever segment arrives first silently
    discards everything earlier when that segment is not the lowest-sequence one."""

    def __init__(self, cap=131072, anchor=None):
        self.next = None
        self.hold = {}
        self.cap = cap
        self.anchor = anchor

    def _held(self):
        return sum(len(v) for v in self.hold.values())

    def add(self, seq, payload):
        if not payload:
            return b""
        if self.next is None:
            if self.anchor is not None and not self.anchor(payload):
                if self._held() < self.cap:
                    self.hold[seq] = payload
                return b""
            self.next = seq
        out = bytearray()
        if seq == self.next:
            out += payload
            self.next = (self.next + len(payload)) & 0xFFFFFFFF
            while self.next in self.hold:
                d = self.hold.pop(self.next)
                out += d
                self.next = (self.next + len(d)) & 0xFFFFFFFF
        elif _seq_gt(seq, self.next):
            if self._held() < self.cap:
                self.hold[seq] = payload
        else:
            end = (seq + len(payload)) & 0xFFFFFFFF
            if _seq_gt(end, self.next):
                skip = (self.next - seq) & 0xFFFFFFFF
                tail = payload[skip:]
                out += tail
                self.next = (self.next + len(tail)) & 0xFFFFFFFF
                while self.next in self.hold:
                    d = self.hold.pop(self.next)
                    out += d
                    self.next = (self.next + len(d)) & 0xFFFFFFFF
        return bytes(out)


class SSHStream:
    """One direction of an SSH connection: identification string, then cleartext binary
    packets, then opacity. `encrypted_bytes` keeps counting after that, because volume
    after key exchange is what separates a real session from a grace-timeout hold."""

    def __init__(self, cap=262144):
        self.buf = bytearray()
        self.ident = None
        self.pre_ident_lines = []
        self.ident_done = False
        self.packets_done = False
        self.encrypted_bytes = 0
        self.cleartext_packets = 0
        self.cap = cap
        self.bad = False

    def feed(self, data):
        """Return a list of cleartext binary-packet payloads newly framed."""
        if not data or self.bad:
            return []
        if self.packets_done:
            self.encrypted_bytes += len(data)
            return []
        if len(self.buf) < self.cap:
            self.buf += data

        if not self.ident_done:
            while True:
                nl = self.buf.find(b"\n")
                if nl < 0:
                    if len(self.buf) > 8192:      # RFC 4253: 255 bytes per line
                        self.bad = True
                    return []
                line = bytes(self.buf[:nl]).rstrip(b"\r")
                del self.buf[:nl + 1]
                ident = parse_ident(line)
                if ident is not None:
                    self.ident = ident
                    self.ident_done = True
                    break
                self.pre_ident_lines.append(line[:200])
                if len(self.pre_ident_lines) > 32:
                    self.bad = True
                    return []

        try:
            pkts, used, done = parse_packets(self.buf)
        except ValueError:
            # Nothing framed and the first length field is not plausible: this is not SSH
            # framing after a valid identification string. Stop rather than guess.
            self.bad = True
            return []
        if used:
            del self.buf[:used]
        self.cleartext_packets += len(pkts)
        if done:
            self.packets_done = True
            # Whatever trails NEWKEYS in this buffer is already encrypted.
            self.encrypted_bytes += len(self.buf)
            self.buf = bytearray()
        return pkts


class SSHFlow:
    __slots__ = ("client_ep", "server_ep", "reasm", "stream", "client_ident",
                 "server_ident", "client_kexinit", "server_kexinit", "first_ts",
                 "last_ts", "emitted_ident", "emitted_session", "closed", "counted",
                 "total_bytes")

    def __init__(self):
        self.client_ep = None
        self.server_ep = None
        self.reasm = {}
        self.stream = {}
        self.client_ident = None
        self.server_ident = None
        self.client_kexinit = None
        self.server_kexinit = None
        self.first_ts = time.time()
        self.last_ts = self.first_ts
        self.emitted_ident = False
        self.emitted_session = False
        self.closed = False
        self.counted = False
        self.total_bytes = 0

    def duration(self):
        return self.last_ts - self.first_ts

    def payload_bytes(self):
        """Every TCP payload byte seen on this flow, in both directions.

        Counted at the FLOW level rather than from the stream parsers on purpose. An
        earlier version summed the per-direction encrypted-byte counters, which only
        advance once NEWKEYS has been observed — so a connection that carried plenty of
        data but whose NEWKEYS was missed, reordered or unparseable read as having carried
        nothing, and was miscounted as a grace hold."""
        return self.total_bytes


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------
class Emitter:
    def __init__(self, out_path="-", pushover=None, min_alert="warn"):
        self.out_path = out_path
        self.fh = sys.stdout if out_path in (None, "-") else open(out_path, "a",
                                                                 buffering=1)
        self.pushover = pushover
        self.min_alert = SEVERITY_ORDER.get(min_alert, 2)

    def emit(self, event):
        self.fh.write(json.dumps(event, separators=(",", ":"), default=str) + "\n")
        self.fh.flush()
        if self.pushover:
            top = max((SEVERITY_ORDER.get(f["severity"], 0)
                       for f in event.get("findings", [])), default=-1)
            if top >= self.min_alert:
                self._alert(event)

    def _alert(self, event):
        """Out-of-band notification. Not on the monitored segment, never carries captured
        payload — the same deliberate exception tlswatch documents."""
        try:
            import urllib.request
            import urllib.parse
            msgs = "; ".join("[%s] %s" % (f["severity"], f["message"])
                             for f in event.get("findings", []))
            data = urllib.parse.urlencode({
                "token": self.pushover["token"], "user": self.pushover["user"],
                "title": "sshwatch: %s" % event.get("event", "finding"),
                "message": (msgs or "ssh event")[:1024],
            }).encode()
            urllib.request.urlopen(
                urllib.request.Request("https://api.pushover.net/1/messages.json",
                                       data=data), timeout=5)
        except Exception:
            pass


def _now():
    t = time.time()
    return t, datetime.fromtimestamp(t, timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Watcher
# ---------------------------------------------------------------------------
class Watcher:
    def __init__(self, emitter, flow_idle=300, max_flows=4096,
                 grace_seconds=120, grace_tolerance=0.30, grace_window=900,
                 grace_min=20, grace_high=100, max_session_bytes=16384,
                 track_grace=True):
        self.em = emitter
        self.flows = {}
        self.flow_idle = flow_idle
        self.max_flows = max_flows
        # regreSSHion behavioural parameters. LoginGraceTime is a server-side setting a
        # passive observer cannot read, so the expected hold time is configurable and the
        # band around it is generous.
        self.grace_seconds = grace_seconds
        self.grace_tolerance = grace_tolerance
        self.grace_window = grace_window
        self.grace_min = grace_min
        self.grace_high = grace_high
        # Total payload above which the connection is assumed to have carried a real
        # session and is therefore not a grace hold. A full key exchange with host key,
        # signature and certificates runs a few kilobytes; 16 KiB leaves clear room above
        # that without admitting an actual login.
        self.max_session_bytes = max_session_bytes
        self.track_grace = track_grace
        self.grace_events = {}      # source ip -> [timestamps]
        self.grace_alerted = {}     # source ip -> last alert ts
        self._last_gc = time.time()

    # ---- ingest ----
    def on_tcp(self, sip, sport, dip, dport, seq, payload, flags=0, ts=None):
        src = (sip, sport)
        dst = (dip, dport)
        key = tuple(sorted((src, dst)))
        now = ts if ts is not None else time.time()
        fl = self.flows.get(key)
        if fl is None:
            if len(self.flows) >= self.max_flows:
                self._gc(force=True)
            fl = SSHFlow()
            fl.first_ts = now
            self.flows[key] = fl
        fl.last_ts = now
        fl.total_bytes += len(payload)

        if payload:
            if src not in fl.reasm:
                fl.reasm[src] = DirReassembler(anchor=looks_like_ssh_start)
                fl.stream[src] = SSHStream()
            data = fl.reasm[src].add(seq, bytes(payload))
            if data:
                try:
                    pkts = fl.stream[src].feed(data)
                except ValueError:
                    pkts = []
                st = fl.stream[src]
                if st.ident is not None and not self._ident_recorded(fl, src, dst, st):
                    pass
                for p in pkts:
                    self._on_packet(fl, src, dst, p)
                self._try_emit_session(fl)

        # FIN or RST closes the flow; that is when a grace-timeout hold is measurable.
        if flags & 0x05:
            self._close(fl, key, now)
        self._maybe_gc()

    def _ident_recorded(self, fl, src, dst, st):
        """Attribute the identification string to a side. The FIRST endpoint to send one
        is not necessarily the client — servers usually speak first — so sides are
        assigned by destination port when it is a well-known SSH port, and otherwise by
        who sent the first byte."""
        if st.ident is None:
            return False
        already = (fl.client_ident is not None and fl.server_ident is not None)
        if fl.server_ep is None and fl.client_ep is None:
            # The server is whichever side did NOT initiate. Without SYN visibility the
            # best available signal is that a server sends its identification unprompted.
            fl.server_ep = src
            fl.client_ep = dst
        if src == fl.server_ep:
            fl.server_ident = st.ident
        else:
            fl.client_ident = st.ident
        if not fl.emitted_ident and fl.server_ident is not None:
            fl.emitted_ident = True
            self._emit_ident(fl, src, dst)
        return already

    def _on_packet(self, fl, src, dst, payload):
        if not payload or payload[0] != SSH_MSG_KEXINIT:
            return
        try:
            kx = parse_kexinit(payload)
        except ValueError:
            return
        if src == fl.server_ep:
            fl.server_kexinit = kx
        else:
            fl.client_kexinit = kx

    # ---- emission ----
    def _sess(self, fl):
        return {
            "client_ident": fl.client_ident,
            "server_ident": fl.server_ident,
            "client_kexinit": fl.client_kexinit,
            "server_kexinit": fl.server_kexinit,
        }

    def _ident_view(self, ident):
        if not ident:
            return None
        return {k: v for k, v in ident.items() if k != "raw"} | {"raw": ident["raw"]}

    def _kex_view(self, kx):
        if not kx:
            return None
        return {k: kx[k] for k in ("kex_algorithms", "server_host_key_algorithms",
                                   "encryption_algorithms_c2s", "mac_algorithms_c2s",
                                   "compression_algorithms_c2s")}

    def _emit_ident(self, fl, src, dst):
        ts, iso = _now()
        ev = {"schema": SCHEMA_VERSION, "module": MODULE, "event": "ident",
              "ts": ts, "time": iso,
              "server": "%s:%d" % (fl.server_ep or src),
              "client": "%s:%d" % (fl.client_ep or dst),
              "server_ident": self._ident_view(fl.server_ident),
              "client_ident": self._ident_view(fl.client_ident)}
        f = evaluate_findings(self._sess(fl))
        if f:
            ev["findings"] = f
        self.em.emit(ev)

    def _try_emit_session(self, fl):
        if fl.emitted_session:
            return
        if not (fl.client_kexinit and fl.server_kexinit):
            return
        fl.emitted_session = True
        ts, iso = _now()
        ck, sk = fl.client_kexinit, fl.server_kexinit
        ev = {
            "schema": SCHEMA_VERSION, "module": MODULE, "event": "session",
            "ts": ts, "time": iso,
            "server": "%s:%d" % fl.server_ep if fl.server_ep else None,
            "client": "%s:%d" % fl.client_ep if fl.client_ep else None,
            "server_ident": self._ident_view(fl.server_ident),
            "client_ident": self._ident_view(fl.client_ident),
            "negotiated": {
                "kex": negotiate(ck["kex_algorithms"], sk["kex_algorithms"]),
                "host_key": negotiate(ck["server_host_key_algorithms"],
                                      sk["server_host_key_algorithms"]),
                "cipher_c2s": negotiate(ck["encryption_algorithms_c2s"],
                                        sk["encryption_algorithms_c2s"]),
                # <implicit> mirrors what OpenSSH itself reports for an AEAD cipher, so
                # the field can be compared against a real endpoint's own answer.
                "mac_c2s": (IMPLICIT_MAC
                            if negotiate(ck["encryption_algorithms_c2s"],
                                         sk["encryption_algorithms_c2s"]) in AEAD_CIPHERS
                            else negotiate(ck["mac_algorithms_c2s"],
                                           sk["mac_algorithms_c2s"])),
                "compression_c2s": negotiate(ck["compression_algorithms_c2s"],
                                             sk["compression_algorithms_c2s"]),
            },
            "strict_kex": {
                "client": STRICT_KEX_CLIENT in ck["kex_algorithms"],
                "server": STRICT_KEX_SERVER in sk["kex_algorithms"],
            },
            "hassh": hassh(ck),
            "hassh_server": hassh_server(sk),
        }
        f = evaluate_findings(self._sess(fl))
        if f:
            ev["findings"] = f
        self.em.emit(ev)

    # ---- regreSSHion behavioural tracking ----
    def _close(self, fl, key, now):
        if fl.closed:
            return
        fl.closed = True
        fl.last_ts = now
        self._score_grace(fl, now)
        self.flows.pop(key, None)

    def _score_grace(self, fl, now):
        """Count a connection that reached the cleartext handshake and was then held to
        roughly the login-grace expiry without carrying a session.

        Deliberately conservative: the handshake must actually have happened (so port
        scans and TCP-only probes do not count), and post-key-exchange volume must be
        small (so a real session that merely lasted two minutes does not count)."""
        if not self.track_grace or fl.counted:
            return
        if not (fl.server_ident and fl.client_ident):
            return
        dur = fl.duration()
        lo = self.grace_seconds * (1.0 - self.grace_tolerance)
        hi = self.grace_seconds * (1.0 + self.grace_tolerance)
        if not (lo <= dur <= hi):
            return
        if fl.payload_bytes() > self.max_session_bytes:
            return
        fl.counted = True
        srcip = (fl.client_ep or ("?", 0))[0]
        hist = self.grace_events.setdefault(srcip, [])
        hist.append(now)
        cutoff = now - self.grace_window
        while hist and hist[0] < cutoff:
            hist.pop(0)
        if len(hist) < self.grace_min:
            return
        # One alert per source per window, escalating when the count crosses the high mark.
        last = self.grace_alerted.get(srcip)
        if last is not None and (now - last) < self.grace_window and \
                len(hist) < self.grace_high:
            return
        self.grace_alerted[srcip] = now
        ts, iso = _now()
        sess = self._sess(fl)
        sess["grace_burst"] = {"source": srcip, "count": len(hist),
                               "window": self.grace_window, "grace": self.grace_seconds,
                               "high_threshold": self.grace_high}
        ev = {"schema": SCHEMA_VERSION, "module": MODULE, "event": "grace_burst",
              "ts": ts, "time": iso, "source": srcip,
              "server": "%s:%d" % fl.server_ep if fl.server_ep else None,
              "findings": [f for f in evaluate_findings(sess)
                           if f["code"] == "cve_2024_6387_grace_timeout_pattern"]}
        self.em.emit(ev)

    # ---- housekeeping ----
    def _maybe_gc(self):
        if time.time() - self._last_gc > 30:
            self._gc()

    def _gc(self, force=False):
        now = time.time()
        self._last_gc = now
        cutoff = 0 if force else self.flow_idle
        dead = [k for k, v in self.flows.items() if (now - v.last_ts) > cutoff]
        if force and not dead and self.flows:
            ordered = sorted(self.flows.items(), key=lambda kv: kv[1].last_ts)
            dead = [k for k, _ in ordered[:max(1, len(ordered) // 4)]]
        for k in dead:
            fl = self.flows.get(k)
            if fl is not None:
                # An idle-expired flow may still be a grace hold that was never torn down
                # within our view; score it before dropping.
                self._score_grace(fl, fl.last_ts)
            self.flows.pop(k, None)
        for ip, hist in list(self.grace_events.items()):
            while hist and hist[0] < now - self.grace_window:
                hist.pop(0)
            if not hist:
                self.grace_events.pop(ip, None)


# ---------------------------------------------------------------------------
# HASSH (Salesforce, BSD-3): an MD5 over the client's algorithm preferences. Included
# because it is the SSH analogue of JA3 and costs nothing once KEXINIT is parsed.
# ---------------------------------------------------------------------------
def hassh(client_kexinit):
    s = ";".join([
        ",".join(client_kexinit["kex_algorithms"]),
        ",".join(client_kexinit["encryption_algorithms_c2s"]),
        ",".join(client_kexinit["mac_algorithms_c2s"]),
        ",".join(client_kexinit["compression_algorithms_c2s"]),
    ])
    return hashlib.md5(s.encode()).hexdigest()


def hassh_server(server_kexinit):
    s = ";".join([
        ",".join(server_kexinit["kex_algorithms"]),
        ",".join(server_kexinit["encryption_algorithms_s2c"]),
        ",".join(server_kexinit["mac_algorithms_s2c"]),
        ",".join(server_kexinit["compression_algorithms_s2c"]),
    ])
    return hashlib.md5(s.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Live capture. Scapy is imported lazily so --selftest needs neither scapy nor root.
# ---------------------------------------------------------------------------
def run_live(args):
    from scapy.all import AsyncSniffer  # noqa
    from scapy.layers.inet import IP, TCP
    try:
        from scapy.layers.inet6 import IPv6
    except Exception:
        IPv6 = None
    from scapy.packet import Raw

    ports = set(int(p) for p in args.ports.split(",") if p.strip())
    pushover = None
    if args.pushover_token and args.pushover_user:
        pushover = {"token": args.pushover_token, "user": args.pushover_user}
    emitter = Emitter(args.out, pushover=pushover, min_alert=args.min_alert_severity)
    watcher = Watcher(emitter, flow_idle=args.flow_idle, max_flows=args.max_flows,
                      grace_seconds=args.grace_seconds,
                      grace_tolerance=args.grace_tolerance,
                      grace_window=args.grace_window, grace_min=args.grace_min,
                      grace_high=args.grace_high,
                      track_grace=not args.no_grace_track)

    bpf = args.bpf or " or ".join("tcp port %d" % p for p in sorted(ports))

    def handle(pkt):
        try:
            if TCP not in pkt:
                return
            ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 and IPv6 in pkt else None)
            if ip is None:
                return
            t = pkt[TCP]
            if int(t.dport) not in ports and int(t.sport) not in ports:
                return
            payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            watcher.on_tcp(ip.src, int(t.sport), ip.dst, int(t.dport), int(t.seq),
                           payload, flags=int(t.flags))
        except Exception:
            return

    sys.stderr.write("[sshwatch] sniffing iface=%s bpf=%r\n" % (args.iface, bpf))
    sniffer = AsyncSniffer(iface=args.iface, filter=bpf, prn=handle, store=False)
    sniffer.start()
    try:
        while True:
            time.sleep(1)
            watcher._maybe_gc()
    except KeyboardInterrupt:
        sniffer.stop()
        sys.stderr.write("[sshwatch] stopped\n")


# ===========================================================================
# In-app adapter. Ragnar wires sshwatch into the Network Tools UI the same way it
# wires tls_watch / ldap_watch: a bounded tcpdump capture into a temp pcap, replayed
# through the SAME passive Watcher used by run_live(), returning one verdict dict for
# the card. No detection logic lives here — it only drives the existing code path.
# ===========================================================================
SSH_TCP_PORTS = (22,)


class _CollectEmitter:
    """Emitter stand-in that keeps events in a list instead of writing JSON-lines."""

    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def _capture_pcap(interface, seconds, tcp_ports):
    """Run tcpdump for `seconds` into a temp pcap and return its path. Passive: -w
    only, no probes. Returns None if tcpdump is unavailable."""
    import shutil
    import subprocess
    import tempfile
    import os
    if not shutil.which("tcpdump"):
        return None
    bpf = " or ".join("tcp port %d" % p for p in tcp_ports)
    fd, path = tempfile.mkstemp(suffix=".pcap", prefix="sshwatch_")
    os.close(fd)
    try:
        subprocess.run(["tcpdump", "-i", interface, "-w", path, "-s", "0", "-U",
                        "-q", bpf], timeout=seconds, capture_output=True)
    except subprocess.TimeoutExpired:
        pass                                       # expected: we run for the window
    except Exception:
        return None
    return path


def _replay_pcap(path, watcher, ports):
    """Feed a captured pcap through the Watcher exactly as run_live() does, using each
    packet's own wire timestamp so a login-grace hold is measured from the capture
    rather than wall-clock. Returns the number of packets fed."""
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
                ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 and IPv6 in pkt else None)
                if ip is None:
                    continue
                t = pkt[TCP]
                if int(t.dport) not in ports and int(t.sport) not in ports:
                    continue
                payload = bytes(pkt[Raw].load) if Raw in pkt else b""
                watcher.on_tcp(ip.src, int(t.sport), ip.dst, int(t.dport),
                               int(t.seq), payload, flags=int(t.flags),
                               ts=float(pkt.time))
                n += 1
            except Exception:
                continue
    return n


def _ssh_row(ev):
    """Compact one emitted event into a card-friendly row."""
    si = ev.get("server_ident") or {}
    ci = ev.get("client_ident") or {}
    row = {"kind": ev.get("event"),
           "server": ev.get("server"), "client": ev.get("client"),
           "server_ident": si.get("raw"), "client_ident": ci.get("raw"),
           "findings": ev.get("findings", [])}
    if "negotiated" in ev:
        row["negotiated"] = ev["negotiated"]
        row["strict_kex"] = ev.get("strict_kex")
        row["hassh"] = ev.get("hassh")
        row["hassh_server"] = ev.get("hassh_server")
    if "source" in ev:
        row["source"] = ev["source"]
    return row


def _ssh_summarize(events, interface, seconds):
    """Collapse emitted ident/session/grace_burst events into one verdict dict. A
    flow's session event supersedes its earlier ident. SSH findings are posture /
    exposure / heuristic — never a confirmed live compromise — so the verdict scale
    tops out at 'suspicious'."""
    index, order, bursts = {}, [], []
    for ev in events:
        if ev.get("event") == "grace_burst":
            bursts.append(_ssh_row(ev))
            continue
        key = (ev.get("server"), ev.get("client"))
        if key not in index:
            order.append(key)
            index[key] = _ssh_row(ev)
        elif ev.get("event") == "session":
            index[key] = _ssh_row(ev)          # session supersedes the ident row
    rows = [index[k] for k in order] + bursts
    all_findings = [f for r in rows for f in r.get("findings", [])]
    verdict = "suspicious" if any(
        f.get("severity") in ("high", "warn") for f in all_findings) else "clean"
    return {"success": True, "verdict": verdict, "sessions": rows,
            "count": len(order), "grace_bursts": len(bursts),
            "findings_total": len(all_findings),
            "interface": interface, "seconds": seconds}


# --- Watchtower feed: append findings as JSON-lines so the unified alert pane tails them ---
_WT_LOG_DIR = os.environ.get("RAGNAR_WATCH_LOG_DIR", "/var/log/ragnar")
_WT_DEDUP_S = 300.0                    # don't re-log the same standing finding within 5 min
_WT_SKIP_SEV = frozenset(("info",))   # pure posture/inventory stays off the alert pane
_wt_lock = threading.Lock()
_wt_seen = {}                         # (code, server) -> last-emitted epoch


def _emit_watchtower(result):
    """Append each non-info SSH finding to <log-dir>/ssh_watch.jsonl in the shape
    Watchtower.normalize() reads, so the unified alert pane and its single Pushover
    path fold in the in-app SSH observer alongside the standalone watchers. Time-window
    deduplicated per (code, server) so the background rotation can't spam a standing
    condition. Best-effort: the scan never fails because logging did."""
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
                if sev in _WT_SKIP_SEV:
                    continue
                code = f.get("code")
                key = (code, server)
                last = _wt_seen.get(key)
                if last is not None and now - last < _WT_DEDUP_S:
                    continue
                _wt_seen[key] = now
                cve = f.get("cve")
                lines.append(json.dumps({
                    "module": "ssh_watch", "ts": now, "iso": iso, "iface": iface,
                    "severity": sev, "code": code, "codes": [code],
                    "src": server, "target": client,
                    "cves": [cve] if cve else [],
                    "summary": f.get("message"), "verdict": verdict}))
        if len(_wt_seen) > 4096:
            cutoff = now - _WT_DEDUP_S
            for k in [k for k, t in _wt_seen.items() if t < cutoff]:
                _wt_seen.pop(k, None)
    if not lines:
        return
    try:
        os.makedirs(_WT_LOG_DIR, exist_ok=True)
        with open(os.path.join(_WT_LOG_DIR, "ssh_watch.jsonl"), "a") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


def do_ssh_watch(interface=None, seconds=12, grace_seconds=120, grace_min=20,
                 no_grace_track=False):
    """Passive SSH observation on `interface` for `seconds`. Reads the cleartext SSH
    prologue (identification strings + both KEXINITs) already flowing and reports
    software versions, the negotiated algorithm set, CVE-2023-48795 (Terrapin)
    exposure, and the CVE-2024-6387 (regreSSHion) login-grace access pattern. Never
    opens a connection. Requires root (raw capture) and tcpdump; scapy for dissection.

    The grace-timeout finding needs a capture window long enough to observe a hold of
    ~`grace_seconds`; on a short snapshot the version/Terrapin/algorithm findings are
    what surface. `grace_seconds` must match the servers' LoginGraceTime."""
    import os
    seconds = max(4, min(int(seconds or 12), 60))
    if not interface:
        return {"success": False, "error": "no interface specified"}
    try:
        import scapy  # noqa: F401
    except Exception:
        return {"success": False, "missing_tool": "scapy",
                "error": 'the Python "scapy" package is required for pcap dissection'}
    pcap = _capture_pcap(interface, seconds, SSH_TCP_PORTS)
    if not pcap:
        return {"success": False, "missing_tool": "tcpdump",
                "error": "tcpdump is required for capture"}
    em = _CollectEmitter()
    watcher = Watcher(em, grace_seconds=grace_seconds, grace_min=grace_min,
                      track_grace=not no_grace_track)
    try:
        _replay_pcap(pcap, watcher, set(SSH_TCP_PORTS))
    except Exception as e:
        return {"success": False, "error": "pcap parse failed: {}".format(e)}
    finally:
        try:
            os.unlink(pcap)
        except OSError:
            pass
    watcher._gc(force=True)      # flush held flows so grace holds within the window score
    result = _ssh_summarize(em.events, interface, seconds)
    _emit_watchtower(result)
    return result


# ===========================================================================
# Self-test. Fixtures are bytes captured from a REAL OpenSSH server wherever possible
# (suite LESSON N) rather than hand-built, because a hand-built KEXINIT would encode this
# module's own understanding of the format and could not disprove it.
# ===========================================================================
# Captured from `OpenSSH_9.6p1 Ubuntu-3ubuntu13.18` on 2026-08-21. This is a real server
# KEXINIT packet exactly as it appeared on the wire, framing included.
REAL_SERVER_KEXINIT_HEX = (
    "0000044c0b1408fd3199b3068c2640df2bd1acea230a00000131736e74727570373631783235"
    "3531392d736861353132406f70656e7373682e636f6d2c637572766532353531392d73686132"
    "35362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d73"
    "6861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d73"
    "6861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368"
    "616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031362d736861"
    "3531322c6469666669652d68656c6c6d616e2d67726f757031382d7368613531322c64696666"
    "69652d68656c6c6d616e2d67726f757031342d7368613235362c6578742d696e666f2d732c6b"
    "65782d7374726963742d732d763030406f70656e7373682e636f6d000000257373682d656432"
    "353531392c7273612d736861322d3531322c7273612d736861322d3235360000006c63686163"
    "686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c61"
    "65733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373"
    "682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000006c636861636861"
    "32302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c616573"
    "3139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e"
    "636f6d2c6165733235362d67636d406f70656e7373682e636f6d000000d5756d61632d36342d"
    "65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e63"
    "6f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d"
    "736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d"
    "406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d"
    "313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861"
    "322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e737368"
    "2e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861"
    "322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d6574"
    "6d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f"
    "6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e737368"
    "2e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d"
    "73686131000000156e6f6e652c7a6c6962406f70656e7373682e636f6d000000156e6f6e652c"
    "7a6c6962406f70656e7373682e636f6d00000000000000000000000000000000000000000000"
    "0000"
)
REAL_SERVER_BANNER = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18\r\n"


class _T:
    def __init__(self):
        self.n = 0
        self.fail = 0
        self.records = []          # [(label, passed)] for the structured selftest()

    def eq(self, got, want, label):
        self.n += 1
        ok = (got == want)
        self.records.append((label, ok))
        if not ok:
            self.fail += 1
            print("  FAIL %-46s got=%r want=%r" % (label, got, want))

    def ok(self, cond, label, detail=""):
        self.n += 1
        self.records.append((label, bool(cond)))
        if not cond:
            self.fail += 1
            print("  FAIL %-46s %s" % (label, detail))

    def raises(self, fn, exc, label):
        self.n += 1
        try:
            fn()
        except exc:
            self.records.append((label, True))
            return
        except Exception as e:
            self.fail += 1
            self.records.append((label, False))
            print("  FAIL %-46s raised %s" % (label, type(e).__name__))
            return
        self.fail += 1
        self.records.append((label, False))
        print("  FAIL %-46s did not raise" % label)


def build_kexinit(kex=(), hostkey=(), enc=(), mac=(), comp=("none",)):
    """Test helper: assemble a KEXINIT packet. Used only for scenarios the real capture
    cannot supply (a Terrapin-vulnerable peer, a weak-algorithm peer)."""
    payload = bytearray([SSH_MSG_KEXINIT]) + b"\x00" * 16
    lists = [kex, hostkey, enc, enc, mac, mac, comp, comp, (), ()]
    for lst in lists:
        blob = ",".join(lst).encode()
        payload += len(blob).to_bytes(4, "big") + blob
    payload += b"\x00" + b"\x00" * 4
    pad_len = 8 - ((len(payload) + 5) % 8)
    if pad_len < 4:
        pad_len += 8
    plen = len(payload) + 1 + pad_len
    return plen.to_bytes(4, "big") + bytes([pad_len]) + bytes(payload) + b"\x00" * pad_len


def _run_selftest_checks(t):
    # ---- identification string parsing ----
    i = parse_ident(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18")
    t.ok(i is not None, "ident_parses")
    t.eq(i["protocol"], "2.0", "ident_protocol")
    t.eq(i["software"], "OpenSSH_9.6p1", "ident_software")
    t.eq(i["comments"], "Ubuntu-3ubuntu13.18", "ident_comments")
    t.eq(i["version"], (9, 6, 1), "ident_version_tuple")
    t.ok(i["distro_packaged"], "ident_distro_detected")

    t.eq(parse_ident(b"SSH-2.0-OpenSSH_8.7")["version"], (8, 7, None), "ident_no_portable")
    t.ok(not parse_ident(b"SSH-2.0-OpenSSH_8.7")["distro_packaged"],
         "ident_bare_version_not_flagged_distro")
    t.eq(parse_ident(b"SSH-1.99-OpenSSH_3.9p1")["protocol"], "1.99", "ident_proto_199")
    t.eq(parse_ident(b"SSH-2.0-dropbear_2022.83")["vendor"], None, "ident_non_openssh")
    # Real banners that violate RFC 4253's no-minus rule must still parse. Cisco IOS is
    # the one that matters operationally.
    for raw, want in ((b"SSH-2.0-Cisco-1.25", "Cisco-1.25"),
                      (b"SSH-1.99-Cisco-1.25", "Cisco-1.25"),
                      (b"SSH-2.0-libssh-0.7.0", "libssh-0.7.0"),
                      (b"SSH-2.0-Go", "Go"),
                      (b"SSH-2.0-paramiko_5.0.0", "paramiko_5.0.0")):
        got = parse_ident(raw)
        t.ok(got is not None, "ident_accepts_%s" % want.replace(".", "_"))
        if got:
            t.eq(got["software"], want, "ident_software_%s" % want.replace(".", "_"))
    t.eq(parse_ident(b"SSH-1.99-Cisco-1.25")["protocol"], "1.99", "ident_cisco_proto_199")
    # A minus-bearing software string with a comment still splits on the first space.
    got = parse_ident(b"SSH-2.0-Cisco-1.25 some comment")
    t.eq(got["software"], "Cisco-1.25", "ident_minus_software_with_comment")
    t.eq(got["comments"], "some comment", "ident_minus_comment")
    t.ok(parse_ident(b"HTTP/1.1 200 OK") is None, "ident_rejects_http")
    t.ok(parse_ident(b"\x16\x03\x01\x00\x05") is None, "ident_rejects_tls")
    t.ok(parse_ident(b"") is None, "ident_rejects_empty")

    # ---- CVE-2024-6387 affected-version model ----
    for ver, want, label in (
            ((9, 6, 1), True, "9.6p1"), ((8, 5, 1), True, "8.5p1_low_boundary"),
            ((9, 7, 1), True, "9.7p1_high_boundary"), ((9, 8, 1), False, "9.8p1_fixed"),
            ((8, 4, 1), False, "8.4p1_below_range"), ((9, 9, 1), False, "9.9p1_above"),
            ((4, 3, 1), True, "4.3p1_ancient"), ((4, 4, 1), False, "4.4p1_fixed_ancient"),
            ((10, 0, 1), False, "10.0p1_future"), ((9, 7, None), True, "9.7_nonportable"),
            # A release and its portable build must agree — they ARE the same release.
            ((8, 5, None), True, "8.5_nonportable_low_boundary"),
            ((9, 8, None), False, "9.8_nonportable_fixed"),
            ((4, 4, None), False, "4.4_nonportable_fixed_ancient"),
            ((8, 5, 2), True, "8.5p2_same_release"),
            ((9, 7, 3), True, "9.7p3_same_release")):
        t.eq(regresshion_affected(ver)[0], want, "regresshion_%s" % label)
    # The p-level must never change membership within a release.
    for mm in ((8, 5), (9, 0), (9, 7), (9, 8), (4, 4), (4, 3)):
        results = {regresshion_affected((mm[0], mm[1], p))[0]
                   for p in (None, 1, 2, 3)}
        t.eq(len(results), 1, "release_membership_independent_of_plevel_%d_%d" % mm)
    t.eq(regresshion_affected((4, 3, 1))[1], "ancient", "regresshion_range_label_ancient")
    t.eq(regresshion_affected((9, 6, 1))[1], "modern", "regresshion_range_label_modern")
    t.eq(regresshion_affected(None)[0], False, "regresshion_unknown_version")
    # Ordering: a non-portable release precedes pN of the same major.minor.
    t.ok(_cmp_version((9, 8, None)) < _cmp_version((9, 8, 1)), "version_ordering_nonportable")
    t.eq(fmt_version((9, 6, 1)), "9.6p1", "fmt_version_portable")
    t.eq(fmt_version((8, 7, None)), "8.7", "fmt_version_bare")

    # ---- binary packet framing ----
    pkt = build_kexinit(kex=("curve25519-sha256",), enc=("aes128-ctr",),
                        mac=("hmac-sha2-256",))
    pkts, used, done = parse_packets(pkt)
    t.eq(len(pkts), 1, "packet_frames_one")
    t.eq(used, len(pkt), "packet_consumes_all")
    t.eq(pkts[0][0], SSH_MSG_KEXINIT, "packet_msg_type")
    t.eq(done, False, "packet_not_done_before_newkeys")
    pkts, used, _ = parse_packets(pkt[:len(pkt) // 2])
    t.eq(pkts, [], "packet_partial_yields_nothing")
    t.eq(used, 0, "packet_partial_consumes_nothing")
    pkts, _, _ = parse_packets(pkt + pkt)
    t.eq(len(pkts), 2, "packet_two_in_one_buffer")
    # A KEXINIT followed by NEWKEYS and then encrypted noise must yield the KEXINIT and
    # stop, not discard it. This is the shape a real handshake produces.
    newkeys_pkt = b"\x00\x00\x00\x0c\x0a" + bytes([SSH_MSG_NEWKEYS]) + b"\x00" * 10
    noise = bytes((i * 37 + 11) & 0xFF for i in range(400))
    pkts, used, done = parse_packets(pkt + newkeys_pkt + noise)
    t.eq(len(pkts), 2, "packet_frames_up_to_newkeys")
    t.eq(done, True, "packet_reports_newkeys")
    t.eq(used, len(pkt) + len(newkeys_pkt), "packet_stops_before_encrypted")
    t.raises(lambda: parse_packets(b"\xff\xff\xff\xff\x04"), ValueError,
             "packet_rejects_huge_length")
    t.raises(lambda: parse_packets(b"\x00\x00\x00\x02\x04"), ValueError,
             "packet_rejects_tiny_length")
    t.raises(lambda: parse_packets(b"\x00\x00\x00\x10\x00" + b"x" * 16), ValueError,
             "packet_rejects_bad_padding")

    # ---- KEXINIT against a REAL captured OpenSSH server packet ----
    if REAL_SERVER_KEXINIT_HEX != "REPLACE_ME":
        raw = bytes.fromhex(REAL_SERVER_KEXINIT_HEX)
        pkts, used, _ = parse_packets(raw)
        t.eq(len(pkts), 1, "real_kexinit_frames")
        t.eq(used, len(raw), "real_kexinit_consumes_all")
        kx = parse_kexinit(pkts[0])
        t.ok("curve25519-sha256" in kx["kex_algorithms"], "real_kexinit_has_curve25519")
        t.ok(STRICT_KEX_SERVER in kx["kex_algorithms"], "real_kexinit_advertises_strict_kex")
        t.ok("ext-info-s" in kx["kex_algorithms"], "real_kexinit_has_ext_info")
        t.ok("ssh-ed25519" in kx["server_host_key_algorithms"], "real_kexinit_hostkeys")
        t.ok("chacha20-poly1305@openssh.com" in kx["encryption_algorithms_c2s"],
             "real_kexinit_ciphers")
        t.ok("umac-64-etm@openssh.com" in kx["mac_algorithms_c2s"], "real_kexinit_macs")
        t.eq(kx["compression_algorithms_c2s"], ["none", "zlib@openssh.com"],
             "real_kexinit_compression")
        t.eq(kx["languages_c2s"], [], "real_kexinit_empty_language_list")
        t.eq(kx["first_kex_packet_follows"], False, "real_kexinit_no_guess")
        t.eq(kx["reserved"], 0, "real_kexinit_reserved_zero")
        t.eq(len(kx["cookie"]), 32, "real_kexinit_cookie_hex_len")
        # A real server is not Terrapin-exposed, and must not be reported as such.
        ck = parse_kexinit(parse_packets(build_kexinit(
            kex=("curve25519-sha256", STRICT_KEX_CLIENT),
            hostkey=("ssh-ed25519",),
            enc=("chacha20-poly1305@openssh.com",),
            mac=("hmac-sha2-256",)))[0][0])
        f = evaluate_findings({"client_kexinit": ck, "server_kexinit": kx})
        t.ok(not any(x["code"] == "cve_2023_48795_terrapin_exposed" for x in f),
             "real_server_not_terrapin_exposed", str([x["code"] for x in f]))

    # ---- name-list parsing edges ----
    r = Reader(b"\x00\x00\x00\x00")
    t.eq(r.name_list(), [], "namelist_empty")
    r = Reader(b"\x00\x00\x00\x03abc")
    t.eq(r.name_list(), ["abc"], "namelist_single")
    t.raises(lambda: Reader(b"\x00\x00\x00\x05ab").name_list(), ValueError,
             "namelist_truncated_raises")

    # ---- negotiation follows the client's preference order ----
    t.eq(negotiate(["a", "b", "c"], ["c", "b"]), "b", "negotiate_client_preference")
    t.eq(negotiate(["a"], ["b"]), None, "negotiate_no_overlap")
    t.eq(negotiate([], ["a"]), None, "negotiate_empty_client")

    # ---- Terrapin ----
    def kx_pair(c_strict, s_strict, cipher, mac):
        c = parse_kexinit(parse_packets(build_kexinit(
            kex=("curve25519-sha256",) + ((STRICT_KEX_CLIENT,) if c_strict else ()),
            hostkey=("ssh-ed25519",), enc=(cipher,), mac=(mac,)))[0][0])
        s = parse_kexinit(parse_packets(build_kexinit(
            kex=("curve25519-sha256",) + ((STRICT_KEX_SERVER,) if s_strict else ()),
            hostkey=("ssh-ed25519",), enc=(cipher,), mac=(mac,)))[0][0])
        return {"client_kexinit": c, "server_kexinit": s}

    codes = lambda f: {x["code"] for x in f}
    f = evaluate_findings(kx_pair(False, False, "chacha20-poly1305@openssh.com",
                                  "hmac-sha2-256"))
    t.ok("cve_2023_48795_terrapin_exposed" in codes(f), "terrapin_chacha_no_strict")
    f = evaluate_findings(kx_pair(True, True, "chacha20-poly1305@openssh.com",
                                  "hmac-sha2-256"))
    t.ok("cve_2023_48795_terrapin_exposed" not in codes(f), "terrapin_strict_protects")
    f = evaluate_findings(kx_pair(True, False, "chacha20-poly1305@openssh.com",
                                  "hmac-sha2-256"))
    t.ok("cve_2023_48795_terrapin_exposed" in codes(f), "terrapin_needs_both_sides")
    f = evaluate_findings(kx_pair(False, False, "aes128-cbc",
                                  "hmac-sha2-256-etm@openssh.com"))
    t.ok("cve_2023_48795_terrapin_exposed" in codes(f), "terrapin_cbc_etm")
    f = evaluate_findings(kx_pair(False, False, "aes128-cbc", "hmac-sha2-256"))
    t.ok("cve_2023_48795_terrapin_exposed" not in codes(f), "terrapin_cbc_without_etm_safe")
    t.ok("ssh_strict_kex_absent" in codes(f), "strict_kex_absent_posture")
    f = evaluate_findings(kx_pair(False, False, "aes128-ctr", "hmac-sha2-256"))
    t.ok("cve_2023_48795_terrapin_exposed" not in codes(f), "terrapin_ctr_safe")

    # ---- weak algorithm posture, on the NEGOTIATED choice ----
    f = evaluate_findings(kx_pair(True, True, "3des-cbc", "hmac-sha2-256"))
    t.ok("ssh_weak_cipher" in codes(f), "weak_cipher_3des")
    f = evaluate_findings(kx_pair(True, True, "aes128-ctr", "hmac-md5"))
    t.ok("ssh_weak_mac" in codes(f), "weak_mac_md5")
    c = parse_kexinit(parse_packets(build_kexinit(
        kex=("diffie-hellman-group1-sha1",), hostkey=("ssh-dss",),
        enc=("aes128-ctr",), mac=("hmac-sha2-256",)))[0][0])
    f = evaluate_findings({"client_kexinit": c, "server_kexinit": c})
    t.ok("ssh_weak_kex" in codes(f), "weak_kex_group1_sha1")
    t.ok("ssh_weak_hostkey" in codes(f), "weak_hostkey_dss")
    f = evaluate_findings(kx_pair(True, True, "aes256-ctr", "hmac-sha2-512"))
    t.eq(codes(f), set(), "modern_algorithms_silent")
    # Severity tiering: broken and merely-dated must not share a severity.
    def sev_of(f, code):
        hits = [x for x in f if x["code"] == code]
        return hits[0]["severity"] if hits else None
    t.eq(sev_of(evaluate_findings(kx_pair(True, True, "none", "hmac-sha2-256")),
                "ssh_weak_cipher"), "high", "cipher_none_is_high")
    t.eq(sev_of(evaluate_findings(kx_pair(True, True, "arcfour", "hmac-sha2-256")),
                "ssh_weak_cipher"), "warn", "cipher_rc4_is_warn")
    t.eq(sev_of(evaluate_findings(kx_pair(True, True, "aes128-ctr", "hmac-md5")),
                "ssh_weak_mac"), "warn", "mac_md5_is_warn")
    # OpenSSH's DEFAULT first-preference MAC must not raise a warning: putting a warn on
    # the default configuration of the commonest implementation makes the feed noise.
    # Paired with a NON-AEAD cipher on purpose: under an AEAD there is no negotiated MAC
    # to score at all, so the tiering could not be observed.
    t.eq(sev_of(evaluate_findings(kx_pair(True, True, "aes128-ctr",
                                          "umac-64-etm@openssh.com")),
                "ssh_weak_mac"), "notice", "openssh_default_mac_is_notice_not_warn")

    # AEAD: no separate MAC is negotiated, so no weak-MAC finding may be raised however
    # weak the MAC name-lists are. Found by comparing against OpenSSH's own report, which
    # prints "MAC: <implicit>" for an AEAD cipher.
    for aead in ("chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com",
                 "aes256-gcm@openssh.com"):
        f = evaluate_findings(kx_pair(True, True, aead, "hmac-md5"))
        t.ok("ssh_weak_mac" not in codes(f), "aead_suppresses_weak_mac_%s" % aead.split("-")[0])
        t.eq(effective_mac(aead, "hmac-md5"), None, "effective_mac_none_under_%s"
             % aead.split("-")[0])
    # ...and a non-AEAD cipher must still raise it, or the suppression is too broad.
    f = evaluate_findings(kx_pair(True, True, "aes128-ctr", "hmac-md5"))
    t.ok("ssh_weak_mac" in codes(f), "non_aead_still_raises_weak_mac")
    t.eq(effective_mac("aes128-ctr", "hmac-md5"), "hmac-md5", "effective_mac_passthrough")

    # CLEAN SET, against the REAL captured OpenSSH server KEXINIT rather than a fixture.
    # A modern client talking to it must raise nothing at warn or above except the version
    # posture notice, or every false-positive gate downstream is meaningless.
    if REAL_SERVER_KEXINIT_HEX != "REPLACE_ME":
        rk = parse_kexinit(parse_packets(bytes.fromhex(REAL_SERVER_KEXINIT_HEX))[0][0])
        rc = parse_kexinit(parse_packets(build_kexinit(
            kex=("sntrup761x25519-sha512@openssh.com", "curve25519-sha256",
                 STRICT_KEX_CLIENT),
            hostkey=("ssh-ed25519",),
            enc=("chacha20-poly1305@openssh.com", "aes256-ctr"),
            mac=("hmac-sha2-256", "umac-64-etm@openssh.com")))[0][0])
        f = evaluate_findings({"client_kexinit": rc, "server_kexinit": rk,
                               "server_ident": parse_ident(REAL_SERVER_BANNER.strip())})
        loud = [x for x in f if SEVERITY_ORDER[x["severity"]] >= SEVERITY_ORDER["warn"]]
        t.eq(loud, [], "real_openssh_session_raises_nothing_loud")
        t.ok(any(x["code"] == "cve_2024_6387_version_in_range" for x in f),
             "real_openssh_still_reports_version_posture")
        # ...and the gate is non-vacuous: a Terrapin-exposed peer breaks the silence.
        rc2 = parse_kexinit(parse_packets(build_kexinit(
            kex=("curve25519-sha256",), hostkey=("ssh-ed25519",),
            enc=("chacha20-poly1305@openssh.com",), mac=("hmac-sha2-256",)))[0][0])
        f2 = evaluate_findings({"client_kexinit": rc2, "server_kexinit": rk})
        t.ok(any(SEVERITY_ORDER[x["severity"]] >= SEVERITY_ORDER["warn"] for x in f2),
             "clean_set_gate_is_non_vacuous")

    # ---- CVE-2024-6387 version posture ----
    srv = parse_ident(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18")
    f = evaluate_findings({"server_ident": srv})
    hit = [x for x in f if x["code"] == "cve_2024_6387_version_in_range"]
    t.eq(len(hit), 1, "regresshion_posture_fires")
    t.eq(hit[0]["severity"], "notice", "regresshion_capped_at_notice")
    t.eq(hit[0]["confidence"], "low", "regresshion_low_confidence")
    t.ok(hit[0]["distro_packaged"], "regresshion_marks_distro")
    t.ok("backport" in hit[0]["message"], "regresshion_message_names_backport_problem")
    t.eq(hit[0]["cvss"], 8.1, "regresshion_cvss")
    t.eq(hit[0]["severity_word"], "HIGH", "regresshion_severity_word_high_not_critical")
    t.eq(hit[0]["detect_class"], "posture", "regresshion_detect_class")
    # A bare version must NOT be treated as more trustworthy than a packaged one.
    bare = parse_ident(b"SSH-2.0-OpenSSH_8.7")
    hit = [x for x in evaluate_findings({"server_ident": bare})
           if x["code"] == "cve_2024_6387_version_in_range"]
    t.eq(len(hit), 1, "regresshion_fires_on_bare_version")
    t.eq(hit[0]["confidence"], "low", "regresshion_bare_still_low_confidence")
    t.ok("Red Hat" in hit[0]["message"], "regresshion_bare_names_rhel_case")
    # Fixed and out-of-range versions stay silent.
    for banner in (b"SSH-2.0-OpenSSH_9.8p1", b"SSH-2.0-OpenSSH_10.0p1",
                   b"SSH-2.0-OpenSSH_8.4p1", b"SSH-2.0-dropbear_2022.83"):
        f = evaluate_findings({"server_ident": parse_ident(banner)})
        t.ok(not any(x["code"] == "cve_2024_6387_version_in_range" for x in f),
             "regresshion_silent_%s" % banner.decode().split("-")[-1])
    # The CLIENT version must never raise it — the flaw is in sshd.
    f = evaluate_findings({"client_ident": srv})
    t.ok(not any(x["code"] == "cve_2024_6387_version_in_range" for x in f),
         "regresshion_ignores_client_version")

    # ---- SSH-1 ----
    f = evaluate_findings({"server_ident": parse_ident(b"SSH-1.5-OpenSSH_3.4p1")})
    t.ok("ssh_protocol_1x" in codes(f), "ssh1_detected")

    # ---- catalog metadata ----
    m = CVE_CATALOG["CVE-2024-6387"]
    t.eq(m["cvss"], 8.1, "catalog_cvss")
    t.eq(m["severity_word"], "HIGH", "catalog_severity_word")
    t.ok("Critical" in m["score_note"], "catalog_notes_critical_mislabel")
    t.ok("backport" in m["detect_note"], "catalog_detect_note_honest")
    t.eq(CVE_CATALOG["CVE-2023-48795"]["detect"], "exposure", "catalog_terrapin_exposure")

    # ---- stream assembly ----
    st = SSHStream()
    t.eq(st.feed(REAL_SERVER_BANNER), [], "stream_banner_only")
    t.ok(st.ident is not None, "stream_ident_captured")
    t.eq(st.ident["software"], "OpenSSH_9.6p1", "stream_ident_software")
    # Banner split across segments
    st = SSHStream()
    t.eq(st.feed(REAL_SERVER_BANNER[:10]), [], "stream_partial_banner")
    st.feed(REAL_SERVER_BANNER[10:])
    t.ok(st.ident is not None, "stream_banner_reassembled")
    # RFC 4253 permits lines before the identification string
    st = SSHStream()
    st.feed(b"Authorized users only\r\nSee policy 42\r\n" + REAL_SERVER_BANNER)
    t.ok(st.ident is not None, "stream_skips_pre_ident_lines")
    t.eq(len(st.pre_ident_lines), 2, "stream_records_pre_ident_lines")
    # Banner then KEXINIT in one segment
    st = SSHStream()
    pkts = st.feed(REAL_SERVER_BANNER + pkt)
    t.eq(len(pkts), 1, "stream_banner_and_packet_one_segment")
    # NEWKEYS switches to opaque counting
    st = SSHStream()
    st.feed(REAL_SERVER_BANNER)
    newkeys = b"\x00\x00\x00\x0c\x0a" + b"\x15" + b"\x00" * 10
    st.feed(newkeys)
    t.ok(st.packets_done, "stream_newkeys_ends_cleartext")
    st.feed(b"\x00" * 5000)
    t.eq(st.encrypted_bytes, 5000, "stream_counts_encrypted_bytes")

    # ---- anchor predicate ----
    t.ok(looks_like_ssh_start(b"SSH-2.0-x"), "anchor_accepts_ident")
    t.ok(looks_like_ssh_start(b"S"), "anchor_prefix_tolerant")
    # A pre-identification banner line ANCHORS only when the identification string is in
    # the same segment, which is how servers actually write it. A banner line on its own
    # carries no evidence the stream is SSH at all, so it is held rather than anchored —
    # and when the segment carrying the token arrives, that becomes the anchor.
    t.ok(looks_like_ssh_start(b"Authorized users only\r\nSSH-2.0-OpenSSH_9.6p1\r\n"),
         "anchor_accepts_banner_plus_ident")
    t.ok(not looks_like_ssh_start(b"Authorized users only\r\n"),
         "anchor_rejects_banner_alone")
    t.ok(not looks_like_ssh_start(b"enSSH_9.6p1 Ubuntu-3ubuntu13.18\r\n"),
         "anchor_rejects_mid_token_tail")
    d0 = DirReassembler(anchor=looks_like_ssh_start)
    t.eq(d0.add(1000, b"Authorized users only\r\n"), b"", "anchor_holds_banner_only")
    t.eq(d0.add(1023, b"SSH-2.0-OpenSSH_9.6p1\r\n"), b"SSH-2.0-OpenSSH_9.6p1\r\n",
         "anchor_takes_ident_segment_as_start")
    t.ok(not looks_like_ssh_start(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00\x00\x00"),
         "anchor_rejects_tls")
    t.ok(not looks_like_ssh_start(b""), "anchor_rejects_empty")
    d = DirReassembler(anchor=looks_like_ssh_start)
    t.eq(d.add(1010, REAL_SERVER_BANNER[10:]) + d.add(1000, REAL_SERVER_BANNER[:10]),
         REAL_SERVER_BANNER, "anchor_survives_reordered_opening")

    # ---- end-to-end through the Watcher ----
    events = []

    class Cap(Emitter):
        def __init__(self):
            pass

        def emit(self, ev):
            events.append(ev)

    srv_kex = build_kexinit(kex=("curve25519-sha256", STRICT_KEX_SERVER),
                            hostkey=("ssh-ed25519",),
                            enc=("chacha20-poly1305@openssh.com",),
                            mac=("hmac-sha2-256",))
    cli_kex = build_kexinit(kex=("curve25519-sha256",),
                            hostkey=("ssh-ed25519",),
                            enc=("chacha20-poly1305@openssh.com",),
                            mac=("hmac-sha2-256",))
    w = Watcher(Cap())
    w.on_tcp("10.0.0.9", 22, "10.0.0.5", 50000, 1000, REAL_SERVER_BANNER)
    w.on_tcp("10.0.0.5", 50000, "10.0.0.9", 22, 2000, b"SSH-2.0-OpenSSH_9.6p1\r\n")
    w.on_tcp("10.0.0.9", 22, "10.0.0.5", 50000, 1000 + len(REAL_SERVER_BANNER), srv_kex)
    w.on_tcp("10.0.0.5", 50000, "10.0.0.9", 22, 2000 + 23, cli_kex)
    kinds = [e["event"] for e in events]
    t.ok("ident" in kinds, "e2e_ident_event")
    t.ok("session" in kinds, "e2e_session_event")
    sess = [e for e in events if e["event"] == "session"][0]
    t.eq(sess["negotiated"]["cipher_c2s"], "chacha20-poly1305@openssh.com", "e2e_cipher")
    t.eq(sess["negotiated"]["mac_c2s"], IMPLICIT_MAC, "e2e_mac_implicit_under_aead")
    t.eq(sess["strict_kex"], {"client": False, "server": True}, "e2e_strict_kex_view")
    t.ok(len(sess["hassh"]) == 32, "e2e_hassh")
    ecodes = {f["code"] for e in events for f in e.get("findings", [])}
    t.ok("cve_2024_6387_version_in_range" in ecodes, "e2e_regresshion_posture")
    t.ok("cve_2023_48795_terrapin_exposed" in ecodes, "e2e_terrapin")

    # Non-SSH traffic must produce nothing at all.
    events2 = []

    class Cap2(Emitter):
        def __init__(self):
            pass

        def emit(self, ev):
            events2.append(ev)

    w2 = Watcher(Cap2())
    for blob in (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
                 b"\x16\x03\x01\x00\x2c\x01\x00\x00\x28\x03\x03" + b"\x00" * 40,
                 b"\x00" * 64, b"\xff" * 64):
        w2.on_tcp("10.1.1.1", 40000, "10.1.1.2", 22, 1, blob)
    t.eq(events2, [], "non_ssh_traffic_silent")

    # ---- regreSSHion behavioural detection ----
    def grace_run(n, duration, post_bytes=0, **wkw):
        evs = []

        class C(Emitter):
            def __init__(self):
                pass

            def emit(self, ev):
                evs.append(ev)

        w = Watcher(C(), grace_min=5, grace_window=600, grace_high=50, **wkw)
        base = 1_000_000.0
        for i in range(n):
            t0 = base + i * 1.0
            cp = 40000 + i
            w.on_tcp("10.0.0.9", 22, "10.6.6.6", cp, 1000, REAL_SERVER_BANNER, ts=t0)
            w.on_tcp("10.6.6.6", cp, "10.0.0.9", 22, 2000,
                     b"SSH-2.0-OpenSSH_9.6p1\r\n", ts=t0)
            if post_bytes:
                w.on_tcp("10.6.6.6", cp, "10.0.0.9", 22, 2100, b"\x00" * post_bytes,
                         ts=t0 + 1)
            w.on_tcp("10.6.6.6", cp, "10.0.0.9", 22, 3000, b"", flags=0x01,
                     ts=t0 + duration)
        return evs

    # A connection that never completed the cleartext handshake is NOT a grace hold.
    # Without this, a port scanner or a TCP-level prober that simply holds sockets open
    # would be counted as regreSSHion exploitation — the exact false positive that would
    # make this finding worthless in a data centre.
    evs_nohs = []

    class CNH(Emitter):
        def __init__(self):
            pass

        def emit(self, ev):
            evs_nohs.append(ev)

    wnh = Watcher(CNH(), grace_min=5, grace_window=600)
    base_nh = 2_000_000.0
    for i in range(12):
        t0 = base_nh + i
        cp = 45000 + i
        wnh.on_tcp("10.7.7.7", cp, "10.0.0.9", 22, 1000, b"", ts=t0)
        wnh.on_tcp("10.7.7.7", cp, "10.0.0.9", 22, 1000, b"", flags=0x01, ts=t0 + 120.0)
    t.eq([e for e in evs_nohs if e["event"] == "grace_burst"], [],
         "grace_requires_completed_handshake")
    # Half a handshake is still not a handshake: server spoke, client never identified.
    evs_half = []

    class CHF(Emitter):
        def __init__(self):
            pass

        def emit(self, ev):
            evs_half.append(ev)

    whf = Watcher(CHF(), grace_min=5, grace_window=600)
    for i in range(12):
        t0 = base_nh + i
        cp = 46000 + i
        whf.on_tcp("10.0.0.9", 22, "10.7.7.8", cp, 1000, REAL_SERVER_BANNER, ts=t0)
        whf.on_tcp("10.7.7.8", cp, "10.0.0.9", 22, 2000, b"", flags=0x01, ts=t0 + 120.0)
    t.eq([e for e in evs_half if e["event"] == "grace_burst"], [],
         "grace_requires_both_idents")

    evs = grace_run(6, 120.0)
    burst = [e for e in evs if e["event"] == "grace_burst"]
    t.eq(len(burst), 1, "grace_burst_fires_once")
    t.eq(burst[0]["findings"][0]["code"], "cve_2024_6387_grace_timeout_pattern",
         "grace_burst_code")
    t.eq(burst[0]["findings"][0]["severity"], "warn", "grace_burst_warn")
    t.eq(burst[0]["findings"][0]["confidence"], "heuristic", "grace_burst_heuristic")
    t.ok("benign causes" in burst[0]["findings"][0]["confidence_reason"],
         "grace_burst_names_false_positive_sources")
    t.eq(burst[0]["source"], "10.6.6.6", "grace_burst_source")

    # Below the count threshold: silent.
    t.eq([e for e in grace_run(4, 120.0) if e["event"] == "grace_burst"], [],
         "grace_below_threshold_silent")
    # Short connections are not grace holds.
    t.eq([e for e in grace_run(10, 3.0) if e["event"] == "grace_burst"], [],
         "grace_short_connections_ignored")
    # Long-but-not-grace connections are not grace holds either.
    t.eq([e for e in grace_run(10, 600.0) if e["event"] == "grace_burst"], [],
         "grace_long_connections_ignored")
    # A connection carrying a real session is not a grace hold, however long it lasted.
    t.eq([e for e in grace_run(10, 120.0, post_bytes=100000)
          if e["event"] == "grace_burst"], [], "grace_real_session_ignored")
    # Boundary of the tolerance band.
    t.ok([e for e in grace_run(6, 120 * 1.29) if e["event"] == "grace_burst"],
         "grace_inside_upper_tolerance")
    t.eq([e for e in grace_run(6, 120 * 1.31) if e["event"] == "grace_burst"], [],
         "grace_outside_upper_tolerance")
    # A non-default LoginGraceTime is configurable.
    t.ok([e for e in grace_run(6, 30.0, grace_seconds=30) if e["event"] == "grace_burst"],
         "grace_configurable_window")
    # Disabling the tracker silences it without affecting anything else.
    t.eq([e for e in grace_run(10, 120.0, track_grace=False)
          if e["event"] == "grace_burst"], [], "grace_track_disable")

    # ---- robustness: truncation sweep and fuzz ----
    bad = 0
    for cut in range(1, len(pkt)):
        try:
            parse_packets(pkt[:cut])
        except ValueError:
            pass
        except Exception:
            bad += 1
    t.eq(bad, 0, "truncation_sweep_only_valueerror")

    import random
    rnd = random.Random(20260821)
    evs3 = []

    class C3(Emitter):
        def __init__(self):
            pass

        def emit(self, ev):
            evs3.append(ev)

    w3 = Watcher(C3())
    try:
        for _ in range(500):
            n = rnd.randrange(1, 300)
            w3.on_tcp("10.9.9.1", 40000, "10.9.9.2", 22, 1,
                      bytes(rnd.randrange(256) for _ in range(n)))
        for _ in range(200):
            n = rnd.randrange(1, 300)
            w3.on_tcp("10.9.9.3", 40001, "10.9.9.4", 22, 1,
                      REAL_SERVER_BANNER + bytes(rnd.randrange(256) for _ in range(n)))
        t.ok(True, "fuzz_no_exception")
    except Exception as e:
        t.ok(False, "fuzz_no_exception", repr(e))


def _selftest():
    t = _T()
    print("sshwatch self-test")
    _run_selftest_checks(t)
    print("-" * 62)
    print("%d checks, %d failed" % (t.n, t.fail))
    return 0 if t.fail == 0 else 1


def selftest():
    """Structured self-test for the Ragnar aggregator: runs the same checks as the
    --selftest CLI and returns {'success', 'checks':[{'name','pass'}]}."""
    t = _T()
    _run_selftest_checks(t)
    return {'success': t.fail == 0,
            'checks': [{'name': n, 'pass': p} for (n, p) in t.records]}


# ---------------------------------------------------------------------------
def build_argparser():
    p = argparse.ArgumentParser(
        prog="sshwatch",
        description="Passive SSH observer (Ragnar suite), built around CVE-2024-6387.")
    p.add_argument("--iface", "-i", default=None, help="capture interface")
    p.add_argument("--ports", default="22,2222", help="TCP ports to treat as SSH")
    p.add_argument("--bpf", default=None, help="override the generated BPF filter")
    p.add_argument("--out", "-o", default="-", help="JSON-lines output path")
    p.add_argument("--flow-idle", type=int, default=300, help="idle flow expiry (s)")
    p.add_argument("--max-flows", type=int, default=4096, help="max tracked flows")
    p.add_argument("--grace-seconds", type=float, default=120.0,
                   help="expected sshd LoginGraceTime; a passive observer cannot read "
                        "this, so it must be told")
    p.add_argument("--grace-tolerance", type=float, default=0.30,
                   help="fractional band around --grace-seconds counted as a hold")
    p.add_argument("--grace-window", type=int, default=900,
                   help="window (s) over which grace holds are counted per source")
    p.add_argument("--grace-min", type=int, default=20,
                   help="holds within the window before a warn finding")
    p.add_argument("--grace-high", type=int, default=100,
                   help="holds within the window before the finding escalates to high")
    p.add_argument("--no-grace-track", action="store_true",
                   help="disable CVE-2024-6387 behavioural tracking; version posture and "
                        "Terrapin detection are unaffected")
    p.add_argument("--pushover-token", default=os.environ.get("PUSHOVER_TOKEN"))
    p.add_argument("--pushover-user", default=os.environ.get("PUSHOVER_USER"))
    p.add_argument("--min-alert-severity", default="warn",
                   choices=list(SEVERITY_ORDER.keys()))
    p.add_argument("--selftest", action="store_true",
                   help="run the self-test harness and exit")
    return p


def main(argv=None):
    args = build_argparser().parse_args(argv)
    if args.selftest:
        return _selftest()
    if args.iface is None:
        sys.stderr.write("[sshwatch] --iface is required for live capture "
                         "(or use --selftest)\n")
        return 2
    run_live(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
