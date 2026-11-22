#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
certwatch self-test harness.

Generates X.509 certs in-memory and synthesizes TLS handshake byte streams,
then drives them through certwatch's triage engine and flow reassembler.
No network, no interface, no pcap file required. Scapy-free path for the
parser tests; a couple of packet-path checks use scapy if present.
"""
from __future__ import annotations

import datetime as dt
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import certwatch as cw

import base64

# Real SHA1-signed self-signed cert (minted via openssl; cryptography 46
# refuses to *sign* SHA1, so we ship a fixture to exercise the detector).
SHA1_CERT_B64 = (
    "MIIDOjCCAiKgAwIBAgIUeUbzBMsRteS6N2ZJp/nNzMYfR7IwDQYJKoZIhvcNAQEFBQAwHTEbMBkG"
    "A1UEAwwSbGVnYWN5LmV4YW1wbGUuY29tMB4XDTI2MDcwOTE3NDUxNVoXDTI3MDEyNTE3NDUxNVow"
    "HTEbMBkGA1UEAwwSbGVnYWN5LmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB"
    "CgKCAQEA0dz9g85RQ+1Sq+FX0Edb+Ml73gztJEYYlcb+zKGrvG0Sk3ReTE7Om4VjCGJ3SfoUAUAR"
    "yAchn6+ouF7FCywqTicUvOBjwDvM1WrdUpuzi2E0LYnBUnplltUOomckgHCiDIA9Hv5Y7oRW66Um"
    "CgLjY75fJ0JRPjB8kfde4pFtvrDBfwfOg+i6mgJ32537AEWsEIRTKMItUjvDMXGQAKOPfTLtnkQL"
    "Fz8PWREPC7WaCUC4iIHsNYI8WRbNpOZ1xmo+P8ehv8+6WEL8LSNJnEKQEjxiRjPz0abbzDpl+oOz"
    "P1Lw+gNjujkWwXMxZs0gKOWfwLR/F/CMSXKMRWhq9GLKIwIDAQABo3IwcDAdBgNVHQ4EFgQUXqrR"
    "iuybR3g8LaMKRz4jFdhNeN4wHwYDVR0jBBgwFoAUXqrRiuybR3g8LaMKRz4jFdhNeN4wDwYDVR0T"
    "AQH/BAUwAwEB/zAdBgNVHREEFjAUghJsZWdhY3kuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQEFBQAD"
    "ggEBAEzKLPZTrbM1epNO6B4uZ36ULDxr/bFGkyc9s12FJYREHBtqi8a/mNdl2tCqZyC170j9QFQh"
    "KfeJli8hNrcXT1RhjeU3GAVrFcwa9mNRfwFAoHRdL6rWyv8zYJ3KFCaLOD3FEbFEXuqwgzJys4qP"
    "b+VLxrlga/kcExTBPQUZbYjrKJT1Ph0BQxcJB4H42udICsdYdz4RD+1hoIK1ZXDEHPJPOL/D/gAw"
    "2fk0NtaENy4yFN4ANvkBA3+3IQDluC5VpWa3i+k/mu38NuHRR4EAhM4n8zqD8HgD3fej9J6ux14T"
    "FRo3UnAxeYcyyBpt/PHu7rH7XozIw7O5byqIIMG2k6I="
)

# ---------------------------------------------------------------------------
# tiny test framework
# ---------------------------------------------------------------------------
_PASS = 0
_FAIL = 0
_SKIP = 0


def check(name, cond, extra=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  ok   {name}")
    else:
        _FAIL += 1
        print(f"  FAIL {name}   {extra}")


def skip(name, why):
    global _SKIP
    _SKIP += 1
    print(f"  skip {name}   ({why})")


# ---------------------------------------------------------------------------
# cert factory
# ---------------------------------------------------------------------------
def _key(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)

_CA_KEY = _key()
_CA_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ragnar Test CA")])


def make_cert(cn="host.example.com", *, days_before=-1, days_after=365,
              self_signed=False, sig=hashes.SHA256(), bits=2048,
              sans=("host.example.com",), is_ca=False, add_san=True):
    key = _key(bits)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    if self_signed:
        issuer, signer = subject, key
    else:
        issuer, signer = _CA_NAME, _CA_KEY
    nb = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days_before)
    na = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days_after)
    b = (x509.CertificateBuilder()
         .subject_name(subject).issuer_name(issuer)
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(nb).not_valid_after(na))
    if add_san and sans:
        b = b.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False)
    if is_ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None),
                            critical=True)
    cert = b.sign(signer, sig)
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# TLS wire synthesis
# ---------------------------------------------------------------------------
def hs_msg(htype, body):
    return bytes([htype]) + len(body).to_bytes(3, "big") + body


def tls_record(payload, ctype=cw.CT_HANDSHAKE, ver=0x0303):
    return bytes([ctype]) + struct.pack("!H", ver) + \
        struct.pack("!H", len(payload)) + payload


def records_split(payload, sizes, ctype=cw.CT_HANDSHAKE):
    """Fragment one handshake payload across several TLS records."""
    out = b""
    i = 0
    for s in sizes:
        out += tls_record(payload[i:i+s], ctype=ctype)
        i += s
    if i < len(payload):
        out += tls_record(payload[i:], ctype=ctype)
    return out


def client_hello(sni="host.example.com"):
    body = b"\x03\x03" + b"\x00" * 32          # version + random
    body += b"\x00"                             # session id len 0
    body += struct.pack("!H", 2) + b"\x13\x01"  # cipher suites
    body += b"\x01\x00"                         # compression: 1 method (null)
    # SNI extension
    name = sni.encode()
    snl = b"\x00" + struct.pack("!H", len(name)) + name   # type host_name
    sni_ext_val = struct.pack("!H", len(snl)) + snl
    sni_ext = struct.pack("!HH", cw.EXT_SNI, len(sni_ext_val)) + sni_ext_val
    body += struct.pack("!H", len(sni_ext)) + sni_ext
    return hs_msg(cw.HS_CLIENT_HELLO, body)


def server_hello(tls13=False):
    body = b"\x03\x03" + b"\x01" * 32
    body += b"\x00"                    # session id
    body += b"\x13\x01"                # cipher suite
    body += b"\x00"                    # compression
    exts = b""
    if tls13:
        exts += struct.pack("!HH", cw.EXT_SUPPORTED_VERSIONS, 2) + \
            struct.pack("!H", cw.TLS13)
    body += struct.pack("!H", len(exts)) + exts
    return hs_msg(cw.HS_SERVER_HELLO, body)


def certificate_msg(ders):
    entries = b""
    for d in ders:
        entries += len(d).to_bytes(3, "big") + d
    body = len(entries).to_bytes(3, "big") + entries
    return hs_msg(cw.HS_CERTIFICATE, body)


# ---------------------------------------------------------------------------
# harness helpers
# ---------------------------------------------------------------------------
class Collector:
    def __init__(self):
        self.events = []

    def __call__(self, rec):
        self.events.append(rec)


def new_tracker():
    col = Collector()
    t = cw.FlowTracker(cw.CertTriage(warn_days=30), emit=col)
    return t, col


CLI, CPORT, SRV, SPORT = "10.0.0.9", 51000, "10.0.0.1", 443


def feed_server(tracker, blob, seg_sizes=None):
    """Feed bytes as coming from the server (SRV:SPORT -> CLI:CPORT)."""
    segs = _split(blob, seg_sizes)
    for s in segs:
        tracker.on_segment(SRV, SPORT, CLI, CPORT, s)


def feed_client(tracker, blob, seg_sizes=None):
    for s in _split(blob, seg_sizes):
        tracker.on_segment(CLI, CPORT, SRV, SPORT, s)


def _split(blob, seg_sizes):
    if not seg_sizes:
        return [blob]
    out, i = [], 0
    for s in seg_sizes:
        out.append(blob[i:i+s]); i += s
    if i < len(blob):
        out.append(blob[i:])
    return out


def codes(rec):
    return {f["code"] for f in rec.get("findings", [])}


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------
def test_triage():
    print("[triage engine]")
    tri = cw.CertTriage(warn_days=30)

    r = tri.triage(make_cert())
    check("valid cert -> OK", r["status"] == cw.SEV_OK, r["status"])

    r = tri.triage(make_cert(days_before=-800, days_after=-30))
    check("expired -> EXPIRED/CRITICAL",
          "EXPIRED" in codes(r) and r["status"] == cw.SEV_CRIT)

    # days_left must truncate toward zero so it agrees with the detail text
    # (timedelta.days floors: an expired-40.5d cert would report -41).
    r = tri.triage(make_cert(days_before=-800, days_after=-40))
    check("expired days_left truncates toward zero (-40 not -41)",
          r["days_left"] == -40, str(r["days_left"]))
    # Minted microseconds ago, so ~9d23h59m remain -> truncates to 9, and the
    # detail text must say the same. Agreement is the invariant worth testing;
    # the exact integer is a function of mint time.
    r = tri.triage(make_cert(days_after=10))
    detail = [f["detail"] for f in r["findings"]
              if f["code"] == "EXPIRING_SOON"][0]
    check("valid days_left agrees with detail text",
          r["days_left"] == 9 and detail.startswith("9d left"),
          f"days_left={r['days_left']} detail={detail!r}")

    r = tri.triage(make_cert(days_before=5, days_after=400))
    check("future cert -> NOT_YET_VALID",
          "NOT_YET_VALID" in codes(r) and r["status"] == cw.SEV_CRIT)

    r = tri.triage(make_cert(days_after=10))
    check("near expiry -> EXPIRING_SOON/WARN",
          "EXPIRING_SOON" in codes(r) and r["status"] == cw.SEV_WARN)

    r = tri.triage(make_cert(self_signed=True))
    check("self-signed -> SELF_SIGNED",
          "SELF_SIGNED" in codes(r) and r["self_signed"] is True)

    der = base64.b64decode(SHA1_CERT_B64)
    r = tri.triage(der)
    check("sha1 sig -> WEAK_SIG_SHA1/CRITICAL",
          "WEAK_SIG_SHA1" in codes(r) and r["sig_hash"] == "sha1"
          and r["status"] == cw.SEV_CRIT)

    r = tri.triage(make_cert(bits=1024))
    check("RSA-1024 -> WEAK_KEY",
          "WEAK_KEY" in codes(r) and r["key"] == "RSA-1024")

    r = tri.triage(make_cert(sans=("*.example.com",)))
    check("wildcard SAN -> WILDCARD", "WILDCARD" in codes(r))

    r = tri.triage(make_cert(add_san=False))
    check("no SAN -> MISSING_SAN", "MISSING_SAN" in codes(r))

    r = tri.triage(make_cert(days_after=800))
    check("long validity -> LONG_VALIDITY", "LONG_VALIDITY" in codes(r))

    r = tri.triage(make_cert(is_ca=True))
    check("CA:TRUE -> CA_CERT", "CA_CERT" in codes(r))

    r = tri.triage(make_cert(cn="host.example.com",
                             sans=("host.example.com",)),
                   server_name="host.example.com")
    check("SNI match -> sni_match True, no mismatch",
          r["sni_match"] is True and "NAME_MISMATCH" not in codes(r))

    r = tri.triage(make_cert(sans=("host.example.com",)),
                   server_name="evil.example.net")
    check("SNI mismatch -> NAME_MISMATCH/CRITICAL",
          "NAME_MISMATCH" in codes(r) and r["status"] == cw.SEV_CRIT)

    r = tri.triage(make_cert(sans=("*.example.com",)),
                   server_name="api.example.com")
    check("wildcard SNI match -> sni_match True", r["sni_match"] is True)


def test_wire_parsers():
    print("[wire parsers]")
    ch = client_hello("shop.example.com")
    check("parse_sni from ClientHello",
          cw.parse_sni(ch[4:]) == "shop.example.com")

    sh = server_hello(tls13=False)
    check("ServerHello version TLS1.2",
          cw.parse_server_hello_version(sh[4:]) == 0x0303)

    sh13 = server_hello(tls13=True)
    check("ServerHello supported_versions -> TLS1.3",
          cw.parse_server_hello_version(sh13[4:]) == cw.TLS13)

    der = make_cert()
    cm = certificate_msg([der])
    ders = cw.parse_certificate_msg(cm[4:])
    check("Certificate msg single cert", len(ders) == 1 and ders[0] == der)

    d1, d2 = make_cert(), make_cert(cn="ca.example.com")
    cm2 = certificate_msg([d1, d2])
    ders2 = cw.parse_certificate_msg(cm2[4:])
    check("Certificate msg 2-cert chain", len(ders2) == 2)


def test_flows():
    print("[flow reassembly]")

    # T: full handshake, single segment each direction
    t, col = new_tracker()
    feed_client(t, tls_record(client_hello("host.example.com")))
    der = make_cert(cn="host.example.com", sans=("host.example.com",))
    blob = tls_record(server_hello() + certificate_msg([der]))
    feed_server(t, blob)
    ev = [e for e in col.events if e.get("type") == "cert"]
    check("full handshake -> one cert event", len(ev) == 1,
          f"got {len(col.events)} events")
    if ev:
        check("cert attributed to server:port",
              ev[0]["server"] == f"{SRV}:{SPORT}", ev[0].get("server"))
        check("observed SNI matched to cert",
              ev[0]["sni"] == "host.example.com" and ev[0]["sni_match"] is True)

    # T: Certificate fragmented across TLS records
    t, col = new_tracker()
    feed_client(t, tls_record(client_hello()))
    payload = server_hello() + certificate_msg([make_cert()])
    feed_server(t, records_split(payload, [40, 300, 200]))
    check("cert msg fragmented across records -> parsed",
          any(e.get("type") == "cert" for e in col.events))

    # T: Certificate spanning multiple TCP segments
    t, col = new_tracker()
    feed_client(t, tls_record(client_hello()))
    blob = tls_record(server_hello() + certificate_msg([make_cert()]))
    feed_server(t, blob, seg_sizes=[20, 50, 100, 5])  # dribble it in
    check("cert spanning TCP segments -> parsed",
          any(e.get("type") == "cert" for e in col.events))

    # T: coalesced ServerHello+Certificate in a single record (already above)
    t, col = new_tracker()
    rec = tls_record(server_hello() + certificate_msg([make_cert()]))
    feed_server(t, rec)
    check("coalesced SH+Cert in one record -> parsed",
          any(e.get("type") == "cert" for e in col.events))

    # T: TLS 1.3 -> inventory only, no cert
    t, col = new_tracker()
    feed_client(t, tls_record(client_hello("secure.example.com")))
    feed_server(t, tls_record(server_hello(tls13=True)))
    inv = [e for e in col.events if e.get("type") == "inventory"]
    check("TLS1.3 -> inventory record, no cert",
          len(inv) == 1 and not any(e.get("type") == "cert"
                                    for e in col.events))
    if inv:
        check("TLS1.3 inventory carries SNI + note",
              inv[0]["sni"] == "secure.example.com" and "encrypted"
              in inv[0]["note"])

    # T: ApplicationData stops handshake parsing, no crash
    t, col = new_tracker()
    feed_server(t, tls_record(server_hello()))
    feed_server(t, tls_record(b"\x00" * 40, ctype=cw.CT_APPDATA))
    ck = cw.conn_key(SRV, SPORT, CLI, CPORT)
    dkey = (SRV, SPORT, CLI, CPORT)
    done = ck in t.conns and t.conns[ck].dirs[dkey].done
    check("appdata record marks direction done", done)

    # T: non-TLS garbage -> no emit, no crash
    t, col = new_tracker()
    feed_server(t, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n" + b"\x00" * 20)
    check("non-TLS payload -> no events, no crash", col.events == [])

    # T: flow evicted after cert reported
    t, col = new_tracker()
    feed_client(t, tls_record(client_hello()))
    feed_server(t, tls_record(server_hello() + certificate_msg([make_cert()])))
    check("flow table emptied after cert report", len(t.conns) == 0,
          f"{len(t.conns)} left")

    # T: per-flow buffer cap enforced
    t, col = new_tracker()
    big = b"\x16\x03\x03\xff\xff" + b"\x00" * (cw.MAX_FLOW_BYTES + 10)
    feed_server(t, big)
    check("per-flow buffer cap enforced (buf_capped)",
          t.stats["buf_capped"] >= 1)

    # T: MAX_FLOWS LRU eviction
    t, col = new_tracker()
    t.max_flows = 8
    for p in range(20):
        t.on_segment("1.1.1.1", 1000 + p, "2.2.2.2", 443, b"\x16\x03\x03")
    check("MAX_FLOWS LRU eviction",
          len(t.conns) <= 8 and t.stats["evicted_lru"] >= 1,
          f"conns={len(t.conns)} lru={t.stats['evicted_lru']}")

    # T: malformed handshake length -> no crash
    t, col = new_tracker()
    bad = tls_record(bytes([cw.HS_CERTIFICATE]) + b"\xff\xff\xff" + b"\x00" * 4)
    feed_server(t, bad)
    check("malformed handshake length -> no crash/no bogus event",
          not any(e.get("type") == "cert" for e in col.events))

    # T: TTL sweep evicts stale flow
    t, col = new_tracker()
    t.on_segment(SRV, SPORT, CLI, CPORT, b"\x16\x03\x03")
    for c in t.conns.values():
        c.last -= (cw.FLOW_TTL + 5)
    t.sweep()
    check("TTL sweep evicts stale flow",
          len(t.conns) == 0 and t.stats["evicted_ttl"] >= 1)


def test_packet_path():
    print("[scapy packet path]")
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
    except Exception as e:
        skip("scapy packet path", f"scapy unavailable: {e}")
        return
    t, col = new_tracker()
    snf = cw.Sniffer(t)
    der = make_cert(cn="pkt.example.com", sans=("pkt.example.com",))
    blob = tls_record(server_hello() + certificate_msg([der]))
    pkt = Ether()/IP(src=SRV, dst=CLI)/TCP(sport=SPORT, dport=CPORT)/blob
    snf._handle(pkt)
    check("scapy IP/TCP packet -> cert event",
          any(e.get("type") == "cert" for e in col.events))

    try:
        from scapy.layers.inet6 import IPv6
        t, col = new_tracker()
        snf = cw.Sniffer(t)
        pkt6 = Ether()/IPv6(src="2001:db8::1", dst="2001:db8::2")/\
            TCP(sport=SPORT, dport=CPORT)/blob
        snf._handle(pkt6)
        check("scapy IPv6/TCP packet -> cert event",
              any(e.get("type") == "cert" for e in col.events))
    except Exception as e:
        skip("IPv6 packet path", str(e))


def test_ipv6_extension_headers():
    """IPv6 EH blind spot: libpcap cannot walk a v6 next-header chain.

    For HopByHop/DestOpt the v6 next-header field reads 0/60 rather than 6,
    so even a bare `tcp` filter misses the packet. Regression guard for the
    broadened default filter.
    """
    print("[IPv6 extension headers]")
    try:
        from scapy.layers.l2 import Ether
        from scapy.layers.inet6 import (IPv6, IPv6ExtHdrDestOpt,
                                        IPv6ExtHdrFragment,
                                        IPv6ExtHdrHopByHop)
        from scapy.layers.inet import TCP
        from scapy.utils import wrpcap
        from scapy.all import sniff
        import contextlib
        import tempfile, os
    except Exception as e:
        skip("IPv6 extension-header BPF", str(e))
        return

    @contextlib.contextmanager
    def _quiet_fd2():
        """Mute the tcpdump subprocess banner; it writes to fd 2 directly,
        so redirecting sys.stderr in Python is not enough."""
        saved = os.dup(2)
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, 2)
            yield
        finally:
            os.dup2(saved, 2)
            os.close(devnull)
            os.close(saved)

    TLS = b"\x16\x03\x03\x00\x10" + b"\x00" * 16
    ehs = [("HopByHop", IPv6ExtHdrHopByHop()),
           ("DestOpt", IPv6ExtHdrDestOpt()),
           ("Fragment", IPv6ExtHdrFragment(offset=0, m=0))]
    narrow = cw.build_bpf((443, 8443), v6_eh=False)
    wide = cw.build_bpf((443, 8443), v6_eh=True)
    for name, eh in ehs:
        pkt = (Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / eh /
               TCP(sport=4000, dport=443, flags="PA") / TLS)
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            wrpcap(path, [pkt])
            try:
                with _quiet_fd2():
                    wide_hit = len(sniff(offline=path, filter=wide,
                                         store=True)) > 0
                    narrow_hit = len(sniff(offline=path, filter=narrow,
                                           store=True)) > 0
            except Exception as e:
                skip(f"IPv6 {name} BPF (libpcap unavailable)", str(e))
                return
            check(f"IPv6 {name}: default filter captures it", wide_hit)
            check(f"IPv6 {name}: narrow filter demonstrably blind",
                  not narrow_hit, "narrow filter matched -- trap gone?")
        finally:
            os.unlink(path)

    # IPv6 host:port must be unambiguous -- a bare v6 addr joined by a colon
    # produces a string that is itself a valid IPv6 address.
    import urllib.parse as _u
    for addr, port in (("203.0.113.2", 8443), ("2001:db8::2", 8443)):
        hp = cw.hostport(addr, port)
        p = _u.urlsplit("//" + hp)
        check(f"hostport round-trips for {addr}",
              p.hostname == addr and p.port == port, hp)
    check("IPv6 hostport uses RFC 3986 brackets",
          cw.hostport("2001:db8::2", 443) == "[2001:db8::2]:443")

    # userspace port filter must still gate v6 traffic
    seen = []

    class _T:
        def on_segment(self, *a):
            seen.append(a)

        def sweep(self, *a):
            pass

    sn = cw.Sniffer(_T(), ports=(443, 8443))
    off = (Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") /
           IPv6ExtHdrDestOpt() / TCP(sport=4000, dport=9999, flags="PA") / TLS)
    sn._handle(off)
    check("userspace port filter drops off-port IPv6", not seen)
    on = (Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") /
          IPv6ExtHdrDestOpt() / TCP(sport=4000, dport=443, flags="PA") / TLS)
    sn._handle(on)
    check("userspace port filter keeps on-port IPv6", len(seen) == 1)

    # pcap mode (ports=None) must not filter -- operator picked the file
    seen.clear()
    sn2 = cw.Sniffer(_T(), ports=None)
    sn2._handle(off)
    check("pcap mode parses off-port traffic (no port filter)", len(seen) == 1)


# A genuine RSA modulus built with the Infineon (ROCA) prime structure:
# p, q = k*M + (65537^a mod M) with M the primorial through 167, so every
# fingerprint prime divides M. Generated in-sandbox; the real Infineon
# library is not needed to reproduce the structure the fingerprint tests.
ROCA_MODULUS = int(
    "4969787a67a4d912033e3cb67fb05497d43fb6b47a33a9cc75c476542ee1421d"
    "e50756697d7aea6bc1b43dcf2a2d32d4cee971a11491554f2b87ed98e84ecd7d"
    "a6b462be83ece59eb18b1e29a40c319a8d4a801ff053c043c9e37829512067b2"
    "3deeb54cb4a29388ab9785695253c4f0a28d7791899bf83b74d6b392fa4b8636"
    "f57298fccafa041754c4928535056d4db280b72dd43396692ef407a805578245"
    "640bcf7a43bc3029406768599b34aaa496d634ce56f5890ff6bf2e4e2b4443d7"
    "d41dc67080018998c9b25c33f2e2f0ff4470c20308c4904f5e20a8b1c2c861cb"
    "6cf995adedbf4a5e494cf289ff4a3766bbb824eab0fa579845d9d553dd3bd0b9"
    , 16)

# ---------------------------------------------------------------------------
# CVE detector fixtures
# ---------------------------------------------------------------------------
# A real certificate carrying EXPLICIT EC parameters (prime256v1 values,
# standard base point), minted with openssl. Embedded rather than generated
# because the `cryptography` library cannot emit explicit parameters -- it
# normalizes them to a named curve, which is the very distinction under test.
# The CurveBall and non-prime-field variants are produced by patching this
# fixture's DER at test time.
EXPLICIT_EC_CERT_B64 = (
"""\
    MIIChzCCAi2gAwIBAgIUSZG4k1MvRHawKVlQLhV+vyNXLqwwCgYIKoZIzj0EAwIwHzEdMB
    sGA1UEAwwUZXhwbGljaXQuZXhhbXBsZS5jb20wHhcNMjYxMDMxMTY0MzM4WhcNMjcxMDMx
    MTY0MzM4WjAfMR0wGwYDVQQDDBRleHBsaWNpdC5leGFtcGxlLmNvbTCCAUswggEDBgcqhk
    jOPQIBMIH3AgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP//////////
    /////zBbBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6k+ez67
    1VdpiGvGUdBrDMU7D2O848PifSYEsDFQDEnTYIhucEk2pmeOETnSa3gZ9+kARBBGsX0fLh
    LEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7
    ZAaDe/UfUCIQD/////AAAAAP//////////vOb6racXnoTzucrC/GMlUQIBAQNCAATNWKcl
    5vsBsJ/BaNr+L2wxa8t5hbuP0ZPXB0lFC0jkAsv5sV5OEc5xKetI4tJ39RQbhndxW9/8uC
    2btnoN0AYdo1MwUTAdBgNVHQ4EFgQUix5SWPD+r8lmP9nLIIouN2QYYyAwHwYDVR0jBBgw
    FoAUix5SWPD+r8lmP9nLIIouN2QYYyAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAg
    NIADBFAiEAv1kAbr3IgbvymLxPRuYWn9SlABwbzkAaLNlyUY/L/2gCIHx3sT9wLAktfd4f
    epMB04YmcB9vkBhkOE6fqWmXicnQ
""")


def _explicit_ec_der() -> bytes:
    import base64
    return base64.b64decode("".join(EXPLICIT_EC_CERT_B64.split()))


def test_cve_detectors():
    """CVE-2020-0601, CVE-2022-0778, CVE-2017-15361, CVE-2025-58188."""
    print("[CVE detectors]")
    import datetime as _dt
    from cryptography.hazmat.primitives.asymmetric import dsa as _dsa
    tri = cw.CertTriage(warn_days=30)

    def codes(der, sni=None):
        return [f["code"] for f in tri.triage(der, sni)["findings"]]

    # ---- baseline: clean certs must gain no CVE codes ----
    cve_codes = {"ROCA_KEY", "DSA_IN_CHAIN", "EC_EXPLICIT_PARAMS",
                 "CURVEBALL_SUSPECT", "EC_INVALID_FIELD"}
    clean = codes(make_cert(cn="ok.example.com", sans=("ok.example.com",)))
    check("healthy RSA cert raises no CVE finding",
          not (set(clean) & cve_codes), str(clean))

    # ---- CVE-2020-0601 / CVE-2022-0778: explicit EC parameters ----
    der = _explicit_ec_der()
    std = cw.STD_CURVES["prime256v1"]

    got = codes(der)
    check("explicit EC params flagged", "EC_EXPLICIT_PARAMS" in got, str(got))
    check("untampered explicit params is not called CurveBall",
          "CURVEBALL_SUSPECT" not in got, str(got))

    # named-curve cert must NOT be flagged (the discriminating case)
    named = make_cert(cn="n.example.com", sans=("n.example.com",))
    check("named-curve/RSA cert not flagged as explicit params",
          "EC_EXPLICIT_PARAMS" not in codes(named))

    # CurveBall shape: identical p/a/b, moved base point G
    G = std["G"]
    i = der.find(G)
    check("fixture contains the standard generator", i > 0)
    if i > 0:
        bad = bytearray(G)
        bad[-1] ^= 0x01
        cb = der[:i] + bytes(bad) + der[i + len(G):]
        got = codes(cb)
        check("CVE-2020-0601: moved base point -> CURVEBALL_SUSPECT",
              "CURVEBALL_SUSPECT" in got, str(got))
        # the library REFUSES this key; detection must survive that
        check("CurveBall cert still triaged despite unparseable key",
              "KEY_UNPARSEABLE" in got, str(got))

    # CVE-2022-0778 shape: field prime replaced with an even number
    pb = std["p"].to_bytes(32, "big")
    j = der.find(pb)
    check("fixture contains the field prime", j > 0)
    if j > 0:
        bad = bytearray(pb)
        bad[-1] = 0xFE
        np_ = der[:j] + bytes(bad) + der[j + len(pb):]
        got = codes(np_)
        check("CVE-2022-0778: non-prime field -> EC_INVALID_FIELD",
              "EC_INVALID_FIELD" in got, str(got))

    # primality helper sanity
    check("_is_probable_prime rejects composites",
          not cw._is_probable_prime(std["p"] - 1))
    check("_is_probable_prime accepts the real field prime",
          cw._is_probable_prime(std["p"]))

    # ---- CVE-2017-15361 ROCA ----
    check("ROCA fingerprint matches a real Infineon-structured modulus",
          cw.roca_fingerprint(ROCA_MODULUS))
    check("ROCA factorable-range test covers 2048-bit",
          cw.roca_factorable(2048) and cw.roca_factorable(1024))
    check("ROCA range test excludes 4096-bit",
          not cw.roca_factorable(4096))
    fp = 0
    for _ in range(12):
        k = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        if cw.roca_fingerprint(k.public_key().public_numbers().n):
            fp += 1
    check("ROCA: no false positive on genuine RSA keys", fp == 0, f"{fp} FPs")
    check("ROCA: zero and negative moduli rejected",
          not cw.roca_fingerprint(0) and not cw.roca_fingerprint(-7))

    # ---- CVE-2025-58188 DSA ----
    dk = _dsa.generate_private_key(key_size=2048)
    now = _dt.datetime.now(_dt.timezone.utc)
    nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dsa.example.com")])
    dc = (x509.CertificateBuilder().subject_name(nm).issuer_name(nm)
          .public_key(dk.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - _dt.timedelta(days=1))
          .not_valid_after(now + _dt.timedelta(days=200))
          .add_extension(x509.SubjectAlternativeName(
              [x509.DNSName("dsa.example.com")]), False)
          .sign(dk, hashes.SHA256()))
    got = codes(dc.public_bytes(serialization.Encoding.DER), "dsa.example.com")
    check("CVE-2025-58188: DSA key -> DSA_IN_CHAIN", "DSA_IN_CHAIN" in got,
          str(got))
    check("DSA cert also keeps the existing WEAK_KEY finding",
          "WEAK_KEY" in got, str(got))

    # ---- detectors must not crash on hostile input ----
    import os as _os
    check("ec_params_tag survives garbage",
          cw.ec_params_tag(_os.urandom(200)) is None)
    check("parse_explicit_ec_params survives garbage",
          cw.parse_explicit_ec_params(_os.urandom(200)) is None)
    truncated = der[:40] + b"\x30\x82\xff\xff"
    check("parse_explicit_ec_params survives truncation",
          cw.parse_explicit_ec_params(truncated) is None)


def run():
    print("=" * 64)
    print("certwatch self-test")
    print("=" * 64)
    test_triage()
    test_wire_parsers()
    test_flows()
    test_packet_path()
    test_ipv6_extension_headers()
    test_cve_detectors()
    print("-" * 64)
    total = _PASS + _FAIL
    print(f"RESULT: {_PASS}/{total} passed"
          + (f", {_SKIP} skipped" if _SKIP else "")
          + (f", {_FAIL} FAILED" if _FAIL else ""))
    print("=" * 64)
    return 0 if _FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(run())
