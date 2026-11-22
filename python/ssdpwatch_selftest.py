#!/usr/bin/env python3
"""ssdpwatch self-test tier.

Every finding code must fire on a positive vector in BOTH address families
where the code is family-applicable, and must stay silent on the clean
negative control.
"""
from __future__ import annotations

import sys
import time

from ssdpwatch import (Config, Packet, SSDPWatch, REGISTRY, parse_httpu,
                       url_host_port, split_callbacks, canon, Scope)

T0 = 1_700_000_000.0

V4 = dict(host="192.168.1.50", router="192.168.1.1", mcast="239.255.255.250",
          off="203.0.113.45", other="192.168.1.77")
V6 = dict(host="fd00:abcd::50", router="fd00:abcd::1", mcast="ff02::c",
          off="2001:db8:bad::45", other="fd00:abcd::77")


def lit(addr: str) -> str:
    return f"[{addr}]" if ":" in addr else addr


def udp(payload: str, src, dst, sport=49152, dport=1900, ttl=2, ts=T0):
    return Packet(ts=ts, proto="udp", src=src, dst=dst, sport=sport,
                  dport=dport, payload=payload.replace("\n", "\r\n").encode(),
                  ttl=ttl)


def tcp(payload: str, src, dst, sport=51000, dport=49152, ts=T0):
    return Packet(ts=ts, proto="tcp", src=src, dst=dst, sport=sport,
                  dport=dport, payload=payload.replace("\n", "\r\n").encode(),
                  ttl=64)


def run(packets, cfg=None):
    e = SSDPWatch(cfg or Config())
    for p in packets:
        e.observe(p)
    return e


def codes(e):
    return {f.code for f in e.findings}


# ---------------------------------------------------------------- vectors

def v_callstranger(A):                                   # SSDP-001
    body = (f"SUBSCRIBE /evt/svc1 HTTP/1.1\n"
            f"HOST: {lit(A['router'])}:49152\n"
            f"CALLBACK: <http://{lit(A['off'])}:8888/cb>\n"
            f"NT: upnp:event\nTIMEOUT: Second-1800\n\n")
    return [tcp(body, A["host"], A["router"])]


def v_callback_mismatch(A):                              # SSDP-002
    body = (f"SUBSCRIBE /evt/svc1 HTTP/1.1\n"
            f"CALLBACK: <http://{lit(A['other'])}:9000/cb>\n"
            f"NT: upnp:event\n\n")
    return [tcp(body, A["host"], A["router"])]


def v_callback_fanout(A):                                # SSDP-003
    cbs = " ".join(f"<http://{lit(A['off'])}:{p}/cb>" for p in (8001, 8002, 8003))
    body = f"SUBSCRIBE /evt/svc1 HTTP/1.1\nCALLBACK: {cbs}\nNT: upnp:event\n\n"
    return [tcp(body, A["host"], A["router"])]


def v_callback_scheme(A):                                # SSDP-004
    body = (f"SUBSCRIBE /evt/svc1 HTTP/1.1\n"
            f"CALLBACK: <gopher://{lit(A['host'])}:70/x>\n"
            f"NT: upnp:event\n\n")
    return [tcp(body, A["host"], A["router"])]


def v_timeout(A):                                        # SSDP-005
    body = (f"SUBSCRIBE /evt/svc1 HTTP/1.1\n"
            f"CALLBACK: <http://{lit(A['host'])}:9000/cb>\n"
            f"NT: upnp:event\nTIMEOUT: Second-infinite\n\n")
    return [tcp(body, A["host"], A["router"])]


def v_unicast_msearch_offlink(A):                        # SSDP-010
    body = ('M-SEARCH * HTTP/1.1\n'
            f'HOST: {lit(A["host"])}:1900\n'
            'MAN: "ssdp:discover"\nMX: 2\nST: upnp:rootdevice\n\n')
    return [udp(body, A["off"], A["host"])]


def v_ssdp_all(A):                                       # SSDP-011
    """Unicast ssdp:all = enumerate one chosen host. The multicast form is
    normal startup discovery and lives in the clean control instead."""
    body = ('M-SEARCH * HTTP/1.1\n'
            f'HOST: {lit(A["router"])}:1900\n'
            'MAN: "ssdp:discover"\nMX: 3\nST: ssdp:all\n\n')
    return [udp(body, A["host"], A["router"], dport=1900)]


def v_amplifier(A):                                      # SSDP-012
    body = ("HTTP/1.1 200 OK\nCACHE-CONTROL: max-age=1800\n"
            f"LOCATION: http://{lit(A['host'])}:49152/desc.xml\n"
            "ST: upnp:rootdevice\nUSN: uuid:aaa::upnp:rootdevice\n\n")
    return [udp(body, A["host"], A["off"], sport=1900, dport=35000)]


def v_ratio(A):                                          # SSDP-013
    """One responder repeating itself at one victim -- the amplification
    multiplier. Distinct devices answering are NOT this (see clean control)."""
    pkts = [udp('M-SEARCH * HTTP/1.1\n'
                f'HOST: {lit(A["mcast"])}:1900\n'
                'MAN: "ssdp:discover"\nMX: 1\nST: ssdp:all\n\n',
                A["host"], A["mcast"], sport=40000, ts=T0)]
    for i in range(8):
        body = ("HTTP/1.1 200 OK\n"
                f"LOCATION: http://{lit(A['router'])}:49152/desc.xml\n"
                "ST: upnp:rootdevice\n"
                "USN: uuid:one-device::upnp:rootdevice\n\n")
        pkts.append(udp(body, A["router"], A["host"], sport=1900,
                        dport=40000, ts=T0 + 0.1 * i))
    return pkts


def v_unsolicited(A):                                    # SSDP-024
    """A 200 OK is only ever a reply to M-SEARCH. One arriving at a host
    that never searched is reflected traffic landing on the victim."""
    seen = udp("NOTIFY * HTTP/1.1\n"
               f"HOST: {lit(A['mcast'])}:1900\n"
               f"LOCATION: http://{lit(A['host'])}:49152/desc.xml\n"
               "NT: upnp:rootdevice\nNTS: ssdp:alive\n"
               "USN: uuid:victim::upnp:rootdevice\n\n",
               A["host"], A["mcast"], ts=T0)
    reflected = udp("HTTP/1.1 200 OK\n"
                    f"LOCATION: http://{lit(A['router'])}:49152/d.xml\n"
                    "ST: upnp:rootdevice\nUSN: uuid:r::upnp:rootdevice\n\n",
                    A["router"], A["host"], sport=1900, dport=33333,
                    ts=T0 + 1)
    return [seen, reflected]


def v_storm(A):                                          # SSDP-014
    pkts = []
    for i in range(45):
        body = ("HTTP/1.1 200 OK\n"
                f"LOCATION: http://{lit(A['router'])}:49152/d{i}.xml\n"
                f"ST: upnp:rootdevice\nUSN: uuid:s{i}::upnp:rootdevice\n\n")
        pkts.append(udp(body, A["router"], A["host"], sport=1900,
                        dport=41000, ts=T0 + 0.05 * i))
    return pkts


def v_ttl(A):                                            # SSDP-015
    body = ('M-SEARCH * HTTP/1.1\n'
            f'HOST: {lit(A["mcast"])}:1900\n'
            'MAN: "ssdp:discover"\nMX: 2\nST: upnp:rootdevice\n\n')
    return [udp(body, A["host"], A["mcast"], ttl=32)]   # >4 = escape


def v_v6_scope(A):                                       # SSDP-016 (v6 only)
    body = ('M-SEARCH * HTTP/1.1\nHOST: [ff0e::c]:1900\n'
            'MAN: "ssdp:discover"\nMX: 2\nST: ssdp:all\n\n')
    return [udp(body, A["host"], "ff0e::c")]


def v_notify_spoof(A):                                   # SSDP-017
    body = ("NOTIFY * HTTP/1.1\n"
            f"HOST: {lit(A['mcast'])}:1900\n"
            f"LOCATION: http://{lit(A['other'])}:49152/desc.xml\n"
            "NT: upnp:rootdevice\nNTS: ssdp:alive\n"
            "USN: uuid:spoof::upnp:rootdevice\n\n")
    return [udp(body, A["host"], A["mcast"])]


def v_byebye_storm(A):                                   # SSDP-018
    pkts = []
    for i in range(25):
        body = ("NOTIFY * HTTP/1.1\n"
                f"HOST: {lit(A['mcast'])}:1900\n"
                "NT: upnp:rootdevice\nNTS: ssdp:byebye\n"
                f"USN: uuid:gone{i}::upnp:rootdevice\n\n")
        pkts.append(udp(body, A["host"], A["mcast"], ts=T0 + 0.2 * i))
    return pkts


def v_bootid_regress(A):                                 # SSDP-019
    def n(boot, ts):
        return udp("NOTIFY * HTTP/1.1\n"
                   f"HOST: {lit(A['mcast'])}:1900\n"
                   f"LOCATION: http://{lit(A['host'])}:49152/desc.xml\n"
                   "NT: upnp:rootdevice\nNTS: ssdp:alive\n"
                   "USN: uuid:stable::upnp:rootdevice\n"
                   f"BOOTID.UPNP.ORG: {boot}\n\n",
                   A["host"], A["mcast"], ts=ts)
    return [n(90, T0), n(12, T0 + 5)]


def v_bad_man(A):                                        # SSDP-020
    body = ('M-SEARCH * HTTP/1.1\n'
            f'HOST: {lit(A["mcast"])}:1900\nMX: 2\nST: upnp:rootdevice\n\n')
    return [udp(body, A["host"], A["mcast"])]


def v_bad_mx(A):                                         # SSDP-021
    body = ('M-SEARCH * HTTP/1.1\n'
            f'HOST: {lit(A["mcast"])}:1900\n'
            'MAN: "ssdp:discover"\nMX: 120\nST: upnp:rootdevice\n\n')
    return [udp(body, A["host"], A["mcast"])]


def v_malformed(A):                                      # SSDP-022
    return [Packet(ts=T0, proto="udp", src=A["host"], dst=A["mcast"],
                   sport=49152, dport=1900, ttl=2,
                   payload=b"\x00\x01\x02 not http at all \xff")]


def v_location_offlink(A):                               # SSDP-023
    body = ("NOTIFY * HTTP/1.1\n"
            f"HOST: {lit(A['mcast'])}:1900\n"
            f"LOCATION: http://{lit(A['off'])}:80/desc.xml\n"
            "NT: upnp:rootdevice\nNTS: ssdp:alive\n"
            "USN: uuid:ext::upnp:rootdevice\n\n")
    return [udp(body, A["host"], A["mcast"])]


def _soap(action, inner, host):
    body = ('<?xml version="1.0"?><s:Envelope '
            'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
            f'<u:{action} xmlns:u="urn:schemas-upnp-org:service:'
            f'WANIPConnection:1">{inner}</u:{action}></s:Body></s:Envelope>')
    return (f"POST /ctl/IPConn HTTP/1.1\nHOST: {lit(host)}:49152\n"
            "CONTENT-TYPE: text/xml; charset=\"utf-8\"\n"
            f'SOAPACTION: "urn:schemas-upnp-org:service:WANIPConnection:1#{action}"\n'
            f"CONTENT-LENGTH: {len(body)}\n\n" + body)


def v_pinhole_third_party(A):                            # SSDP-030
    inner = ("<NewRemoteHost></NewRemoteHost><NewExternalPort>5555</NewExternalPort>"
             "<NewProtocol>TCP</NewProtocol><NewInternalPort>8080</NewInternalPort>"
             f"<NewInternalClient>{A['other']}</NewInternalClient>"
             "<NewEnabled>1</NewEnabled><NewPortMappingDescription>x"
             "</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration>")
    return [tcp(_soap("AddPortMapping", inner, A["router"]),
                A["host"], A["router"])]


def v_wan_side_control(A):                               # SSDP-031
    inner = ("<NewExternalPort>80</NewExternalPort><NewProtocol>TCP</NewProtocol>"
             "<NewInternalPort>8080</NewInternalPort>"
             f"<NewInternalClient>{A['host']}</NewInternalClient>"
             "<NewLeaseDuration>3600</NewLeaseDuration>")
    return [tcp(_soap("AddPortMapping", inner, A["router"]),
                A["off"], A["router"])]


def v_sensitive_port(A):                                 # SSDP-032
    inner = ("<NewExternalPort>62000</NewExternalPort><NewProtocol>TCP</NewProtocol>"
             "<NewInternalPort>445</NewInternalPort>"
             f"<NewInternalClient>{A['host']}</NewInternalClient>"
             "<NewLeaseDuration>3600</NewLeaseDuration>")
    return [tcp(_soap("AddPortMapping", inner, A["router"]),
                A["host"], A["router"])]


def v_delete_mapping(A):                                 # SSDP-033
    """Deleting someone ELSE's mapping. The Add must be witnessed first --
    a host deleting its own mapping is ordinary housekeeping."""
    add = ("<NewRemoteHost></NewRemoteHost><NewExternalPort>443</NewExternalPort>"
           "<NewProtocol>TCP</NewProtocol><NewInternalPort>8443</NewInternalPort>"
           f"<NewInternalClient>{A['other']}</NewInternalClient>"
           "<NewLeaseDuration>3600</NewLeaseDuration>")
    dele = ("<NewRemoteHost></NewRemoteHost><NewExternalPort>443</NewExternalPort>"
            "<NewProtocol>TCP</NewProtocol>")
    return [tcp(_soap("AddPortMapping", add, A["router"]),
                A["other"], A["router"], ts=T0),
            tcp(_soap("DeletePortMapping", dele, A["router"]),
                A["host"], A["router"], ts=T0 + 1)]


def v_infinite_lease(A):                                 # SSDP-034
    inner = ("<NewExternalPort>62001</NewExternalPort><NewProtocol>TCP</NewProtocol>"
             "<NewInternalPort>8080</NewInternalPort>"
             f"<NewInternalClient>{A['host']}</NewInternalClient>"
             "<NewLeaseDuration>0</NewLeaseDuration>")
    return [tcp(_soap("AddPortMapping", inner, A["router"]),
                A["host"], A["router"])]


# code -> (vector builder, families it applies to)
VECTORS = [
    ("SSDP-001", v_callstranger, (4, 6)),
    ("SSDP-002", v_callback_mismatch, (4, 6)),
    ("SSDP-003", v_callback_fanout, (4, 6)),
    ("SSDP-004", v_callback_scheme, (4, 6)),
    ("SSDP-005", v_timeout, (4, 6)),
    ("SSDP-010", v_unicast_msearch_offlink, (4, 6)),
    ("SSDP-011", v_ssdp_all, (4, 6)),
    ("SSDP-012", v_amplifier, (4, 6)),
    ("SSDP-013", v_ratio, (4, 6)),
    ("SSDP-014", v_storm, (4, 6)),
    ("SSDP-015", v_ttl, (4, 6)),
    ("SSDP-016", v_v6_scope, (6,)),
    ("SSDP-017", v_notify_spoof, (4, 6)),
    ("SSDP-018", v_byebye_storm, (4, 6)),
    ("SSDP-019", v_bootid_regress, (4, 6)),
    ("SSDP-020", v_bad_man, (4, 6)),
    ("SSDP-021", v_bad_mx, (4, 6)),
    ("SSDP-022", v_malformed, (4, 6)),
    ("SSDP-023", v_location_offlink, (4, 6)),
    ("SSDP-024", v_unsolicited, (4, 6)),
    ("SSDP-030", v_pinhole_third_party, (4, 6)),
    ("SSDP-031", v_wan_side_control, (4, 6)),
    ("SSDP-032", v_sensitive_port, (4, 6)),
    ("SSDP-033", v_delete_mapping, (4, 6)),
    ("SSDP-034", v_infinite_lease, (4, 6)),
]


# ------------------------------------------------------------ clean control

def clean_traffic(A):
    """Ordinary, correct home UPnP: multicast discovery, a handful of
    responses, alive adverts, a local subscription, a self-pinhole."""
    pkts = [
        udp('M-SEARCH * HTTP/1.1\n'
            f'HOST: {lit(A["mcast"])}:1900\n'
            'MAN: "ssdp:discover"\nMX: 2\nST: upnp:rootdevice\n\n',
            A["host"], A["mcast"], sport=42000, ttl=2, ts=T0),
    ]
    for i in range(3):
        pkts.append(udp(
            "HTTP/1.1 200 OK\nCACHE-CONTROL: max-age=1800\n"
            f"LOCATION: http://{lit(A['router'])}:49152/desc{i}.xml\n"
            "SERVER: Linux/5.10 UPnP/1.1 miniupnpd/2.3\n"
            "ST: upnp:rootdevice\n"
            f"USN: uuid:clean{i}::upnp:rootdevice\n"
            "BOOTID.UPNP.ORG: 7\nCONFIGID.UPNP.ORG: 1\n\n",
            A["router"], A["host"], sport=1900, dport=42000, ts=T0 + 0.2 * i))
    pkts.append(udp(
        "NOTIFY * HTTP/1.1\n"
        f"HOST: {lit(A['mcast'])}:1900\nCACHE-CONTROL: max-age=1800\n"
        f"LOCATION: http://{lit(A['router'])}:49152/desc.xml\n"
        "NT: upnp:rootdevice\nNTS: ssdp:alive\n"
        "USN: uuid:clean-root::upnp:rootdevice\n"
        "BOOTID.UPNP.ORG: 7\n\n",
        A["router"], A["mcast"], ttl=2, ts=T0 + 1))
    pkts.append(udp(
        "NOTIFY * HTTP/1.1\n"
        f"HOST: {lit(A['mcast'])}:1900\n"
        "NT: upnp:rootdevice\nNTS: ssdp:byebye\n"
        "USN: uuid:clean-root::upnp:rootdevice\n"
        "BOOTID.UPNP.ORG: 8\n\n",
        A["router"], A["mcast"], ttl=2, ts=T0 + 2))
    pkts.append(tcp(
        f"SUBSCRIBE /evt/WANIPConn1 HTTP/1.1\nHOST: {lit(A['router'])}:49152\n"
        f"CALLBACK: <http://{lit(A['host'])}:51000/notify>\n"
        "NT: upnp:event\nTIMEOUT: Second-1800\n\n",
        A["host"], A["router"], ts=T0 + 3))
    pkts.append(tcp(
        f"UNSUBSCRIBE /evt/WANIPConn1 HTTP/1.1\nHOST: {lit(A['router'])}:49152\n"
        "SID: uuid:subscription-1\n\n",
        A["host"], A["router"], ts=T0 + 4))
    inner = ("<NewRemoteHost></NewRemoteHost><NewExternalPort>51820</NewExternalPort>"
             "<NewProtocol>UDP</NewProtocol><NewInternalPort>51820</NewInternalPort>"
             f"<NewInternalClient>{A['host']}</NewInternalClient>"
             "<NewEnabled>1</NewEnabled>"
             "<NewPortMappingDescription>wg</NewPortMappingDescription>"
             "<NewLeaseDuration>3600</NewLeaseDuration>")
    pkts.append(tcp(_soap("AddPortMapping", inner, A["router"]),
                    A["host"], A["router"], ts=T0 + 5))

    # a host tearing down the mapping it just created: housekeeping, not abuse
    dele = ("<NewRemoteHost></NewRemoteHost><NewExternalPort>51820"
            "</NewExternalPort><NewProtocol>UDP</NewProtocol>")
    pkts.append(tcp(_soap("DeletePortMapping", dele, A["router"]),
                    A["host"], A["router"], ts=T0 + 6))

    # UDA 1.0 gear still ships TTL 4 -- must not read as a scope escape
    pkts.append(udp(
        "NOTIFY * HTTP/1.1\n"
        f"HOST: {lit(A['mcast'])}:1900\n"
        f"LOCATION: http://{lit(A['router'])}:49152/desc.xml\n"
        "NT: upnp:rootdevice\nNTS: ssdp:alive\n"
        "USN: uuid:uda10::upnp:rootdevice\n\n",
        A["router"], A["mcast"], ttl=4, ts=T0 + 7))

    # a media-heavy house: ONE ssdp:all, 20 DISTINCT devices answer.
    # This is the shape that a naive response-count rule mistakes for
    # amplification. It must stay silent.
    pkts.append(udp('M-SEARCH * HTTP/1.1\n'
                    f'HOST: {lit(A["mcast"])}:1900\n'
                    'MAN: "ssdp:discover"\nMX: 2\nST: ssdp:all\n\n',
                    A["host"], A["mcast"], sport=43000, ttl=2, ts=T0 + 10))
    base = 60 if ":" not in A["host"] else 0x60
    for i in range(20):
        responder = (f"192.168.1.{base + i}" if ":" not in A["host"]
                     else f"fd00:abcd::{base + i:x}")
        pkts.append(udp(
            "HTTP/1.1 200 OK\nCACHE-CONTROL: max-age=1800\n"
            f"LOCATION: http://{lit(responder)}:49152/desc.xml\n"
            "ST: upnp:rootdevice\n"
            f"USN: uuid:house{i}::upnp:rootdevice\n\n",
            responder, A["host"], sport=1900, dport=43000,
            ts=T0 + 10.1 + 0.05 * i))
    return pkts


# ------------------------------------------------------------------- unit

def unit_checks():
    out = []

    def chk(name, got, want):
        out.append((name, got == want, f"got {got!r} want {want!r}"))

    chk("url v4 host", url_host_port("http://192.168.1.5:49152/d.xml"),
        ("192.168.1.5", 49152, "http"))
    chk("url v6 bracket", url_host_port("http://[fd00::1]:8080/cb"),
        ("fd00::1", 8080, "http"))
    chk("url v6 default port", url_host_port("http://[2001:db8::9]/cb"),
        ("2001:db8::9", 80, "http"))
    chk("url v6 no brackets is unparsed port",
        url_host_port("http://[fd00::1]/x")[0], "fd00::1")
    chk("callback split multi",
        split_callbacks("<http://a:1/x> <http://b:2/y>"),
        ["http://a:1/x", "http://b:2/y"])
    chk("callback split bare", split_callbacks("http://a:1/x"), ["http://a:1/x"])
    chk("rfc5952 canon", canon("FD00:0000:0000::0001"), "fd00::1")
    chk("canon zone strip", canon("fe80::1%eth0"), "fe80::1")

    s = Scope()
    chk("ula local", s.is_local("fd00::1"), True)
    chk("gua offlink", s.is_offlink("2001:db8::1"), True)
    chk("rfc1918 local", s.is_local("10.1.2.3"), True)
    chk("public offlink", s.is_offlink("8.8.8.8"), True)
    chk("cgnat offlink", s.is_offlink("100.64.0.1"), True)
    chk("cgnat reclaimable via --local",
        Scope(("100.64.0.0/10",)).is_local("100.64.0.1"), True)
    chk("mcast not offlink", s.is_offlink("239.255.255.250"), False)
    chk("v6 mcast not offlink", s.is_offlink("ff02::c"), False)

    m = parse_httpu(b"M-SEARCH * HTTP/1.1\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n\r\n")
    chk("parse method", m.method, "M-SEARCH")
    chk("parse header ci", m.get("Man"), '"ssdp:discover"')
    r = parse_httpu(b"HTTP/1.1 200 OK\r\nST: x\r\n\r\n")
    chk("parse status", (r.kind, r.status), ("response", 200))
    chk("parse junk", parse_httpu(b"\x00\x01garbage"), None)
    lf = parse_httpu(b"NOTIFY * HTTP/1.1\nNTS: ssdp:alive\n\n")
    chk("lf tolerated", lf.get("nts"), "ssdp:alive")
    chk("lf flagged", "lf_only_terminator" in lf.errors, True)
    return out



# ------------------------------------------------------------------ census

CENSUS_MACS = {"router": "e4:3e:d7:00:11:22", "host": "aa:bb:cc:dd:ee:01",
               "other": "00:17:88:1a:2b:3c"}


def cpkt(payload, src, dst, mac=None, sport=49152, dport=1900, ttl=2,
         ts=T0, proto="udp"):
    if isinstance(payload, str):
        payload = payload.replace("\n", "\r\n").encode()
    return Packet(ts=ts, proto=proto, src=src, dst=dst, sport=sport,
                  dport=dport, payload=payload, ttl=ttl, src_mac=mac)


def _advert(A, uuid, dtype, server=None, loc=None, extra="", mac=None, ts=T0):
    lit_ = lit(A["router"])
    loc = loc or f"http://{lit_}:49152/desc.xml"
    hdr = (f"NOTIFY * HTTP/1.1\nHOST: {lit(A['mcast'])}:1900\n"
           f"LOCATION: {loc}\nNT: {dtype}\nNTS: ssdp:alive\n"
           f"USN: uuid:{uuid}::{dtype}\n")
    if server:
        hdr += f"SERVER: {server}\n"
    hdr += extra + "\n"
    return cpkt(hdr, A["router"], A["mcast"], mac=mac, ts=ts)


def _description(A, uuid, fields, mac=None, ts=T0, split_at=None):
    body = ('<?xml version="1.0"?>'
            '<root xmlns="urn:schemas-upnp-org:device-1-0"><device>'
            + "".join(f"<{k}>{v}</{k}>" for k, v in fields.items())
            + f"<UDN>uuid:{uuid}</UDN></device></root>")
    whole = ("HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n" + body).encode()
    if split_at is None:
        return [cpkt(whole, A["router"], A["host"], mac=mac, sport=49152,
                     dport=51000, ts=ts, proto="tcp")]
    return [cpkt(whole[:split_at], A["router"], A["host"], mac=mac, sport=49152,
                 dport=51000, ts=ts, proto="tcp"),
            cpkt(whole[split_at:], A["router"], A["host"], mac=mac, sport=49152,
                 dport=51000, ts=ts + 0.1, proto="tcp")]


def census_checks():
    """The census is an inventory, not a detector. These assert it identifies
    devices correctly AND that it never produces a finding."""
    import ssdpwatch as M
    out = []

    def c(name, ok, msg=""):
        out.append((name, bool(ok), msg))

    for fam, A in ((4, V4), (6, V6)):
        uuid = "aaaabbbb-cccc-dddd-eeee-ffff00001111"
        dtype = "urn:schemas-upnp-org:device:MediaServer:1"
        pkts = [_advert(A, uuid, dtype, server="Linux/5.10 UPnP/1.1 MiniUPnPd/2.3.0",
                        mac=CENSUS_MACS["router"], ts=T0)]
        pkts += _description(A, uuid, {
            "deviceType": dtype, "friendlyName": "Basement NAS",
            "manufacturer": "Synology", "modelName": "DS920+",
            "serialNumber": "2290ABC01"}, mac=CENSUS_MACS["router"], ts=T0 + 1)
        e = M.SSDPWatch(M.Config())
        for p in pkts:
            e.observe(p)
        recs = e.census.records()

        # THE regression that matters: a USN is "uuid:<udn>::<type>". If the
        # uuid is parsed across the '::' the SSDP record and the description
        # record key differently and one device is reported as two.
        c(f"ipv{fam}: advert and description merge into ONE device",
          len(recs) == 1, f"{len(recs)} records: {[r.key for r in recs]}")
        if recs:
            r = recs[0]
            c(f"ipv{fam}: uuid stops at '::'", r.uuid == uuid, str(r.uuid))
            c(f"ipv{fam}: friendly name recovered", r.name == "Basement NAS", r.name)
            c(f"ipv{fam}: name provenance is the description",
              r.fields["friendlyName"].source == "description",
              r.fields["friendlyName"].source)
            c(f"ipv{fam}: manufacturer from description",
              r.get("manufacturer") == "Synology", str(r.get("manufacturer")))
            c(f"ipv{fam}: serial from description",
              r.get("serialNumber") == "2290ABC01", str(r.get("serialNumber")))
            c(f"ipv{fam}: device type recovered",
              r.best_device_type() == "MediaServer", str(r.best_device_type()))
            c(f"ipv{fam}: SSDP stack token kept alongside description",
              r.get("serverProduct") == "MiniUPnPd/2.3.0", str(r.get("serverProduct")))
            # The protocol token UPnP/x.y must land in upnpVersion, not be
            # reported as the product. A substring test is wrong here:
            # "MiniUPnPd" legitimately contains "UPnP".
            c(f"ipv{fam}: UPnP protocol token is not mistaken for a product",
              r.get("upnpVersion") == "1.1"
              and not (r.get("serverProduct") or "").lower().startswith("upnp/"),
              f"{r.get('upnpVersion')} / {r.get('serverProduct')}")
            c(f"ipv{fam}: mac captured from the frame",
              CENSUS_MACS["router"] in r.macs, str(r.macs))
        c(f"ipv{fam}: census produced no findings", e.findings == [],
          str([f.code for f in e.findings]))

    # a description split across TCP segments must still yield the name
    A = V4
    uuid = "split-dev-0001"
    pkts = [_advert(A, uuid, "urn:schemas-upnp-org:device:MediaRenderer:1",
                    mac=CENSUS_MACS["host"])]
    pkts += _description(A, uuid, {"friendlyName": "Living Room Speaker",
                                   "manufacturer": "Acme"},
                         mac=CENSUS_MACS["host"], ts=T0 + 1, split_at=180)
    e = M.SSDPWatch(M.Config())
    for p in pkts:
        e.observe(p)
    r = e.census.records()[0]
    c("description split across segments is reassembled",
      r.name == "Living Room Speaker", r.name)
    c("split description still merges to one device",
      len(e.census.records()) == 1, str(len(e.census.records())))

    # no description at all -> no invented name, and it says why
    e = M.SSDPWatch(M.Config())
    e.observe(_advert(V4, "nameless-01",
                      "urn:schemas-upnp-org:device:MediaRenderer:1",
                      mac=CENSUS_MACS["host"]))
    r = e.census.records()[0]
    c("no description means no name is invented",
      r.name == "<unnamed MediaRenderer>" and "friendlyName" not in r.fields,
      r.name)

    # a vendor extension header is recorded verbatim and mined for a MAC.
    # hue-bridgeid carries an EUI-64-shaped, MAC-derived serial.
    e = M.SSDPWatch(M.Config())
    e.observe(cpkt("HTTP/1.1 200 OK\nHOST: 239.255.255.250:1900\nEXT:\n"
                   "LOCATION: http://192.168.1.20:80/description.xml\n"
                   "SERVER: Linux/3.14.0 UPnP/1.0 IpBridge/1.17.0\n"
                   "hue-bridgeid: 001788FFFE1A2B3C\n"
                   "ST: upnp:rootdevice\n"
                   "USN: uuid:2f402f80-da50::upnp:rootdevice\n\n",
                   "192.168.1.20", "192.168.1.50", sport=1900, dport=45000))
    r = e.census.records()[0]
    c("vendor extension header recorded verbatim",
      r.vendor_headers.get("hue-bridgeid") == "001788FFFE1A2B3C",
      str(r.vendor_headers))
    c("MAC recovered from an EUI-64-shaped vendor header",
      "00:17:88:1a:2b:3c" in r.macs, str(r.macs))
    c("standard UDA headers are not logged as vendor extensions",
      not ({"host", "location", "server", "st", "usn", "ext"}
           & set(r.vendor_headers)), str(set(r.vendor_headers)))
    c("upnp:rootdevice is never reported as a device type",
      r.best_device_type() is None, str(r.best_device_type()))

    # M-SEARCH must NOT create a device: a search proves a control point
    # exists, not that any device does
    e = M.SSDPWatch(M.Config())
    e.observe(cpkt('M-SEARCH * HTTP/1.1\nHOST: 239.255.255.250:1900\n'
                   'MAN: "ssdp:discover"\nMX: 2\nST: ssdp:all\n\n',
                   "192.168.1.50", "239.255.255.250"))
    c("M-SEARCH does not populate the census with a phantom device",
      e.census.records() == [], str([r.key for r in e.census.records()]))

    # byebye carries no identity and must not create a record either
    e = M.SSDPWatch(M.Config())
    e.observe(cpkt("NOTIFY * HTTP/1.1\nHOST: 239.255.255.250:1900\n"
                   "NT: upnp:rootdevice\nNTS: ssdp:byebye\n"
                   "USN: uuid:gone-01::upnp:rootdevice\n\n",
                   "192.168.1.9", "239.255.255.250"))
    c("ssdp:byebye does not create a device record",
      e.census.records() == [], str([r.key for r in e.census.records()]))

    # source ranking: a weaker source must never overwrite the description
    e = M.SSDPWatch(M.Config())
    uuid = "rank-01"
    for p in _description(V4, uuid, {"friendlyName": "Real Name",
                                     "manufacturer": "RealCo"}):
        e.observe(p)
    e.observe(_advert(V4, uuid, "urn:schemas-upnp-org:device:MediaServer:1",
                      server="Linux/1.0 UPnP/1.0 Guess/9.9", ts=T0 + 5))
    r = e.census.records()[0]
    c("later SSDP cannot downgrade a description-sourced name",
      r.name == "Real Name", r.name)
    c("later SSDP cannot downgrade manufacturer",
      r.get("manufacturer") == "RealCo", str(r.get("manufacturer")))

    # oversized field must be truncated, not stored whole
    e = M.SSDPWatch(M.Config())
    for p in _description(V4, "big-01", {"friendlyName": "X" * 5000}):
        e.observe(p)
    r = e.census.records()[0]
    c("an oversized friendlyName is truncated",
      len(r.get("friendlyName")) <= M.DESC_CAP + 20, str(len(r.get("friendlyName") or "")))

    # locally-administered MAC must not yield a vendor claim
    tbl = M.OUITable()
    tbl.map["02dead"] = "Should Not Appear"
    rec = M.DeviceRecord(key="x")
    rec.macs.add("02:de:ad:be:ef:01")
    c("randomized (locally-administered) MAC yields no vendor",
      rec.vendor(tbl) is None, str(rec.vendor(tbl)))

    # --- mechanism-level contracts -----------------------------------
    # These exercise the guards directly. Testing them only through whole
    # exchanges leaves them untested whenever no exchange happens to make
    # two sources compete, or to overflow a buffer.

    # source ranking: a stronger source upgrades, a weaker one never wins,
    # regardless of arrival order
    rec = M.DeviceRecord(key="rank")
    rec.learn("friendlyName", "From Server Token", "server-header", 1.0)
    rec.learn("friendlyName", "From Description", "description", 2.0)
    c("a stronger source upgrades a field",
      rec.get("friendlyName") == "From Description", str(rec.get("friendlyName")))
    rec.learn("friendlyName", "Late Weak Guess", "inferred", 3.0)
    c("a weaker source never overwrites a stronger one",
      rec.get("friendlyName") == "From Description", str(rec.get("friendlyName")))
    rec.learn("friendlyName", "Second Description", "description", 4.0)
    c("an equal source does not thrash the value",
      rec.get("friendlyName") == "From Description", str(rec.get("friendlyName")))
    c("provenance is retained alongside the value",
      rec.fields["friendlyName"].source == "description",
      rec.fields["friendlyName"].source)

    # the field cap is enforced at the point of record, not only at parse:
    # a value can reach learn() from a vendor header too
    rec = M.DeviceRecord(key="cap")
    rec.learn("friendlyName", "Z" * 10000, "description", 1.0)
    c("learn() caps an oversized value at the record boundary",
      len(rec.get("friendlyName")) <= M.DESC_CAP + 20,
      str(len(rec.get("friendlyName"))))
    c("a truncated value says so rather than pretending to be complete",
      rec.get("friendlyName").endswith("(truncated)"),
      rec.get("friendlyName")[-20:])

    # stream reassembly is bounded. Without this a device that opens a
    # description-shaped stream and never closes it pins memory on a Pi
    # indefinitely, one buffer per stream.
    cen = M.Census()
    pkt_src, pkt_dst = "192.168.1.9", "192.168.1.50"
    opener = (b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n"
              b'<root xmlns="urn:schemas-upnp-org:device-1-0"><device>'
              b"<friendlyName>Never Closes</friendlyName>")
    cen.observe_http(cpkt(opener, pkt_src, pkt_dst, sport=49152, dport=51000,
                          proto="tcp"))
    buffered_before = sum(len(v) for v in cen._streams.values())
    chunk = b"<padding>" + b"A" * 8000 + b"</padding>"
    for i in range(12):
        cen.observe_http(cpkt(chunk, pkt_src, pkt_dst, sport=49152,
                              dport=51000, proto="tcp", ts=T0 + i))
    buffered_after = sum(len(v) for v in cen._streams.values())
    c("an unterminated description stream is bounded, not grown forever",
      buffered_after <= M.MAX_STREAM_BUFFER,
      f"{buffered_before} -> {buffered_after} bytes "
      f"(cap {M.MAX_STREAM_BUFFER})")
    c("hitting the bound is counted rather than silently ignored",
      cen.stats.get("stream_overflow", 0) >= 1, str(dict(cen.stats)))

    # baseline comparison
    import tempfile, os
    e = M.SSDPWatch(M.Config())
    e.observe(_advert(V4, "known-01", "urn:schemas-upnp-org:device:MediaServer:1",
                      mac=CENSUS_MACS["host"]))
    e.observe(_advert(V4, "stranger-01", "urn:schemas-upnp-org:device:MediaServer:1",
                      mac=CENSUS_MACS["other"], ts=T0 + 1))
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as fh:
        fh.write("# expected\nknown-01\n")
    e.census.mark_known(path)
    os.unlink(path)
    by = {r.uuid: e.census.is_new(r) for r in e.census.records()}
    c("baseline marks an expected device known", by.get("known-01") is False, str(by))
    c("baseline marks an unexpected device NEW", by.get("stranger-01") is True, str(by))
    c("no baseline means no new/known verdict at all",
      M.Census().is_new(M.DeviceRecord(key="x")) is None)

    # passivity: the census must never emit a description request
    src = open(__file__.replace("_selftest", "")).read()
    c("census contains no HTTP request construction",
      'b"GET ' not in src.split("def observe_http")[1].split("def ")[0]
      if "def observe_http" in src else False)
    return out


# ------------------------------------------------------- capture layer

def capture_layer_checks():
    """run_live must survive a host with no libpcap. scapy compiles the BPF
    through libpcap, so on a bare WSL or minimal Pi image the FILTER fails,
    not the capture. Exercised without sockets by faking sniff()."""
    import ssdpwatch as M
    from scapy.error import Scapy_Exception
    import scapy.all as scapy_all

    out = []
    calls = []
    real = scapy_all.sniff

    def fake_sniff(**kw):
        calls.append(kw)
        if "filter" in kw:
            raise Scapy_Exception(
                "Cannot set filter: libpcap is not available. "
                "Cannot compile filter !")
        return []

    scapy_all.sniff = fake_sniff
    try:
        M.run_live("lo", M.SSDPWatch(M.Config()), timeout=1)
    except Exception as exc:
        out.append(("libpcap fallback engages", False, f"raised {exc!r}"))
    else:
        out.append(("libpcap fallback engages", len(calls) == 2, f"{len(calls)} sniff calls"))
        out.append(("fallback drops the bpf, uses lfilter",
                    "filter" not in calls[-1] and callable(calls[-1].get("lfilter")),
                    str(sorted(calls[-1]))[:60]))
    finally:
        scapy_all.sniff = real

    # A non-filter fault must propagate. The fallback leg is made to SUCCEED
    # here on purpose: if the guard that distinguishes a libpcap problem from
    # a real one is removed, run_live would quietly retry and return, and a
    # missing interface would look like a clean capture.
    boom_calls = []

    def boom(**kw):
        boom_calls.append(kw)
        if "filter" in kw:
            raise Scapy_Exception("No such device: eth99")
        return []                      # fallback would succeed

    scapy_all.sniff = boom
    try:
        M.run_live("eth99", M.SSDPWatch(M.Config()), timeout=1)
        out.append(("real capture errors still raise", False,
                    f"swallowed after {len(boom_calls)} calls"))
    except Scapy_Exception:
        out.append(("real capture errors still raise", True, ""))
    finally:
        scapy_all.sniff = real

    # the software predicate must match what the BPF selects
    w = M._wanted
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw
    SUB = Raw(b"SUBSCRIBE /evt/svc1 HTTP/1.1\r\n")
    SOAP = Raw(b"POST /ctl/IPConn HTTP/1.1\r\n")
    TLS = Raw(bytes([0x16, 0x03, 0x01, 0x02, 0x00]))
    cases = [
        (IP() / UDP(sport=49152, dport=1900), True, "ssdp to 1900"),
        (IP() / UDP(sport=1900, dport=35000), True, "ssdp reply from 1900"),
        (IPv6() / UDP(sport=49152, dport=1900), True, "ssdp over ipv6"),
        (IP() / UDP(sport=53, dport=53), False, "plain dns"),
        (IP() / TCP(sport=51000, dport=2869) / SUB, True, "gena subscribe v4"),
        (IPv6() / TCP(sport=51000, dport=2869) / SUB, True, "gena subscribe v6"),
        (IP() / TCP(sport=51000, dport=49152) / SOAP, True, "igd soap v4"),
        (IPv6() / TCP(sport=51000, dport=49152) / SOAP, True, "igd soap v6"),
        (IP() / TCP(sport=51000, dport=443) / TLS, False, "ordinary https"),
        (IPv6() / TCP(sport=443, dport=51000) / TLS, False, "https reply v6"),
        (IP() / TCP(sport=51000, dport=49152), False, "bare ack, no payload"),
    ]
    for pkt, want, label in cases:
        out.append((f"software filter: {label}", w(pkt) == want,
                    f"got {w(pkt)} want {want}"))
    return out


# ------------------------------------------------------------------- driver

def run_selftest() -> int:
    passed = failed = 0
    fails = []

    print(f"ssdpwatch self-test  ({len(REGISTRY)} codes in registry)")
    print("-" * 68)

    print("\n[unit]")
    for name, ok, msg in unit_checks():
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
        if not ok:
            fails.append(f"unit:{name}: {msg}")
        print(f"  {'PASS' if ok else 'FAIL':4}  {name}")

    print("\n[capture layer]")
    for name, ok, msg in capture_layer_checks():
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
        if not ok:
            fails.append(f"capture:{name}: {msg}")
        print(f"  {'PASS' if ok else 'FAIL':4}  {name}")

    print("\n[census]")
    for name, ok, msg in census_checks():
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
        if not ok:
            fails.append(f"census:{name}: {msg}")
        print(f"  {'PASS' if ok else 'FAIL':4}  {name}")

    print("\n[positive vectors]")
    for code, builder, fams in VECTORS:
        for fam in (4, 6):
            A = V4 if fam == 4 else V6
            tag = f"{code} ipv{fam}"
            if fam not in fams:
                print(f"  n/a   {tag}  (not family-applicable)")
                continue
            e = run(builder(A))
            ok = code in codes(e)
            passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
            if not ok:
                fails.append(f"{tag}: fired {sorted(codes(e))}")
            print(f"  {'PASS' if ok else 'FAIL':4}  {tag}")

    print("\n[negative control — clean home UPnP]")
    for fam in (4, 6):
        A = V4 if fam == 4 else V6
        e = run(clean_traffic(A))
        got = sorted(codes(e))
        ok = not got
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
        if not ok:
            fails.append(f"clean ipv{fam} false positives: {got}")
        print(f"  {'PASS' if ok else 'FAIL':4}  clean ipv{fam}"
              f"{'' if ok else '  -> ' + ','.join(got)}")

    print("\n[registry coverage]")
    covered = {c for c, _, _ in VECTORS}
    missing = sorted(set(REGISTRY) - covered)
    ok = not missing
    passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
    if not ok:
        fails.append(f"codes with no vector: {missing}")
    print(f"  {'PASS' if ok else 'FAIL':4}  every registry code has a vector"
          f"{'' if ok else ' -> ' + ','.join(missing)}")

    print("\n[passivity]")
    src = open(__file__.replace("_selftest", "")).read()
    banned = ("socket.send", ".sendto(", "scapy.sendrecv", "sendp(", "srp(",
              "sr1(", "\nsend(")
    hits = [b for b in banned if b in src]
    ok = not hits
    passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
    if not ok:
        fails.append(f"transmit primitives present: {hits}")
    print(f"  {'PASS' if ok else 'FAIL':4}  module contains no transmit primitive")

    print("-" * 68)
    print(f"{passed} passed, {failed} failed")
    for f in fails:
        print(f"  ! {f}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_selftest())
