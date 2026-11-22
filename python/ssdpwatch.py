#!/usr/bin/env python3
"""
ssdpwatch - Ragnar passive SSDP / UPnP detector.

Scope: the PROTOCOL only (UPnP Device Architecture wire grammar + GENA + IGD
control). Vendor / implementation CVEs are out of scope by design.

Tiers
  A  SSDP discovery plane .... UDP/1900, IPv4 239.255.255.250 + IPv6 FF0x::C
  B  GENA eventing ........... TCP, SUBSCRIBE/UNSUBSCRIBE (CallStranger)
  C  IGD control ............. TCP, SOAP WANIPConnection/WANPPPConnection

Passive only. Never transmits. Dual-stack with full IPv4/IPv6 parity.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Optional, Tuple

__version__ = "0.2.0-dev"
MODULE = "ssdpwatch"

SSDP_PORT = 1900
SSDP_V4_GROUP = ipaddress.ip_address("239.255.255.250")
# UPnP Device Architecture 1.1 / 2.0 multicast scopes
SSDP_V6_GROUPS = {
    ipaddress.ip_address("ff02::c"): "link",
    ipaddress.ip_address("ff05::c"): "site",
    ipaddress.ip_address("ff08::c"): "organization",
    ipaddress.ip_address("ff0e::c"): "global",
}
# UDA 1.1/2.0 default the multicast TTL / hop limit to 2; UDA 1.0 gear
# shipped 4 and is still everywhere in homes. Anything at or below 4 is
# within historical spec, so only a value ABOVE 4 is a deliberate escape.
UDA_DEFAULT_TTL = 2
UDA_MAX_SANE_TTL = 4


# --------------------------------------------------------------------------
# finding registry
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class CodeDef:
    code: str
    tier: str
    severity: str
    title: str
    cve: Optional[str] = None


REGISTRY: Dict[str, CodeDef] = {}


def _reg(code, tier, severity, title, cve=None):
    REGISTRY[code] = CodeDef(code, tier, severity, title, cve)
    return code


# --- Tier B: CallStranger, the one CVE trigger -----------------------------
SSDP_001 = _reg("SSDP-001", "B", "high",
                "GENA SUBSCRIBE CALLBACK points off-link (CallStranger)",
                "CVE-2020-12695")
SSDP_002 = _reg("SSDP-002", "B", "high",
                "GENA SUBSCRIBE CALLBACK host differs from subscriber source",
                "CVE-2020-12695")
SSDP_003 = _reg("SSDP-003", "B", "medium",
                "GENA SUBSCRIBE carries multiple CALLBACK URLs (fan-out amplifier)",
                "CVE-2020-12695")
SSDP_004 = _reg("SSDP-004", "B", "medium",
                "GENA SUBSCRIBE CALLBACK uses non-http scheme or odd port")
SSDP_005 = _reg("SSDP-005", "B", "low",
                "GENA SUBSCRIBE requests unbounded / excessive TIMEOUT")

# --- Tier A: discovery-plane abuse and posture -----------------------------
SSDP_010 = _reg("SSDP-010", "A", "high",
                "Unicast M-SEARCH from off-link source (reflection probe)")
SSDP_011 = _reg("SSDP-011", "A", "medium",
                "Unicast M-SEARCH with ST: ssdp:all (targeted inventory sweep)")
SSDP_012 = _reg("SSDP-012", "A", "high",
                "SSDP response sent to off-link destination (amplifier exposure)")
SSDP_013 = _reg("SSDP-013", "A", "high",
                "One responder sent duplicate responses to a single host "
                "(amplification multiplier)")
SSDP_014 = _reg("SSDP-014", "A", "high",
                "Response storm converging on a single destination")
SSDP_015 = _reg("SSDP-015", "A", "medium",
                "SSDP multicast TTL / hop limit above the UDA range of 2-4 "
                "(deliberate scope escape)")
SSDP_016 = _reg("SSDP-016", "A", "medium",
                "SSDP sent to a wider-than-link IPv6 scope (FF05/FF08/FF0E)")
SSDP_017 = _reg("SSDP-017", "A", "medium",
                "NOTIFY LOCATION host does not match packet source (advert spoof)")
SSDP_018 = _reg("SSDP-018", "A", "medium",
                "ssdp:byebye storm (device-eviction flood)")
SSDP_019 = _reg("SSDP-019", "A", "medium",
                "BOOTID.UPNP.ORG regression for a known USN (impersonation)")
SSDP_020 = _reg("SSDP-020", "A", "low",
                "M-SEARCH missing or malformed MAN: \"ssdp:discover\"")
SSDP_021 = _reg("SSDP-021", "A", "low",
                "M-SEARCH MX value out of UDA range (1-5)")
SSDP_022 = _reg("SSDP-022", "A", "low",
                "Malformed or oversized SSDP message")
SSDP_023 = _reg("SSDP-023", "A", "medium",
                "NOTIFY LOCATION points at a routable off-link host")
SSDP_024 = _reg("SSDP-024", "A", "medium",
                "Unsolicited SSDP 200 OK to a host that issued no M-SEARCH "
                "(reflection victim)")

# --- Tier C: IGD control-plane abuse ---------------------------------------
SSDP_030 = _reg("SSDP-030", "C", "high",
                "IGD AddPortMapping NewInternalClient differs from requester "
                "(pinhole punched for a third party)")
SSDP_031 = _reg("SSDP-031", "C", "high",
                "IGD control request arrives from an off-link source "
                "(WAN-side control)")
SSDP_032 = _reg("SSDP-032", "C", "medium",
                "IGD AddPortMapping targets an infrastructure / admin port")
SSDP_033 = _reg("SSDP-033", "C", "medium",
                "IGD DeletePortMapping / DeletePortMappingRange for a mapping "
                "the requester does not own")
SSDP_034 = _reg("SSDP-034", "C", "low",
                "IGD AddPortMapping with unbounded lease duration")

SENSITIVE_PORTS = {
    22: "ssh", 23: "telnet", 53: "dns", 139: "netbios-ssn", 445: "smb",
    1900: "ssdp", 3389: "rdp", 5555: "adb", 8291: "winbox", 9100: "jetdirect",
}


# --------------------------------------------------------------------------
# normalized packet
# --------------------------------------------------------------------------

@dataclass
class Packet:
    ts: float
    proto: str              # "udp" | "tcp"
    src: str
    dst: str
    sport: int
    dport: int
    payload: bytes
    ttl: int = 64           # IPv4 TTL or IPv6 hop limit
    iface: str = "-"
    src_mac: Optional[str] = None   # link layer; present on a local tap
    dst_mac: Optional[str] = None

    @property
    def family(self) -> int:
        return ipaddress.ip_address(self.src).version


@dataclass
class Finding:
    ts: float
    code: str
    severity: str
    title: str
    cve: Optional[str]
    tier: str
    src: str
    dst: str
    family: int
    detail: Dict[str, object] = field(default_factory=dict)

    def as_dict(self):
        d = {
            "ts": round(self.ts, 3),
            "module": MODULE,
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "tier": self.tier,
            "src": self.src,
            "dst": self.dst,
            "af": f"ipv{self.family}",
        }
        if self.cve:
            d["cve"] = self.cve
        if self.detail:
            d["detail"] = self.detail
        return d

    def line(self):
        cve = f" [{self.cve}]" if self.cve else ""
        det = ""
        if self.detail:
            det = " " + " ".join(f"{k}={v}" for k, v in self.detail.items())
        return (f"{time.strftime('%H:%M:%S', time.localtime(self.ts))} "
                f"{self.severity.upper():<6} {self.code} ipv{self.family} "
                f"{self.src} -> {self.dst}{cve} :: {self.title}{det}")


# --------------------------------------------------------------------------
# link-layer identity
# --------------------------------------------------------------------------

def norm_mac(mac: Optional[str]) -> Optional[str]:
    """Lower-case colon-separated form, or None if it is not a MAC."""
    if not mac:
        return None
    hexs = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hexs) != 12:
        return None
    hexs = hexs.lower()
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2))


def oui_of(mac: Optional[str]) -> Optional[str]:
    """The 24-bit OUI as six hex digits, or None."""
    m = norm_mac(mac)
    return None if m is None else m[:8].replace(":", "")


def is_local_mac(mac: Optional[str]) -> bool:
    """True when the locally-administered bit is set, i.e. the address is
    randomized or hand-assigned and its OUI means nothing."""
    m = norm_mac(mac)
    if m is None:
        return False
    return bool(int(m[:2], 16) & 0x02)


def mac_from_eui64ish(value: str) -> Optional[str]:
    """Recover a MAC from an identifier that embeds one.

    Several vendors publish a MAC-derived serial in an SSDP header, in the
    EUI-64 shape where FFFE is stuffed into the middle of the OUI/NIC split
    (a Philips Hue bridge's hue-bridgeid is 001788FFFExxxxxx). Both the
    16-digit EUI-64 form and the plain 12-digit form are accepted.
    """
    hexs = re.sub(r"[^0-9a-fA-F]", "", value or "")
    if len(hexs) == 16 and hexs[6:10].lower() == "fffe":
        hexs = hexs[:6] + hexs[10:]
    if len(hexs) != 12:
        return None
    return norm_mac(hexs)


class OUITable:
    """Optional vendor lookup. Deliberately NOT bundled: shipping a vendor
    table would be a maintenance treadmill and would go stale silently, so
    the default is to report the raw OUI and say so. Point --oui at a
    Wireshark `manuf` or IEEE `oui.txt` and names get resolved."""

    def __init__(self, path: Optional[str] = None):
        self.map: Dict[str, str] = {}
        self.path = path
        if path:
            self.load(path)

    def load(self, path: str) -> int:
        n = 0
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Wireshark manuf: "00:17:88<TAB>Philips  Philips Lighting BV"
                # IEEE oui.txt:    "00-17-88   (hex)\t\tPhilips Lighting BV"
                m = re.match(r"^([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-]"
                             r"[0-9A-Fa-f]{2})(?:/\d+)?\s+(?:\(hex\)\s+)?(.+)$",
                             line)
                if not m:
                    continue
                oui = m.group(1).replace("-", "").replace(":", "").lower()
                name = m.group(2).strip().split("\t")[-1].strip()
                if oui and name:
                    self.map.setdefault(oui, name)
                    n += 1
        return n

    def vendor(self, mac: Optional[str]) -> Optional[str]:
        o = oui_of(mac)
        return self.map.get(o) if o else None


# --------------------------------------------------------------------------
# address scope
# --------------------------------------------------------------------------

class Scope:
    """Decides on-link vs off-link.

    Home default: RFC1918, ULA, link-local and loopback are on-link;
    everything else is off-link.

    CGNAT (100.64.0.0/10) is deliberately OFF-link. It is carrier shared
    space upstream of the CPE, never a home LAN, so a CALLBACK or
    NewInternalClient pointing into it is pointing off the premises -- which
    is exactly the CallStranger primitive. Treating it as on-link would be a
    silent blind spot. A site that really does number internally out of
    100.64/10 adds it back with --local.
    """

    def __init__(self, extra_prefixes: Iterable[str] = ()):
        self.local_nets = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("169.254.0.0/16"),     # v4 link-local
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("fc00::/7"),           # ULA
            ipaddress.ip_network("fe80::/10"),          # v6 link-local
            ipaddress.ip_network("::1/128"),
        ]
        for p in extra_prefixes:
            self.local_nets.append(ipaddress.ip_network(p, strict=False))

    @staticmethod
    def parse(addr: str):
        a = addr.strip()
        if a.startswith("[") and "]" in a:
            a = a[1:a.index("]")]
        if "%" in a:
            a = a.split("%", 1)[0]
        try:
            return ipaddress.ip_address(a)
        except ValueError:
            return None

    def is_local(self, addr) -> bool:
        ip = addr if isinstance(addr, (ipaddress.IPv4Address,
                                       ipaddress.IPv6Address)) else self.parse(addr)
        if ip is None:
            return False
        if ip.is_multicast:
            return True
        return any(ip in n for n in self.local_nets if n.version == ip.version)

    def is_offlink(self, addr) -> bool:
        ip = addr if isinstance(addr, (ipaddress.IPv4Address,
                                       ipaddress.IPv6Address)) else self.parse(addr)
        if ip is None:
            return False
        if ip.is_multicast:
            return False
        return not self.is_local(ip)


def canon(addr: str) -> str:
    """RFC 5952 canonical form where possible, else the raw string."""
    ip = Scope.parse(addr)
    return str(ip) if ip is not None else addr.strip()


# --------------------------------------------------------------------------
# HTTPU / HTTP message parser (hand-rolled, tolerant)
# --------------------------------------------------------------------------

_START_RE = re.compile(rb"^([A-Z\-]+)[ \t]+(\S+)[ \t]+HTTP/(\d\.\d)\s*$")
_STATUS_RE = re.compile(rb"^HTTP/(\d\.\d)[ \t]+(\d{3})(?:[ \t]+(.*))?\s*$")
MAX_SANE = 8192


class HTTPUMessage:
    __slots__ = ("kind", "method", "uri", "status", "version",
                 "headers", "body", "errors", "raw_len")

    def __init__(self):
        self.kind: Optional[str] = None     # "request" | "response"
        self.method: Optional[str] = None
        self.uri: Optional[str] = None
        self.status: Optional[int] = None
        self.version: Optional[str] = None
        self.headers: Dict[str, List[str]] = {}
        self.body: bytes = b""
        self.errors: List[str] = []
        self.raw_len = 0

    def get(self, name: str, default=None) -> Optional[str]:
        v = self.headers.get(name.lower())
        return v[0] if v else default

    def all(self, name: str) -> List[str]:
        return self.headers.get(name.lower(), [])

    def has(self, name: str) -> bool:
        return name.lower() in self.headers


def parse_httpu(data: bytes) -> Optional[HTTPUMessage]:
    if not data:
        return None
    msg = HTTPUMessage()
    msg.raw_len = len(data)

    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = data.partition(b"\n\n")
        if sep:
            msg.errors.append("lf_only_terminator")
    msg.body = body

    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    if not lines or not lines[0].strip():
        return None
    start = lines[0]

    m = _STATUS_RE.match(start)
    if m:
        msg.kind = "response"
        msg.version = m.group(1).decode()
        msg.status = int(m.group(2))
    else:
        m = _START_RE.match(start)
        if not m:
            return None
        msg.kind = "request"
        msg.method = m.group(1).decode()
        msg.uri = m.group(2).decode("latin-1")
        msg.version = m.group(3).decode()

    for raw in lines[1:]:
        if not raw.strip():
            continue
        if raw[:1] in (b" ", b"\t"):          # obs-fold continuation
            msg.errors.append("obs_fold")
            continue
        if b":" not in raw:
            msg.errors.append("headerless_line")
            continue
        name, _, value = raw.partition(b":")
        key = name.strip().lower().decode("latin-1", "replace")
        if not key:
            msg.errors.append("empty_header_name")
            continue
        msg.headers.setdefault(key, []).append(
            value.strip().decode("latin-1", "replace"))
    return msg


def url_host_port(url: str) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """Return (host, port, scheme). Handles bracketed IPv6 literals."""
    u = url.strip().strip("<>")
    scheme = None
    if "://" in u:
        scheme, _, rest = u.partition("://")
        scheme = scheme.lower()
    else:
        rest = u
    authority = rest.split("/", 1)[0]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    port = None
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            return None, None, scheme
        host = authority[1:end]
        tail = authority[end + 1:]
        if tail.startswith(":") and tail[1:].isdigit():
            port = int(tail[1:])
    else:
        if authority.count(":") == 1:
            host, _, p = authority.partition(":")
            if p.isdigit():
                port = int(p)
        else:
            host = authority
    if not host:
        return None, None, scheme
    if port is None and scheme in ("http", "https"):
        port = 80 if scheme == "http" else 443
    return host, port, scheme


def split_callbacks(value: str) -> List[str]:
    """CALLBACK is one or more <absolute-URI> in angle brackets."""
    found = re.findall(r"<([^>]*)>", value)
    if found:
        return [f.strip() for f in found if f.strip()]
    v = value.strip()
    return [v] if v else []


# --------------------------------------------------------------------------
# census / fingerprinting
# --------------------------------------------------------------------------
#
# This is an INVENTORY, not a detector. Earlier in the build, device-visibility
# disclosure was deliberately rejected as a finding code: SSDP advertises
# identity by design, so seeing it is not an anomaly. Nothing here emits a
# finding. The census answers "what is on this network and what is it" for
# troubleshooting and for spotting gear that does not belong.
#
# Every field records WHERE it came from, because the sources differ wildly in
# trustworthiness: a friendlyName read out of a description document is the
# device's own answer, while a vendor inferred from a SERVER token is a guess.
# A census that hid that distinction would be worse than useless for the
# "device that shouldn't be here" question.

# The UDA header set. Anything outside it is a vendor extension, and vendor
# extensions are where identity leaks (hue-bridgeid carries a Hue bridge's
# MAC-derived serial; GWID.phoscon.de marks a deCONZ gateway). The module
# does NOT carry a signature table for these -- it records them verbatim and
# mines any MAC-shaped value. That keeps the census vendor-agnostic instead of
# turning it into a signature treadmill that rots.
UDA_HEADERS = frozenset("""
host cache-control location nt nts server usn st man mx ext date opt
bootid.upnp.org configid.upnp.org nextbootid.upnp.org searchport.upnp.org
securelocation.upnp.org cpfn.upnp.org cpuuid.upnp.org tcpport.upnp.org
user-agent content-length content-type connection al 01-nls
""".split())

# Description-document fields worth keeping, with the UDA's own byte limits.
# Vendors routinely exceed them, so the cap here is generous but finite: a
# device is not allowed to put a megabyte of text in its own name.
DESC_FIELDS = {
    "friendlyName": 64, "manufacturer": 64, "modelName": 32,
    "modelNumber": 32, "modelDescription": 128, "serialNumber": 64,
    "UDN": 128, "deviceType": 64, "UPC": 12, "manufacturerURL": 128,
    "modelURL": 128, "presentationURL": 128,
}
DESC_CAP = 256                      # hard truncation, whatever the field
UPNP_DESC_NS = "urn:schemas-upnp-org:device-1-0"
MAX_STREAM_BUFFER = 64 * 1024       # per TCP stream, then give up

# A description may use a namespace PREFIX (<u:root xmlns:u="...">), so the
# document-complete check and the content gate must both tolerate one. A
# literal "</root>" test leaves a prefixed document buffered forever and the
# device silently never gets a name.
_DESC_CLOSE_RE = re.compile(rb"</(?:[A-Za-z0-9_.-]+:)?(?:root|device)\s*>")
_DESC_HINT_RE = re.compile(rb"<(?:[A-Za-z0-9_.-]+:)?friendlyName[\s>]")


@dataclass
class Provenanced:
    """A value plus how it was learned. `source` is the wire evidence."""
    value: str
    source: str
    ts: float = 0.0

    def __str__(self):
        return self.value


@dataclass
class DeviceRecord:
    """One physical/logical device, merged across every message seen."""
    key: str                                    # uuid when known, else address
    uuid: Optional[str] = None
    addresses: set = field(default_factory=set)
    macs: set = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    messages: int = 0
    fields: Dict[str, Provenanced] = field(default_factory=dict)
    device_types: set = field(default_factory=set)
    service_types: set = field(default_factory=set)
    vendor_headers: Dict[str, str] = field(default_factory=dict)
    locations: set = field(default_factory=set)
    description_seen: bool = False

    # -- field merge ------------------------------------------------------
    # Sources are ranked: the device's own description document outranks a
    # token scraped from SERVER, which outranks anything inferred. A weaker
    # source never overwrites a stronger one, so an opportunistic description
    # harvest upgrades a record and later SSDP chatter cannot downgrade it.
    SOURCE_RANK = {
        "description": 40,          # the device's own description document
        "vendor-header": 30,        # a vendor's own SSDP extension header
        "oui": 25,                  # IEEE assignment for the frame's MAC
        "server-header": 20,        # SERVER product token
        "device-type": 15,          # the URN the device claims
        "location-path": 10,        # description URL path shape
        "inferred": 5,
    }

    def learn(self, name: str, value: str, source: str, ts: float):
        value = (value or "").strip()
        if not value:
            return
        if len(value) > DESC_CAP:
            value = value[:DESC_CAP] + "...(truncated)"
        cur = self.fields.get(name)
        if cur is not None:
            if self.SOURCE_RANK.get(source, 0) <= self.SOURCE_RANK.get(cur.source, 0):
                return
        self.fields[name] = Provenanced(value, source, ts)

    def get(self, name: str, default=None):
        p = self.fields.get(name)
        return p.value if p else default

    # -- presentation -----------------------------------------------------
    @property
    def name(self) -> str:
        """Best available human label, never invented. Falls back through
        progressively weaker identity until only the address is left."""
        for k in ("friendlyName", "modelName", "modelDescription"):
            v = self.get(k)
            if v:
                return v
        dt = self.best_device_type()
        if dt:
            return f"<unnamed {dt}>"
        return f"<unnamed {sorted(self.addresses)[0]}>" if self.addresses else "<unknown>"

    def best_device_type(self) -> Optional[str]:
        """Shortest specific device type, with the URN boilerplate stripped.
        `upnp:rootdevice` is not a type -- every root device advertises it,
        so it identifies nothing and is never reported as the type."""
        cands = [t for t in self.device_types if "rootdevice" not in t.lower()]
        if not cands:
            return None
        def short(t):
            m = re.match(r"urn:[^:]+:device:([^:]+):?(\d*)", t)
            return m.group(1) if m else t
        return sorted({short(t) for t in cands}, key=len)[0]

    def vendor(self, oui_table: "OUITable") -> Optional[Provenanced]:
        """Vendor, preferring the description document's own claim, then an
        OUI assignment, then a SERVER token."""
        p = self.fields.get("manufacturer")
        if p:
            return p
        for mac in sorted(self.macs):
            if is_local_mac(mac):
                continue            # randomized/assigned: the OUI means nothing
            v = oui_table.vendor(mac)
            if v:
                return Provenanced(v, f"oui:{oui_of(mac)}", self.last_seen)
            o = oui_of(mac)
            if o:
                return Provenanced(f"OUI {o[:2]}:{o[2:4]}:{o[4:6]} (unresolved)",
                                   "oui", self.last_seen)
        return self.fields.get("serverProduct")

    def as_dict(self, oui_table: "OUITable"):
        ven = self.vendor(oui_table)
        return {
            "key": self.key,
            "uuid": self.uuid,
            "name": self.name,
            "named": "friendlyName" in self.fields,
            "device_type": self.best_device_type(),
            "vendor": ven.value if ven else None,
            "vendor_source": ven.source if ven else None,
            "addresses": sorted(self.addresses),
            "macs": sorted(self.macs),
            "locations": sorted(self.locations),
            "device_types": sorted(self.device_types),
            "service_types": sorted(self.service_types),
            "vendor_headers": dict(sorted(self.vendor_headers.items())),
            "description_seen": self.description_seen,
            "messages": self.messages,
            "first_seen": round(self.first_seen, 3),
            "last_seen": round(self.last_seen, 3),
            "fields": {k: {"value": v.value, "source": v.source}
                       for k, v in sorted(self.fields.items())},
        }


class Census:
    """Passive device census. Observes only; never fetches anything."""

    _UUID_RE = re.compile(r"uuid:((?:(?!::)[0-9A-Za-z._:-])+)", re.I)
    # SERVER is "OS/ver UPnP/ver product/ver" per UDA, but vendors use commas,
    # omit fields and reorder, so parse tolerantly rather than by position.
    _TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z0-9 ._+-]*?)/([0-9][0-9A-Za-z._-]*)")

    def __init__(self, oui_table: Optional["OUITable"] = None):
        self.oui = oui_table or OUITable()
        self.devices: Dict[str, DeviceRecord] = {}
        self._by_addr: Dict[str, str] = {}          # address -> key
        self._by_location: Dict[Tuple[str, int], str] = {}
        self._streams: Dict[Tuple, bytes] = {}
        self.stats = defaultdict(int)

    # -- record lookup ----------------------------------------------------
    def _record(self, uuid: Optional[str], addr: str, ts: float) -> DeviceRecord:
        key = f"uuid:{uuid}" if uuid else f"addr:{canon(addr)}"
        rec = self.devices.get(key)
        if rec is None and uuid:
            # the device was first seen without a USN: adopt the address record
            old = self._by_addr.get(canon(addr))
            if old and old.startswith("addr:") and old in self.devices:
                rec = self.devices.pop(old)
                rec.key, rec.uuid = key, uuid
                self.devices[key] = rec
                for a in rec.addresses:
                    self._by_addr[a] = key
        if rec is None:
            rec = DeviceRecord(key=key, uuid=uuid, first_seen=ts)
            self.devices[key] = rec
        rec.last_seen = max(rec.last_seen, ts)
        rec.first_seen = min(rec.first_seen or ts, ts)
        rec.addresses.add(canon(addr))
        self._by_addr[canon(addr)] = key
        return rec

    @staticmethod
    def _uuid_from(usn: str) -> Optional[str]:
        m = Census._UUID_RE.search(usn or "")
        return m.group(1) if m else None

    # -- SSDP side --------------------------------------------------------
    def observe_ssdp(self, pkt: Packet, msg: "HTTPUMessage"):
        """Census every advert and search RESPONSE. M-SEARCH is skipped: a
        search tells you a control point exists, not what any device is, and
        counting searches as devices would populate the census with phantoms."""
        if msg.kind == "request" and msg.method != "NOTIFY":
            return
        nts = (msg.get("nts") or "").strip().lower()
        if nts == "ssdp:byebye":
            self.stats["byebye"] += 1           # departure, carries no identity
            return

        usn = msg.get("usn") or ""
        uuid = self._uuid_from(usn)
        rec = self._record(uuid, pkt.src, pkt.ts)
        rec.messages += 1
        self.stats["ssdp_observed"] += 1

        if pkt.src_mac and not pkt.src_mac.startswith("01:00:5e") \
                and not pkt.src_mac.startswith("33:33"):
            rec.macs.add(pkt.src_mac)

        # what the device says it is
        target = (msg.get("nt") if msg.kind == "request" else msg.get("st")) or ""
        for t in (target.strip(), usn.split("::", 1)[1] if "::" in usn else ""):
            t = t.strip()
            if not t or t.lower() in ("upnp:rootdevice", "ssdp:all"):
                if t:
                    rec.device_types.add(t)
                continue
            if ":service:" in t:
                rec.service_types.add(t)
            else:
                rec.device_types.add(t)
            if ":device:" in t:
                rec.learn("deviceTypeClaimed", t, "device-type", pkt.ts)

        loc = msg.get("location")
        if loc:
            rec.locations.add(loc)
            host, port, _ = url_host_port(loc)
            if host and port:
                self._by_location[(canon(host), port)] = rec.key
            path = loc.split("/", 3)[-1] if loc.count("/") >= 3 else ""
            if path:
                rec.learn("descriptionPath", "/" + path, "location-path", pkt.ts)

        server = msg.get("server")
        if server:
            rec.learn("serverHeader", server, "server-header", pkt.ts)
            self._parse_server(rec, server, pkt.ts)

        # vendor extension headers: recorded verbatim, then mined for a MAC
        for name, values in msg.headers.items():
            if name in UDA_HEADERS:
                continue
            val = values[0]
            rec.vendor_headers[name] = val[:DESC_CAP]
            self.stats["vendor_headers"] += 1
            mac = mac_from_eui64ish(val)
            if mac and not is_local_mac(mac):
                rec.macs.add(mac)
                rec.learn("macFromHeader", mac, "vendor-header", pkt.ts)

    def _parse_server(self, rec: DeviceRecord, server: str, ts: float):
        """Pull OS and product tokens out of SERVER. UPnP/x.y is the protocol
        version, not a product, so it is recorded separately and never
        mistaken for the device's identity."""
        toks = self._TOKEN_RE.findall(server)
        products = []
        for name, ver in toks:
            name = name.strip()
            if name.lower() == "upnp":
                rec.learn("upnpVersion", ver, "server-header", ts)
                continue
            products.append((name, ver))
        if products:
            # UDA order is OS first, product last; the product is the
            # interesting one for identification.
            rec.learn("osToken", "/".join(products[0]), "server-header", ts)
            rec.learn("serverProduct", "/".join(products[-1]), "server-header", ts)

    # -- description side (opportunistic, strictly passive) ---------------
    def observe_http(self, pkt: Packet):
        """Harvest a UPnP description document that happens to cross the tap.

        This NEVER fetches anything. A control point in the house fetches the
        description as a matter of course, and when that response passes the
        tap the device's own friendlyName is in it, in cleartext. That is the
        only passive route to a real device name: SSDP itself has no name
        field, so a module that refuses to read this has no names at all.

        Because a description can span TCP segments, payloads are buffered
        per stream until the document closes.
        """
        data = pkt.payload
        if not data:
            return
        skey = (canon(pkt.src), pkt.sport, canon(pkt.dst), pkt.dport)
        buf = self._streams.get(skey, b"") + data
        if len(buf) > MAX_STREAM_BUFFER:
            self._streams.pop(skey, None)
            self.stats["stream_overflow"] += 1
            return

        if UPNP_DESC_NS.encode() not in buf and not _DESC_HINT_RE.search(buf):
            # not a description document: only keep a buffer that still could be
            if buf.lstrip()[:5].upper().startswith(b"HTTP/") and len(buf) < MAX_STREAM_BUFFER:
                self._streams[skey] = buf
            else:
                self._streams.pop(skey, None)
            return

        if not _DESC_CLOSE_RE.search(buf):
            self._streams[skey] = buf           # still arriving
            return
        self._streams.pop(skey, None)

        text = buf.decode("utf-8", "replace")
        fields = self._parse_description(text)
        if not fields:
            return
        self.stats["descriptions"] += 1

        udn = fields.get("UDN", "")
        uuid = self._uuid_from(udn)
        # the description comes FROM the device, so the packet source is it
        rec = self._record(uuid, pkt.src, pkt.ts)
        if not rec.uuid and uuid:
            rec.uuid = uuid
        rec.description_seen = True
        rec.messages += 1
        if pkt.src_mac:
            rec.macs.add(pkt.src_mac)
        for k, v in fields.items():
            rec.learn(k, v, "description", pkt.ts)
        if "deviceType" in fields:
            rec.device_types.add(fields["deviceType"])

    @staticmethod
    def _parse_description(text: str) -> Dict[str, str]:
        """Pull the identity fields out of a description document.

        Uses a real XML parser when the document is well formed, and falls
        back to element-wise extraction when it is not -- embedded devices
        ship malformed XML routinely, and a truncated capture is malformed by
        definition. Namespaces are stripped because vendors vary the prefix.
        """
        out: Dict[str, str] = {}
        body = text
        i = body.find("<?xml")
        if i == -1:
            i = body.find("<root")
        if i > 0:
            body = body[i:]

        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(body)
            dev = None
            for el in root.iter():
                if el.tag.split("}")[-1] == "device":
                    dev = el
                    break
            scope = dev if dev is not None else root
            for el in scope.iter():
                tag = el.tag.split("}")[-1]
                if tag in DESC_FIELDS and el.text and tag not in out:
                    out[tag] = el.text.strip()[:DESC_CAP]
            if out:
                return out
        except Exception:
            pass

        for tag in DESC_FIELDS:
            m = re.search(rf"<(?:\w+:)?{tag}\s*>(.*?)</(?:\w+:)?{tag}\s*>",
                          body, re.S | re.I)
            if m:
                v = re.sub(r"\s+", " ", m.group(1)).strip()
                if v:
                    out[tag] = v[:DESC_CAP]
        return out

    # -- reporting --------------------------------------------------------
    def records(self) -> List[DeviceRecord]:
        return sorted(self.devices.values(),
                      key=lambda r: (not r.description_seen, r.name.lower()))

    def mark_known(self, path: str) -> int:
        """Load a baseline of expected devices. One identifier per line --
        a uuid, a MAC or an IP; '#' comments allowed. Devices outside it are
        reported as NEW, which is the whole point of a census run against a
        network you are auditing."""
        self.known: set = getattr(self, "known", set())
        with open(path) as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    self.known.add(line.lower())
        return len(self.known)

    def is_new(self, rec: DeviceRecord) -> Optional[bool]:
        known = getattr(self, "known", None)
        if known is None:
            return None                     # no baseline supplied
        ids = {(rec.uuid or "").lower()} | {m.lower() for m in rec.macs} \
            | {a.lower() for a in rec.addresses}
        ids.discard("")
        return not (ids & known)

    def report(self, as_json=False) -> str:
        recs = self.records()
        if as_json:
            return json.dumps({
                "module": MODULE, "version": __version__,
                "census": {"devices": len(recs), "stats": dict(self.stats),
                           "oui_table": self.oui.path or None},
                "devices": [dict(r.as_dict(self.oui),
                                 **({"new": self.is_new(r)}
                                    if self.is_new(r) is not None else {}))
                            for r in recs],
            }, indent=2)

        if not recs:
            return "no devices observed"
        lines = [f"{len(recs)} device(s) observed"
                 f"{'' if self.oui.path else '   (no OUI table: --oui resolves vendor names)'}",
                 ""]
        for r in recs:
            ven = r.vendor(self.oui)
            new = self.is_new(r)
            tag = "" if new is None else ("  [NEW]" if new else "  [known]")
            lines.append(f"{r.name}{tag}")
            nm = r.fields.get("friendlyName")
            lines.append(f"    name       {nm.value} ({nm.source})" if nm else
                         "    name       -- (no description document seen; "
                         "SSDP carries no name field)")
            if ven:
                lines.append(f"    vendor     {ven.value} ({ven.source})")
            dt = r.best_device_type()
            if dt:
                lines.append(f"    type       {dt}")
            for k in ("modelName", "modelNumber", "serialNumber"):
                p = r.fields.get(k)
                if p:
                    lines.append(f"    {k:<10} {p.value} ({p.source})")
            if r.addresses:
                lines.append(f"    address    {', '.join(sorted(r.addresses))}")
            if r.macs:
                lines.append(f"    mac        {', '.join(sorted(r.macs))}")
            sp = r.fields.get("serverProduct")
            if sp:
                lines.append(f"    stack      {sp.value} ({sp.source})")
            if r.uuid:
                lines.append(f"    uuid       {r.uuid}")
            if r.service_types:
                lines.append(f"    services   {len(r.service_types)}")
            for h, v in sorted(r.vendor_headers.items()):
                lines.append(f"    +{h}  {v}")
            lines.append(f"    seen       {r.messages} message(s)")
            lines.append("")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# detection engine
# --------------------------------------------------------------------------

@dataclass
class Config:
    local_prefixes: Tuple[str, ...] = ()
    # SSDP-013 counts responses from ONE responder to ONE destination.
    # Counting total responses would fire on any media-heavy home, where a
    # single ssdp:all legitimately draws a reply from every device.
    response_ratio: int = 6           # dupes from one responder in ratio_window
    ratio_window: float = 5.0
    storm_responses: int = 40         # responses to one dst in storm_window
    storm_window: float = 10.0
    byebye_threshold: int = 20
    byebye_window: float = 10.0
    max_timeout_seconds: int = 1800   # GENA TIMEOUT ceiling
    max_message_bytes: int = MAX_SANE
    emit_low: bool = True
    census: bool = True              # inventory is always cheap to maintain
    oui_path: Optional[str] = None


class SSDPWatch:
    def __init__(self, config: Optional[Config] = None):
        self.cfg = config or Config()
        self.scope = Scope(self.cfg.local_prefixes)
        self.findings: List[Finding] = []
        self._seen: set = set()
        self.census = (Census(OUITable(self.cfg.oui_path))
                       if self.cfg.census else None)

        # per-exchange state (no baseline learning anywhere)
        self._msearch: Dict[Tuple[str, int], Deque[float]] = defaultdict(deque)
        self._resp_to: Dict[Tuple[str, int], Deque[float]] = defaultdict(deque)
        self._resp_pair: Dict[Tuple[str, str, int], Deque[float]] = defaultdict(deque)
        self._seen_hosts: set = set()
        self._mappings: Dict[Tuple[str, str], str] = {}   # (extport,proto)->owner
        self._byebye: Dict[str, Deque[float]] = defaultdict(deque)
        self._bootid: Dict[str, int] = {}
        self._location_ports: Dict[str, set] = defaultdict(set)
        self.stats = defaultdict(int)

    # -- emit -------------------------------------------------------------
    def _emit(self, pkt: Packet, code: str, **detail):
        d = REGISTRY[code]
        if d.severity == "low" and not self.cfg.emit_low:
            return
        key = (code, pkt.src, pkt.dst, tuple(sorted(
            (k, str(v)) for k, v in detail.items())))
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(
            ts=pkt.ts, code=code, severity=d.severity, title=d.title,
            cve=d.cve, tier=d.tier, src=canon(pkt.src), dst=canon(pkt.dst),
            family=pkt.family, detail=detail))

    def _noop(self, *a, **k):
        """Sink used only by the bite test's mutation harness."""
        return None

    # -- entry point ------------------------------------------------------
    def observe(self, pkt: Packet):
        self.stats["packets"] += 1
        self._seen_hosts.add(canon(pkt.src))
        if pkt.proto == "udp" and (pkt.dport == SSDP_PORT or pkt.sport == SSDP_PORT):
            self._tier_a(pkt)
        elif pkt.proto == "tcp":
            self._tier_bc(pkt)

    # -- Tier A : discovery plane ----------------------------------------
    def _tier_a(self, pkt: Packet):
        if len(pkt.payload) > self.cfg.max_message_bytes:
            self._emit(pkt, SSDP_022, reason="oversized", bytes=len(pkt.payload))
            return
        msg = parse_httpu(pkt.payload)
        if msg is None:
            if pkt.payload.strip():
                self._emit(pkt, SSDP_022, reason="unparseable",
                           head=pkt.payload[:24].decode("latin-1", "replace"))
            return
        self.stats["ssdp_messages"] += 1
        if self.census is not None:
            self.census.observe_ssdp(pkt, msg)
        if msg.errors:
            self._emit(pkt, SSDP_022, reason=",".join(sorted(set(msg.errors))))

        dst_ip = Scope.parse(pkt.dst)
        is_mcast = dst_ip is not None and dst_ip.is_multicast

        # scope posture -- applies to any multicast SSDP
        if is_mcast:
            if pkt.ttl > UDA_MAX_SANE_TTL:
                self._emit(pkt, SSDP_015, ttl=pkt.ttl,
                           field="hop_limit" if pkt.family == 6 else "ttl")
            if pkt.family == 6 and dst_ip in SSDP_V6_GROUPS:
                sc = SSDP_V6_GROUPS[dst_ip]
                if sc != "link":
                    self._emit(pkt, SSDP_016, scope=sc, group=str(dst_ip))

        if msg.kind == "request" and msg.method == "M-SEARCH":
            self._msearch_rules(pkt, msg, is_mcast)
        elif msg.kind == "request" and msg.method == "NOTIFY":
            self._notify_rules(pkt, msg)
        elif msg.kind == "response":
            self._response_rules(pkt, msg)

    def _msearch_rules(self, pkt, msg, is_mcast):
        self.stats["m_search"] += 1
        man = (msg.get("man") or "").strip()
        if man.strip('"').lower() != "ssdp:discover":
            self._emit(pkt, SSDP_020, man=man or "<absent>")

        mx = msg.get("mx")
        if mx is not None:
            try:
                mxv = int(mx.strip())
                if mxv < 1 or mxv > 5:
                    self._emit(pkt, SSDP_021, mx=mxv)
            except ValueError:
                self._emit(pkt, SSDP_021, mx=mx.strip() or "<empty>")

        st = (msg.get("st") or "").strip()
        # A MULTICAST ssdp:all is ordinary startup discovery -- every control
        # point in the house emits it. Only a UNICAST ssdp:all is a sweep:
        # it enumerates one chosen host rather than announcing interest.
        if st.lower() == "ssdp:all" and not is_mcast:
            self._emit(pkt, SSDP_011, st=st, target=canon(pkt.dst))

        if not is_mcast and self.scope.is_offlink(pkt.src):
            self._emit(pkt, SSDP_010, st=st or "<absent>", dport=pkt.dport)

        q = self._msearch[(canon(pkt.src), pkt.sport)]
        q.append(pkt.ts)
        self._prune(q, pkt.ts, self.cfg.ratio_window)

    def _notify_rules(self, pkt, msg):
        self.stats["notify"] += 1
        nts = (msg.get("nts") or "").strip().lower()
        usn = (msg.get("usn") or "").strip()
        loc = msg.get("location")

        if loc:
            host, port, _scheme = url_host_port(loc)
            if host:
                hip = Scope.parse(host)
                if hip is not None and canon(host) != canon(pkt.src):
                    self._emit(pkt, SSDP_017, location_host=canon(host))
                if hip is not None and self.scope.is_offlink(hip):
                    self._emit(pkt, SSDP_023, location_host=canon(host))
                if port:
                    self._location_ports[canon(pkt.src)].add(port)

        if nts == "ssdp:byebye":
            q = self._byebye[canon(pkt.src)]
            q.append(pkt.ts)
            self._prune(q, pkt.ts, self.cfg.byebye_window)
            if len(q) >= self.cfg.byebye_threshold:
                self._emit(pkt, SSDP_018, count=len(q),
                           window_s=self.cfg.byebye_window)

        boot = msg.get("bootid.upnp.org")
        if boot is not None and usn:
            try:
                b = int(boot.strip())
            except ValueError:
                b = None
            if b is not None:
                prev = self._bootid.get(usn)
                if prev is not None and b < prev:
                    self._emit(pkt, SSDP_019, usn=usn, bootid=b, previous=prev)
                self._bootid[usn] = max(b, prev) if prev is not None else b

    def _response_rules(self, pkt, msg):
        self.stats["responses"] += 1
        loc = msg.get("location")
        if loc:
            host, port, _ = url_host_port(loc)
            if host and port:
                self._location_ports[canon(pkt.src)].add(port)
            if host:
                hip = Scope.parse(host)
                if hip is not None and self.scope.is_offlink(hip):
                    self._emit(pkt, SSDP_023, location_host=canon(host))

        if self.scope.is_offlink(pkt.dst):
            self._emit(pkt, SSDP_012, dport=pkt.dport,
                       bytes=len(pkt.payload))

        key = (canon(pkt.dst), pkt.dport)
        q = self._resp_to[key]
        q.append(pkt.ts)
        self._prune(q, pkt.ts, self.cfg.storm_window)

        # amplification = ONE responder repeating itself at ONE victim.
        # A big house answering ssdp:all from 20 distinct devices is normal.
        pair = self._resp_pair[(canon(pkt.src), canon(pkt.dst), pkt.dport)]
        pair.append(pkt.ts)
        self._prune(pair, pkt.ts, self.cfg.ratio_window)
        if len(pair) >= self.cfg.response_ratio:
            self._emit(pkt, SSDP_013, responder=canon(pkt.src),
                       duplicates=len(pair), window_s=self.cfg.ratio_window)

        # a 200 OK is only ever a reply to M-SEARCH. One sent to a host the
        # tap has seen talking, but which never searched, is reflected traffic.
        dst_host = canon(pkt.dst)
        if dst_host in self._seen_hosts:
            searched = any(k[0] == dst_host for k, v in self._msearch.items()
                           if v and v[-1] >= pkt.ts - self.cfg.ratio_window)
            if not searched:
                self._emit(pkt, SSDP_024, dport=pkt.dport)

        if len(q) >= self.cfg.storm_responses:
            self._emit(pkt, SSDP_014, responses=len(q),
                       window_s=self.cfg.storm_window)

    # -- Tier B / C : TCP side -------------------------------------------
    def _tier_bc(self, pkt: Packet):
        data = pkt.payload
        if not data:
            return
        head = data[:16].upper()
        if head.startswith(b"SUBSCRIBE ") or head.startswith(b"UNSUBSCRIBE "):
            msg = parse_httpu(data)
            if msg:
                self._gena_rules(pkt, msg)
        elif head.startswith(b"POST ") or head.startswith(b"M-POST "):
            msg = parse_httpu(data)
            if msg and (msg.has("soapaction") or b"urn:schemas-upnp-org:service"
                        in data[:2048]):
                self._igd_rules(pkt, msg)
        elif self.census is not None:
            # An HTTP response, or the continuation of one, may be a device
            # description crossing the tap. The census decides; nothing here
            # ever requests it. No finding is produced from this path.
            self.census.observe_http(pkt)

    def _gena_rules(self, pkt, msg):
        self.stats["gena"] += 1
        if msg.method == "UNSUBSCRIBE":
            return
        cb_raw = msg.all("callback")
        if not cb_raw:
            return
        callbacks: List[str] = []
        for v in cb_raw:
            callbacks.extend(split_callbacks(v))
        if not callbacks:
            return

        if len(callbacks) > 1:
            self._emit(pkt, SSDP_003, callbacks=len(callbacks),
                       sample=callbacks[0][:80])

        for cb in callbacks:
            host, port, scheme = url_host_port(cb)
            if not host:
                self._emit(pkt, SSDP_004, callback=cb[:80], reason="unparseable")
                continue
            if scheme not in (None, "http"):
                self._emit(pkt, SSDP_004, callback=cb[:80],
                           scheme=scheme or "<none>")
            hip = Scope.parse(host)
            if hip is not None:
                if self.scope.is_offlink(hip):
                    # the CallStranger primitive
                    self._emit(pkt, SSDP_001, callback_host=canon(host),
                               callback_port=port if port else "-",
                               service=(msg.uri or "")[:60])
                elif canon(host) != canon(pkt.src):
                    self._emit(pkt, SSDP_002, callback_host=canon(host),
                               subscriber=canon(pkt.src))
            else:
                # DNS name in CALLBACK: cannot be resolved passively
                self._emit(pkt, SSDP_004, callback=cb[:80], reason="named_host")
            if port is not None and port in SENSITIVE_PORTS and port != 80:
                self._emit(pkt, SSDP_004, callback_port=port,
                           service_name=SENSITIVE_PORTS[port])

        tmo = msg.get("timeout")
        if tmo:
            t = tmo.strip().lower()
            if t in ("second-infinite", "infinite"):
                self._emit(pkt, SSDP_005, timeout=t)
            elif t.startswith("second-"):
                try:
                    secs = int(t.split("-", 1)[1])
                    if secs > self.cfg.max_timeout_seconds:
                        self._emit(pkt, SSDP_005, timeout_s=secs)
                except ValueError:
                    pass

    _SOAP_ACTION_RE = re.compile(r'[#"]([A-Za-z]+)"?\s*$')

    def _igd_rules(self, pkt, msg):
        self.stats["igd"] += 1
        action_hdr = msg.get("soapaction") or ""
        m = self._SOAP_ACTION_RE.search(action_hdr.strip())
        action = m.group(1) if m else ""
        body = msg.body.decode("latin-1", "replace")
        if not action:
            m2 = re.search(r"<(?:\w+:)?(AddPortMapping|DeletePortMapping"
                           r"|DeletePortMappingRange|AddAnyPortMapping)\b", body)
            action = m2.group(1) if m2 else ""

        if self.scope.is_offlink(pkt.src):
            self._emit(pkt, SSDP_031, action=action or "<unknown>",
                       dport=pkt.dport)

        def arg(name):
            mm = re.search(rf"<(?:\w+:)?{name}>\s*(.*?)\s*</", body, re.S)
            return mm.group(1).strip() if mm else None

        ext = arg("NewExternalPort") or arg("NewStartPort")
        proto = (arg("NewProtocol") or "").upper()

        if action in ("AddPortMapping", "AddAnyPortMapping"):
            if ext:
                self._mappings[(ext, proto)] = canon(pkt.src)
            client = arg("NewInternalClient")
            if client:
                cip = Scope.parse(client)
                if cip is not None and canon(client) != canon(pkt.src):
                    self._emit(pkt, SSDP_030, internal_client=canon(client),
                               requester=canon(pkt.src),
                               external_port=arg("NewExternalPort") or "-")
            iport = arg("NewInternalPort")
            if iport and iport.isdigit() and int(iport) in SENSITIVE_PORTS:
                self._emit(pkt, SSDP_032, internal_port=int(iport),
                           service_name=SENSITIVE_PORTS[int(iport)],
                           external_port=arg("NewExternalPort") or "-")
            lease = arg("NewLeaseDuration")
            if lease is not None and lease.strip() in ("0", ""):
                self._emit(pkt, SSDP_034, lease="0 (indefinite)",
                           external_port=arg("NewExternalPort") or "-")

        elif action in ("DeletePortMapping", "DeletePortMappingRange"):
            # Deleting your own mapping is ordinary housekeeping. Only a
            # delete aimed at a mapping THIS host did not create is a finding,
            # and only once the tap has actually witnessed the Add.
            owner = self._mappings.get((ext, proto)) if ext else None
            if owner is not None and owner != canon(pkt.src):
                self._emit(pkt, SSDP_033, action=action,
                           external_port=ext or "-",
                           owner=owner, requester=canon(pkt.src))

    @staticmethod
    def _prune(q: Deque[float], now: float, window: float):
        while q and q[0] < now - window:
            q.popleft()

    # -- reporting --------------------------------------------------------
    def census_report(self, as_json=False) -> str:
        if self.census is None:
            return "census disabled"
        return self.census.report(as_json=as_json)

    def report(self, as_json=False) -> str:
        if as_json:
            return json.dumps({
                "module": MODULE, "version": __version__,
                "stats": dict(self.stats),
                "findings": [f.as_dict() for f in self.findings],
            }, indent=2)
        if not self.findings:
            return "no findings"
        return "\n".join(f.line() for f in self.findings)


# --------------------------------------------------------------------------
# live capture (passive, read-only) + pcap offline
# --------------------------------------------------------------------------

# Tier A is UDP/1900. Tier B/C ride TCP on whatever description port SSDP
# advertised in LOCATION, so the port is not known ahead of capture.
#
# Two tempting filters are both WRONG:
#   "tcp portrange 49152-65535" -- ephemeral SOURCE ports live in that range,
#     so it captures the whole household's browsing, the opposite of intent.
#   a payload-byte match on the method token -- libpcap's tcp[offset]
#     arithmetic is IPv4-ONLY, and the ip6[] workaround breaks on extension
#     headers. That filter would silently go blind on every IPv6 SUBSCRIBE,
#     which is the same BPF/IPv6-EH trap that bit juniperwatch, and it breaks
#     the dual-stack rule by construction.
#
# So the BPF stays coarse and provably not-blind, and the precision lives in
# Python where no such limitation exists. _wanted() runs on every packet
# whether or not libpcap is present, so behaviour is identical either way.
# A home link carries little enough TCP for this to be the cheap trade.
BPF = "(udp port 1900) or tcp"

# GENA and SOAP control requests, plus the description fetch. The HTTP
# RESPONSE token is here because a device description crossing the tap is the
# only passive source of a real device name -- SSDP has no name field at all.
UPNP_TCP_METHODS = (b"SUBSCRIBE ", b"UNSUBSCRIBE ", b"POST ", b"M-POST ")
HTTP_RESPONSE_TOKEN = b"HTTP/"


def _wanted(p) -> bool:
    """Precise second-stage filter. Dual-stack by construction: it reads the
    decoded payload, never a hard-coded header offset.

    TCP is admitted on a method token, an HTTP response token, or -- for a
    description that spans segments -- a continuation carrying description
    XML. Ordinary TLS fails all three, because a TLS record starts with 0x16
    and never with an HTTP token.
    """
    from scapy.layers.inet import TCP, UDP
    if UDP in p:
        return p[UDP].sport == SSDP_PORT or p[UDP].dport == SSDP_PORT
    if TCP in p:
        pay = bytes(p[TCP].payload)
        if not pay:
            return False
        head = pay[:16].upper()
        if any(head.startswith(m) for m in UPNP_TCP_METHODS):
            return True
        if head.startswith(HTTP_RESPONSE_TOKEN) or head.startswith(b"GET "):
            return True
        # mid-document continuation of a description already in flight
        return bool(UPNP_DESC_NS.encode() in pay[:2048]
                    or _DESC_HINT_RE.search(pay[:2048])
                    or _DESC_CLOSE_RE.search(pay[-512:]))
    return False


def _scapy_to_packet(p) -> Optional[Packet]:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    smac = dmac = None
    if Ether in p:
        smac, dmac = norm_mac(p[Ether].src), norm_mac(p[Ether].dst)
    if IP in p:
        src, dst, ttl = p[IP].src, p[IP].dst, p[IP].ttl
    elif IPv6 in p:
        src, dst, ttl = p[IPv6].src, p[IPv6].dst, p[IPv6].hlim
    else:
        return None
    if UDP in p:
        l4, proto = p[UDP], "udp"
    elif TCP in p:
        l4, proto = p[TCP], "tcp"
    else:
        return None
    payload = bytes(l4.payload)
    if not payload:
        return None
    return Packet(ts=float(p.time), proto=proto, src=src, dst=dst,
                  sport=int(l4.sport), dport=int(l4.dport),
                  payload=payload, ttl=int(ttl),
                  src_mac=smac, dst_mac=dmac)


def run_live(iface: str, engine: SSDPWatch, count: int = 0, timeout=None,
             bpf: Optional[str] = None, on_finding=None):
    """Passive capture. Opens a receive socket only -- never transmits."""
    from scapy.all import sniff
    from scapy.error import Scapy_Exception

    seen = 0

    def handler(p):
        nonlocal seen
        if not _wanted(p):          # always applied, libpcap or not
            return
        pk = _scapy_to_packet(p)
        if not pk:
            return
        pk.iface = iface
        before = len(engine.findings)
        engine.observe(pk)
        if on_finding:
            for f in engine.findings[before:]:
                on_finding(f)

    kw = dict(iface=iface, prn=handler, store=False,
              count=count, timeout=timeout)
    try:
        sniff(filter=bpf or BPF, **kw)
    except Scapy_Exception as exc:
        # scapy compiles BPF through libpcap. A stripped host (a bare WSL
        # image, a minimal Pi build) has none, and the filter -- not the
        # capture -- is what fails. Fall back to an unfiltered socket with
        # the same predicate applied in Python.
        if "libpcap" not in str(exc).lower() and "filter" not in str(exc).lower():
            raise
        print(f"{MODULE}: no libpcap, capturing unfiltered and selecting "
              f"in software", file=sys.stderr)
        sniff(lfilter=_wanted, **kw)


def run_pcap(path: str, engine: SSDPWatch):
    from scapy.all import rdpcap
    for p in rdpcap(path):
        pk = _scapy_to_packet(p)
        if pk:
            engine.observe(pk)


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(prog=MODULE,
                                 description="Passive SSDP/UPnP protocol detector")
    ap.add_argument("-i", "--iface", help="interface for live passive capture")
    ap.add_argument("-r", "--pcap", help="read from pcap instead of the wire")
    ap.add_argument("--local", action="append", default=[],
                    metavar="PREFIX", help="additional on-link prefix")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--count", type=int, default=0)
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--census", action="store_true",
                    help="report the device inventory instead of findings")
    ap.add_argument("--both", action="store_true",
                    help="report findings and then the inventory")
    ap.add_argument("--oui", metavar="FILE",
                    help="IEEE oui.txt or Wireshark manuf, to resolve vendor names")
    ap.add_argument("--known", metavar="FILE",
                    help="baseline of expected uuids/MACs/IPs; others report as NEW")
    ap.add_argument("--no-census", action="store_true",
                    help="disable inventory collection entirely")
    ap.add_argument("--bpf", help="override the capture filter")
    ap.add_argument("--no-low", action="store_true", help="suppress low severity")
    ap.add_argument("--codes", action="store_true", help="print finding registry")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--version", action="version",
                    version=f"{MODULE} {__version__}")
    args = ap.parse_args(argv)

    if args.codes:
        for c in sorted(REGISTRY.values(), key=lambda d: d.code):
            cve = f"  {c.cve}" if c.cve else ""
            print(f"{c.code}  tier {c.tier}  {c.severity:<6} {c.title}{cve}")
        return 0

    if args.selftest:
        from ssdpwatch_selftest import run_selftest
        return run_selftest()

    cfg = Config(local_prefixes=tuple(args.local), emit_low=not args.no_low,
                 census=not args.no_census, oui_path=args.oui)
    engine = SSDPWatch(cfg)
    if args.known:
        if engine.census is None:
            ap.error("--known needs the census enabled")
        engine.census.mark_known(args.known)

    if args.pcap:
        run_pcap(args.pcap, engine)
    elif args.iface:
        run_live(args.iface, engine, count=args.count, timeout=args.timeout,
                 bpf=args.bpf, on_finding=lambda f: print(f.line(), flush=True))
    else:
        ap.error("need -i/--iface or -r/--pcap")

    if args.census and not args.both:
        print(engine.census_report(as_json=args.json))
    elif args.both:
        print(engine.report(as_json=args.json))
        print()
        print(engine.census_report(as_json=args.json))
    else:
        print(engine.report(as_json=args.json))
    return 0


if __name__ == "__main__":
    sys.exit(main())
