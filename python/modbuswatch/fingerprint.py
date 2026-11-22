"""
modbuswatch — LoRaWAN device and gateway fingerprinting.

Enriches the MBW-100 census with identity and behaviour, the same treatment
Matter, Thread and Z-Wave got in DNS Doctor. LoRaWAN has no user-set names, so
fingerprinting here means identifiers and behaviour, never labels:

  identity   DevEUI OUI -> vendor, JoinEUI as seen, DevAddr -> NetID -> operator,
             gateway EUI OUI -> vendor, gateway coordinates from stat
  behaviour  per-DevAddr datarate, channel, RSSI/SNR range, uplink cadence,
             FPort set, payload size range, ADR bit

Nothing is guessed. An OUI that does not resolve is reported raw, a NetID that
is not in the bundled assignment list is reported as its type and value, and
application payloads stay encrypted throughout.

The OUI snapshot (`oui_snapshot.dat`) is a sorted fixed-width file searched by
seek, not loaded into a dict: 35k entries cost two or three disk reads and a few
hundred bytes of RAM, which keeps the module inside its Pi Zero 2W budget. The
header line records the source and generation date; regenerate it from the IEEE
registry to refresh.
"""

from __future__ import annotations

import os
import statistics
from collections import deque
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
OUI_SNAPSHOT = os.path.join(HERE, "oui_snapshot.dat")

_HDR_LEN = 96          # bytes of ASCII header before the first record
_PREFIX_LEN = 6        # "a84041"
_ORG_LEN = 50
_REC_LEN = _PREFIX_LEN + _ORG_LEN

# Bounded state, sized to the preflight's budget.
MAX_DEVADDRS_PER_GW = 8192
MAX_DEVEUIS_PER_GW = 2048
MAX_SET = 16           # per-profile sets: datr, chan, fport
CADENCE_MIN_SAMPLES = 8
CADENCE_WINDOW = 32

# Coordinates are rounded before they reach a finding so the finding does not
# re-leak precise siting. Three decimals is about 100 m.
COORD_DECIMALS = 3


# ---------------------------------------------------------------------------
# IEEE OUI lookup
# ---------------------------------------------------------------------------
class OuiRegistry:
    """Binary search over the bundled fixed-width IEEE OUI snapshot."""

    def __init__(self, path: str = OUI_SNAPSHOT):
        self.path = path
        self._n = None
        self._version = None
        self._fh = None

    def _open(self):
        if self._fh is not None:
            return self._fh
        if not os.path.exists(self.path):
            return None
        fh = open(self.path, "rb")
        hdr = fh.read(_HDR_LEN).decode("ascii", "replace").strip()
        self._version = hdr
        size = os.path.getsize(self.path)
        self._n = max((size - _HDR_LEN) // _REC_LEN, 0)
        self._fh = fh
        return fh

    @property
    def version(self) -> str | None:
        self._open()
        return self._version

    @property
    def count(self) -> int:
        self._open()
        return self._n or 0

    def lookup(self, oui: str) -> str | None:
        """oui: 6 lowercase hex chars. Returns the organisation, or None."""
        fh = self._open()
        if fh is None or not self._n:
            return None
        target = oui.lower().encode("ascii")
        if len(target) != _PREFIX_LEN:
            return None
        lo, hi = 0, self._n - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            fh.seek(_HDR_LEN + mid * _REC_LEN)
            rec = fh.read(_REC_LEN)
            if len(rec) < _REC_LEN:
                return None
            prefix = rec[:_PREFIX_LEN]
            if prefix == target:
                return rec[_PREFIX_LEN:].decode("ascii", "replace").strip() or None
            if prefix < target:
                lo = mid + 1
            else:
                hi = mid - 1
        return None


REGISTRY = OuiRegistry()


def eui_vendor(eui_hex: str | None) -> tuple[str | None, str | None]:
    """
    (oui, vendor) for an EUI-48/64 hex string. vendor is None when the OUI does
    not resolve -- reported raw rather than guessed. An IEEE "Registration
    Authority" block means the assignee is a 28/36-bit sub-block holder the
    public registry does not name, which is reported as such.
    """
    if not eui_hex or len(eui_hex) < _PREFIX_LEN:
        return None, None
    oui = eui_hex[:_PREFIX_LEN].lower()
    return oui, REGISTRY.lookup(oui)


# ---------------------------------------------------------------------------
# DevAddr -> NetID -> operator
# ---------------------------------------------------------------------------
# LoRaWAN DevAddr types: (prefix bit length, NwkID bits, NwkAddr bits).
# The prefix is `type` ones followed by a zero, except type 7 which is all ones.
_DEVADDR_TYPES = [
    (1, 6, 25),
    (2, 6, 24),
    (3, 9, 20),
    (4, 11, 17),
    (5, 12, 15),
    (6, 13, 13),
    (7, 15, 10),
    (8, 17, 7),
]

# Bundled LoRa Alliance NetID notes. Deliberately tiny: only assignments that
# are specification-level or unambiguous. Everything else is reported as its
# type and value -- an operator name is never guessed from a NetID.
NETID_NOTES = {
    0x000000: "private/experimental (NetID type 0, reserved by spec)",
    0x000001: "private/experimental (NetID type 0, reserved by spec)",
    0x000013: "The Things Network",
}
NETID_LIST_VERSION = "bundled v1 (spec-reserved + TTN only; extend from the "
NETID_LIST_VERSION += "LoRa Alliance assignment list)"


def netid_from_devaddr(dev_addr_hex: str) -> tuple[int, int, int] | None:
    """
    (type, nwkid, netid) from a DevAddr. NetID is the 24-bit (type << 21) | NwkID.

    Worked check: TTN's 0x26011bda -> leading bit 0 -> type 0, NwkID 0x13,
    NetID 0x000013, which is TTN's assignment.
    """
    try:
        val = int(dev_addr_hex, 16)
    except (TypeError, ValueError):
        return None
    if not 0 <= val <= 0xFFFFFFFF:
        return None
    for t, (plen, nwkid_bits, _addr_bits) in enumerate(_DEVADDR_TYPES):
        # prefix for type t is t ones then a zero (type 7: eight ones)
        shift = 32 - plen
        prefix = val >> shift
        # type t's prefix is t ones followed by a zero; type 7 is eight ones
        expected = 0xFF if t == 7 else (((1 << t) - 1) << 1)
        if prefix == expected:
            nwkid = (val >> (32 - plen - nwkid_bits)) & ((1 << nwkid_bits) - 1)
            return t, nwkid, (t << 21) | nwkid
    return None


def netid_label(netid: int) -> str:
    return NETID_NOTES.get(netid, "operator not in bundled list")


# ---------------------------------------------------------------------------
# Regional band from rxpk frequency
# ---------------------------------------------------------------------------
# Overlapping allocations are real (IN865 sits inside EU868; AU915 inside
# US915), so a frequency that fits more than one plan reports all candidates.
_BANDS = [
    (433.05, 434.79, "EU433"),
    (470.0, 510.0, "CN470"),
    (779.0, 787.0, "CN779"),
    (863.0, 870.0, "EU868"),
    (865.0, 867.0, "IN865"),
    (902.0, 928.0, "US915"),
    (915.0, 928.0, "AU915"),
    (920.0, 925.0, "AS923"),
    (923.0, 925.0, "KR920"),
]


def bands_for(freq_mhz: float) -> list[str]:
    try:
        f = float(freq_mhz)
    except (TypeError, ValueError):
        return []
    return sorted({name for lo, hi, name in _BANDS if lo <= f <= hi})


# ---------------------------------------------------------------------------
# Per-DevAddr behavioural profile
# ---------------------------------------------------------------------------
@dataclass
class DeviceProfile:
    datr: set = field(default_factory=set)
    chans: set = field(default_factory=set)
    fports: set = field(default_factory=set)
    bands: set = field(default_factory=set)
    rssi_min: float | None = None
    rssi_max: float | None = None
    lsnr_min: float | None = None
    lsnr_max: float | None = None
    size_min: int | None = None
    size_max: int | None = None
    adr_seen: bool = False
    adr_clear_seen: bool = False
    uplinks: deque = field(default_factory=lambda: deque(maxlen=CADENCE_WINDOW))

    def observe(self, phy, now: float) -> None:
        rx = getattr(phy, "rx", None) or {}
        _bounded_add(self.datr, rx.get("datr"))
        _bounded_add(self.chans, rx.get("chan"))
        _bounded_add(self.fports, phy.fport)
        for b in bands_for(rx.get("freq")):
            _bounded_add(self.bands, b)
        self.rssi_min, self.rssi_max = _range(self.rssi_min, self.rssi_max, rx.get("rssi"))
        self.lsnr_min, self.lsnr_max = _range(self.lsnr_min, self.lsnr_max, rx.get("lsnr"))
        self.size_min, self.size_max = _range(self.size_min, self.size_max, rx.get("size"))
        if phy.adr is True:
            self.adr_seen = True
        elif phy.adr is False:
            self.adr_clear_seen = True
        self.uplinks.append(now)

    @property
    def cadence_s(self) -> float | None:
        """
        Median interval between uplinks, once at least CADENCE_MIN_SAMPLES are
        seen. A fixed period is what identifies metering and sensor classes; the
        median rather than the mean so one gap does not distort it.
        """
        if len(self.uplinks) < CADENCE_MIN_SAMPLES:
            return None
        ts = list(self.uplinks)
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b > a]
        return round(statistics.median(gaps), 3) if gaps else None

    def summary(self) -> str:
        bits = []
        if self.datr:
            bits.append("datr=" + "/".join(sorted(str(d) for d in self.datr)))
        if self.bands:
            bits.append("band=" + "/".join(sorted(self.bands)))
        if self.chans:
            bits.append("chan=" + ",".join(str(c) for c in sorted(map(str, self.chans))))
        if self.rssi_min is not None:
            bits.append(f"rssi={self.rssi_min}..{self.rssi_max}")
        if self.lsnr_min is not None:
            bits.append(f"lsnr={self.lsnr_min}..{self.lsnr_max}")
        if self.size_min is not None:
            bits.append(f"size={self.size_min}..{self.size_max}")
        if self.fports:
            bits.append("fport=" + ",".join(str(p) for p in sorted(self.fports)))
        adr = ("on" if self.adr_seen else "") + ("/off" if self.adr_clear_seen else "")
        if adr:
            bits.append("adr=" + adr.strip("/"))
        c = self.cadence_s
        if c is not None:
            bits.append(f"cadence={c}s")
        elif self.uplinks:
            bits.append(f"cadence=pending({len(self.uplinks)}/{CADENCE_MIN_SAMPLES})")
        return " ".join(bits)


def _hostport(addr: str, port) -> str:
    """host:port, with IPv6 literals bracketed per RFC 3986."""
    host = f"[{addr}]" if ":" in str(addr) else str(addr)
    return f"{host}:{port}" if port else host


def _bounded_add(s: set, value) -> None:
    if value is None:
        return
    if len(s) < MAX_SET:
        s.add(value)


def _range(lo, hi, value):
    if value is None:
        return lo, hi
    try:
        v = float(value) if isinstance(value, float) else value
    except (TypeError, ValueError):
        return lo, hi
    if not isinstance(v, (int, float)):
        return lo, hi
    return (v if lo is None else min(lo, v), v if hi is None else max(hi, v))


# ---------------------------------------------------------------------------
# Per-gateway fingerprint
# ---------------------------------------------------------------------------
@dataclass
class GatewayFingerprint:
    """
    Accumulating identity for one (family, gateway EUI).

    MBW-100 fires once per gateway EUI and carries this object, so a finding
    rendered later -- by the reporting layer, or from the log -- shows the
    running counts the preflight asks for rather than a first-sight snapshot.
    """
    family: int = 0
    gw_eui: str = ""
    gw_oui: str | None = None
    gw_vendor: str | None = None
    proto_version: int | None = None
    gw_addrs: set = field(default_factory=set)
    server_addrs: set = field(default_factory=set)
    server_port: int | None = None
    dev_addrs: set = field(default_factory=set)
    dev_euis: set = field(default_factory=set)
    join_euis: set = field(default_factory=set)
    device_vendors: dict = field(default_factory=dict)   # oui -> vendor or None
    netids: dict = field(default_factory=dict)           # netid -> (type, label)
    stat_keys: set = field(default_factory=set)
    location: tuple | None = None                        # (lat, lon, alt) rounded
    first_seen: float = 0.0
    last_seen: float = 0.0

    def note_gateway(self, oui, vendor, version, src, dst, dport) -> None:
        self.gw_oui, self.gw_vendor = oui, vendor
        self.proto_version = version
        _bounded_add(self.gw_addrs, src)
        if dst is not None:
            _bounded_add(self.server_addrs, dst)
        if dport is not None:
            self.server_port = dport

    def note_join(self, dev_eui: str, join_eui: str | None) -> None:
        if len(self.dev_euis) < MAX_DEVEUIS_PER_GW:
            self.dev_euis.add(dev_eui)
        oui, vendor = eui_vendor(dev_eui)
        if oui and len(self.device_vendors) < MAX_SET:
            self.device_vendors[oui] = vendor
        if join_eui:
            _bounded_add(self.join_euis, join_eui)

    def note_uplink(self, dev_addr: str) -> None:
        if len(self.dev_addrs) < MAX_DEVADDRS_PER_GW:
            self.dev_addrs.add(dev_addr)
        got = netid_from_devaddr(dev_addr)
        if got and len(self.netids) < MAX_SET:
            t, _nwkid, netid = got
            self.netids[netid] = (t, netid_label(netid))

    def note_stat(self, stat: dict) -> tuple | None:
        """Record the stat key set and coordinates. Returns rounded coords if new."""
        for k in list(stat)[:MAX_SET]:
            _bounded_add(self.stat_keys, k)
        lat, lon = stat.get("lati"), stat.get("long")
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            return None
        if lat == 0 and lon == 0:
            return None          # the forwarder's "no GPS fix" value
        alt = stat.get("alti")
        coords = (round(float(lat), COORD_DECIMALS), round(float(lon), COORD_DECIMALS),
                  alt if isinstance(alt, (int, float)) else None)
        first = self.location is None
        self.location = coords
        return coords if first else None

    # --- rendering ---
    def identity_summary(self) -> str:
        bits = [f"eui={self.gw_eui}"]
        if self.gw_vendor:
            bits.append(f"vendor={self.gw_vendor}")
        elif self.gw_oui:
            bits.append(f"oui={self.gw_oui} (unresolved)")
        if self.proto_version is not None:
            bits.append(f"gwmp=v{self.proto_version}")
        if self.server_addrs:
            # Bracket IPv6 literals: "2001:db8::9:1700" is ambiguous.
            srv = ",".join(_hostport(a, self.server_port)
                           for a in sorted(self.server_addrs))
            bits.append(f"server={srv}")
        return " ".join(bits)

    def census_summary(self) -> str:
        bits = [self.identity_summary(),
                f"devaddrs={len(self.dev_addrs)}", f"deveuis={len(self.dev_euis)}"]
        if self.netids:
            bits.append("netid=" + ",".join(
                f"0x{n:06x}/type{t}({lab})" for n, (t, lab) in sorted(self.netids.items())))
        if self.device_vendors:
            bits.append("device_vendors=" + ",".join(
                (v or f"{o} (unresolved)") for o, v in sorted(self.device_vendors.items())))
        if self.join_euis:
            bits.append("joineui=" + ",".join(sorted(self.join_euis)))
        if self.stat_keys:
            bits.append("stat_keys=" + ",".join(sorted(self.stat_keys)))
        return " | ".join(bits)
