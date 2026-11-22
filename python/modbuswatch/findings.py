"""
modbuswatch — finding registry and detector engine.

Severity is operator-facing, not CVSS. Confidence is honest: 'high' only when an
action was directly observed; 'medium'/'low' for triggers and exposures that
cannot confirm a vulnerable or compromised host from traffic alone.

Passive only. Nothing here transmits.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field

try:  # Ragnar: relative inside the vendored package, bare for flat standalone.
    from .parser import (
        Adu, FC, WRITE_FCS,
        DIAG_RESTART_COMM, DIAG_FORCE_LISTEN_ONLY, DIAG_CLEAR_COUNTERS,
        MEI_READ_DEVICE_ID, MODBUS_SECURITY_PORT,
        diag_subfunction, mei_type, umas_subcode,
    )
    from .state import (
        FlowKey, Baseline, SweepTracker, EnumTracker, UmasSession,
        GatewayServerMap, GatewayCensus, DevNonceTracker, FCntTracker,
        LORA_FCNT_LOW, LORA_FCNT_HIGH, LORA_GW_WINDOW_S,
    )
    from . import lora as L
    from . import fingerprint as FP
except ImportError:
    from parser import (
        Adu, FC, WRITE_FCS,
        DIAG_RESTART_COMM, DIAG_FORCE_LISTEN_ONLY, DIAG_CLEAR_COUNTERS,
        MEI_READ_DEVICE_ID, MODBUS_SECURITY_PORT,
        diag_subfunction, mei_type, umas_subcode,
    )
    from state import (
        FlowKey, Baseline, SweepTracker, EnumTracker, UmasSession,
        GatewayServerMap, GatewayCensus, DevNonceTracker, FCntTracker,
        LORA_FCNT_LOW, LORA_FCNT_HIGH, LORA_GW_WINDOW_S,
    )
    import lora as L
    import fingerprint as FP

# code -> (title, class, severity, confidence)
REGISTRY = {
    "MBW-001": ("Unauthorized write from non-baseline master", "abuse", "high", "high"),
    "MBW-002": ("FC8 sub-4 Force Listen Only Mode", "abuse", "high", "high"),
    "MBW-003": ("FC8 restart/clear-counters", "abuse", "medium", "high"),
    "MBW-004": ("Unexpected master issuing function codes", "abuse", "medium", "medium"),
    "MBW-010": ("FC90 UMAS activity present", "abuse", "medium", "high"),
    "MBW-011": ("ModiPwn sub-code sequence (CVE-2021-22779 chain)", "abuse", "high", "medium"),
    "MBW-020": ("FC43/MEI-14 device enumeration burst", "exposure", "low", "medium"),
    "MBW-021": ("Unit-ID sweep against one host", "exposure", "low", "medium"),
    "MBW-030": ("Malformed MBAP/PDU framing (libmodbus trigger)", "exposure", "medium", "medium"),
    "MBW-040": ("Modbus/TCP cleartext on non-isolated segment", "exposure", "low", "low"),
    "MBW-041": ("Plain 502 where 802/TLS option exists", "exposure", "info", "low"),
    "MBW-042": ("Cleartext Modbus on 502, no secure Modbus seen for peer", "exposure", "info", "low"),
    # --- LoRaWAN gateway backhaul (Semtech GWMP over UDP) ---
    "MBW-100": ("LoRaWAN gateway backhaul present", "exposure", "info", "high"),
    "MBW-101": ("LoRaWAN backhaul cleartext, PHYPayloads recoverable", "exposure", "medium", "high"),
    "MBW-102": ("Gateway EUI claimed from two source addresses", "abuse", "high", "medium"),
    "MBW-103": ("PULL_RESP downlink from a non-server address", "abuse", "high", "medium"),
    "MBW-104": ("JoinRequest DevNonce reuse (join replay)", "abuse", "medium", "medium"),
    "MBW-105": ("Uplink frame-counter reset", "abuse", "high", "medium"),
    "MBW-106": ("Gateway location exposed in cleartext backhaul", "exposure", "medium", "high"),
}

# Findings on the LoRaWAN backhaul tier: no Modbus unit id applies, so the
# rendered line names the gateway/server pair instead.
LORA_CODES = frozenset({"MBW-100", "MBW-101", "MBW-102", "MBW-103",
                        "MBW-104", "MBW-105", "MBW-106"})

# Codes reported once per flow (family, master, slave, unit) rather than per request.
ONCE_PER_FLOW = frozenset({"MBW-004", "MBW-040", "MBW-041", "MBW-103"})


@dataclass
class Finding:
    code: str
    key: FlowKey
    detail: str
    ts: float
    # Live fingerprint record for the census codes. Held by reference, not
    # copied, so a finding rendered later -- by the reporting layer, or replayed
    # from the log -- shows the running counts the preflight asks for instead of
    # a first-sight snapshot. None for every non-census code.
    fp: object = None

    @property
    def spec(self):
        return REGISTRY[self.code]

    @property
    def meta(self) -> str:
        """The fingerprint metadata as it stands now, or ''."""
        if self.fp is None:
            return ""
        try:
            return self.fp.census_summary()
        except Exception:
            return ""

    def __str__(self) -> str:
        title, cls, sev, conf = self.spec
        fam = "v6" if self.key.family == socket.AF_INET6 else "v4"
        head = (f"[{self.code}] {sev.upper()} ({conf} conf) {title} "
                f"| {fam} {self.key.src}->{self.key.dst}")
        if self.code not in LORA_CODES:
            head += f" unit={self.key.unit_id}"
        line = f"{head} | {self.detail}"
        m = self.meta
        return f"{line} | {m}" if m else line


@dataclass
class LoraConfig:
    """
    Operator configuration for the LoRaWAN backhaul tier.

    ports     : UDP ports carrying Semtech GWMP (default 1700)
    servers   : declared network-server addresses, for an anycast or
                load-balanced server; empty = derive from the gateway's own
                PULL_DATA destination
    gw_allow  : per-EUI declared source addresses, {eui: {addr, ...}}; an EUI
                with a list treats any other source as MBW-102 at once
    fcnt_low / fcnt_high : the MBW-105 reset thresholds
    gw_window : MBW-102 conflict window, seconds

    There is no server-learning window: the server is the destination of the
    gateway's PULL_DATA, which needs no learning (state.GatewayServerMap).
    """
    ports: tuple = (L.DEFAULT_LORA_PORT,)
    servers: frozenset = frozenset()
    gw_allow: dict = field(default_factory=dict)
    fcnt_low: int = LORA_FCNT_LOW
    fcnt_high: int = LORA_FCNT_HIGH
    gw_window: float = LORA_GW_WINDOW_S

    @property
    def enabled(self) -> bool:
        return bool(self.ports)


class Engine:
    """
    Feed decoded ADUs with their flow key; collect findings. One engine per
    sensor. Dual-stack by construction: every tracker is family-aware.
    """

    def __init__(self, baseline: Baseline | None = None, ot_subnets=None,
                 security_hosts=None, lora: "LoraConfig | None" = None):
        self.baseline = baseline or Baseline()
        self.sweeps = SweepTracker()
        self.enums = EnumTracker()
        self.umas = UmasSession()
        self.findings: list[Finding] = []
        # operator-declared OT subnets as list of (family, ip_network); enables MBW-040
        self.ot_subnets = ot_subnets or []
        # (family, host) pairs ever seen speaking port 802; enables MBW-041/042
        self.security_hosts = security_hosts or set()
        # dedupe state
        self._flow_reported: set[tuple[str, FlowKey]] = set()
        # (family, slave) already reported for MBW-042
        self._mbw042_reported: set[tuple[int, str]] = set()

        # --- LoRaWAN backhaul tier ---
        # No baseline and no learning window: every rule here is per-packet or
        # per-exchange inside a bounded window, and server identity comes from
        # the gateway's own PULL_DATA destination rather than from anything a
        # sender claims. LoRa traffic therefore never touches the Modbus
        # baseline, which would otherwise leave later Modbus masters unlearned.
        self.lora = lora or LoraConfig()
        self.lora_servers = GatewayServerMap(declared=self.lora.servers)
        self.gw_census = GatewayCensus(window_s=self.lora.gw_window,
                                       gw_allow=self.lora.gw_allow)
        self.devnonces = DevNonceTracker()
        self.fcnts = FCntTracker(low=self.lora.fcnt_low, high=self.lora.fcnt_high)
        # (family, gw_eui) already reported for MBW-100 / MBW-101 / MBW-106
        self._lora_census_reported: set[tuple[int, str]] = set()
        self._lora_cleartext_reported: set[tuple[int, str]] = set()
        self._lora_location_reported: set[tuple[int, str]] = set()
        # fingerprints: (family, gw_eui) -> GatewayFingerprint
        self.gw_fingerprints: dict[tuple[int, str], FP.GatewayFingerprint] = {}
        self._lora_dport: int | None = None
        self._pending_coords = None
        # (family, dev_addr) -> DeviceProfile
        self.device_profiles: dict[tuple[int, str], FP.DeviceProfile] = {}

    def _emit(self, code: str, key: FlowKey, detail: str, now: float,
              fp=None) -> None:
        if code in ONCE_PER_FLOW:
            tag = (code, key)
            if tag in self._flow_reported:
                return
            self._flow_reported.add(tag)
        self.findings.append(Finding(code, key, detail, now, fp=fp))

    def note_security_host(self, family: int, host: str) -> None:
        """
        Record a host seen on Modbus Security (802). A slave that shows up on 802
        is no longer an MBW-042 candidate: it will not (re)fire 042, and further
        plaintext 502 to it is reported as MBW-041 instead.
        """
        self.security_hosts.add((family, host))

    def feed(self, key: FlowKey, adu: Adu, dst_port: int = 502,
             now: float | None = None) -> None:
        now = now if now is not None else time.time()
        self.baseline.note_traffic(now)

        # MBW-030: framing trigger. Emit even though we discard nothing else.
        if adu.malformed:
            self._emit("MBW-030", key, adu.malformed, now)
            # malformed framing can't be trusted for semantic checks below
            return

        # responses don't carry attacker intent for the abuse checks
        is_req = not adu.is_response

        # learn/track baseline on every request
        if is_req:
            self.baseline.observe(key, adu.function_code, now)

        fc = adu.function_code

        # --- MBW-001 / MBW-004: writes & any FC from an unknown master ---
        if is_req and self.baseline.is_new_master(key, now):
            if fc in WRITE_FCS:
                self._emit("MBW-001", key,
                           f"write FC{fc} from unlearned master", now)
            else:
                self._emit("MBW-004", key,
                           f"FC{fc} from unlearned master", now)

        # --- MBW-002 / MBW-003: FC8 diagnostics ---
        if is_req and fc == FC.DIAGNOSTICS:
            sub = diag_subfunction(adu)
            if sub == DIAG_FORCE_LISTEN_ONLY:
                self._emit("MBW-002", key, "FC8 sub=0x0004 Force Listen Only", now)
            elif sub in (DIAG_RESTART_COMM, DIAG_CLEAR_COUNTERS):
                self._emit("MBW-003", key, f"FC8 sub=0x{sub:04x}", now)

        # --- MBW-020: FC43/MEI-14 enumeration ---
        if is_req and fc == FC.ENCAPSULATED_INTERFACE and mei_type(adu) == MEI_READ_DEVICE_ID:
            if self.enums.record(key, now):
                self._emit("MBW-020", key, "Read Device ID burst", now)

        # --- MBW-021: unit-ID sweep ---
        if is_req:
            if self.sweeps.record(key, now):
                self._emit("MBW-021", key, "unit-ID sweep", now)

        # --- MBW-010 / MBW-011: UMAS presence and ModiPwn chain ---
        if is_req and fc == FC.UMAS:
            sub = umas_subcode(adu)
            self._emit("MBW-010", key,
                       f"UMAS sub=0x{sub:02x}" if sub is not None else "UMAS", now)
            if sub is not None and self.umas.record(key, sub, now):
                self._emit("MBW-011", key,
                           "read-primitive then write/reconfigure within window", now)

        # --- MBW-040: cleartext on a non-isolated segment ---
        if is_req and dst_port != MODBUS_SECURITY_PORT and self.ot_subnets:
            if not self._in_declared_ot(key):
                self._emit("MBW-040", key,
                           "Modbus/TCP outside declared OT subnet", now)

        # --- MBW-041 / MBW-042: plaintext 502 vs secure-Modbus availability ---
        if is_req and dst_port != MODBUS_SECURITY_PORT:
            slave = (key.family, key.dst)
            if slave in self.security_hosts:
                self._emit("MBW-041", key, "plain 502 to a host that offers 802", now)
            elif (not self.baseline.learning(now)
                  and slave not in self._mbw042_reported):
                # Only after the learning window, so an 802 session seen during
                # learning counts. Once per (family, slave).
                self._mbw042_reported.add(slave)
                self._emit("MBW-042", key,
                           "slave reached on 502, never seen on 802", now)

    # ------------------------------------------------------------------
    # LoRaWAN gateway backhaul (MBW-100..105)
    # ------------------------------------------------------------------
    def feed_lora(self, key: FlowKey, pkt: "L.Gwmp", now: float | None = None,
                  dst_port: int | None = None) -> None:
        """
        Feed one well-formed GWMP packet. `key` is as observed on the wire
        (src -> dst, unit_id unused); the sensor does not flip direction here
        because for this tier the direction *is* the signal.
        """
        now = now if now is not None else time.time()
        self._lora_dport = dst_port

        fp = None
        if pkt.gw_eui and pkt.from_gateway:
            # The gateway's own address, and -- from a PULL_DATA -- the address
            # it treats as its network server. Both are destinations or sources
            # of gateway-originated packets, so neither can be claimed.
            self.lora_servers.note_gateway_addr(key.family, key.src, pkt.gw_eui)
            if pkt.identifier == L.PULL_DATA:
                self.lora_servers.note_pull_data(key.family, pkt.gw_eui, key.dst)

            fp = self._fingerprint(key, pkt, now)

            # --- MBW-100 / MBW-102: census and source-address conflict ---
            is_new, conflict = self.gw_census.record(key.family, pkt.gw_eui,
                                                     key.src, now)
            if is_new:
                self._emit("MBW-100", key,
                           f"gateway EUI {pkt.gw_eui} via {pkt.name} "
                           f"(GWMP v{pkt.version}) on UDP backhaul", now, fp=fp)
            self._emit_location(key, pkt, fp, now)
            if conflict:
                spans = self.gw_census.source_spans(key.family, pkt.gw_eui)
                self._emit("MBW-102", key,
                           f"gateway EUI {pkt.gw_eui}: {conflict} | {spans}", now)

        # --- MBW-103: downlink from an address that is not this gateway's server ---
        # PULL_RESP carries no EUI, so the gateway it is aimed at is identified
        # by the datagram's destination address.
        if pkt.identifier == L.PULL_RESP:
            for eui in sorted(self.lora_servers.euis_at(key.family, key.dst)):
                if not self.lora_servers.armed(key.family, eui):
                    continue        # no PULL_DATA seen yet: map unknown, stay silent
                if self.lora_servers.is_expected(key.family, eui, key.src):
                    continue
                expected = ", ".join(sorted(
                    self.lora_servers.expected_for(key.family, eui))) or "none"
                tx = self._txpk_summary(pkt)
                self._emit("MBW-103", key,
                           f"PULL_RESP token=0x{pkt.token:04x} to gateway {eui} "
                           f"at {key.dst} from {key.src}; expected server "
                           f"{expected}{tx}", now)

        # --- MBW-101: PHYPayloads actually recovered from the cleartext link ---
        if pkt.gw_eui and pkt.from_gateway and pkt.phy:
            slot = (key.family, pkt.gw_eui)
            if slot not in self._lora_cleartext_reported:
                self._lora_cleartext_reported.add(slot)
                kinds = sorted({p.mtype_name for p in pkt.phy})
                self._emit("MBW-101", key,
                           f"{len(pkt.phy)} PHYPayload(s) readable off the backhaul "
                           f"({', '.join(kinds)}); GWMP has no authentication or "
                           f"encryption", now)

        # --- per-frame LoRaWAN checks ---
        for phy in pkt.phy:
            # fingerprint enrichment runs before the abuse checks so the census
            # metadata is current even on the packet that trips a finding
            if fp is not None:
                self._fingerprint_phy(fp, key, phy, now)

            # MBW-104: DevNonce reuse in a JoinRequest
            if phy.mtype == L.MT_JOIN_REQUEST and phy.dev_eui is not None:
                repeats = self.devnonces.record(key.family, phy.dev_eui,
                                                phy.dev_nonce)
                if repeats:
                    self._emit("MBW-104", key,
                               f"DevEUI {phy.dev_eui} re-used DevNonce "
                               f"0x{phy.dev_nonce:04x} (seen {repeats}x) "
                               f"- join replay or a non-compliant device", now)

            # MBW-105: uplink frame-counter reset (uplinks only; downlinks carry
            # an independent counter under the same DevAddr)
            if phy.uplink and phy.mtype in L.DATA_UP and phy.dev_addr is not None:
                prev = self.fcnts.record(key.family, phy.dev_addr, phy.fcnt)
                if prev is not None:
                    self._emit("MBW-105", key,
                               f"DevAddr {phy.dev_addr} FCnt {prev} -> {phy.fcnt} "
                               f"(high-water {prev} > {self.lora.fcnt_high}, "
                               f"now <= {self.lora.fcnt_low})", now)

    @staticmethod
    def _txpk_summary(pkt) -> str:
        """txpk frequency and size, for the MBW-103 metadata."""
        tx = (pkt.obj or {}).get("txpk")
        if not isinstance(tx, dict):
            return ""
        freq, size = tx.get("freq"), tx.get("size")
        bits = []
        if freq is not None:
            bits.append(f"freq={freq}")
        if size is not None:
            bits.append(f"size={size}")
        return (" | txpk " + " ".join(bits)) if bits else ""

    # --- fingerprinting (MBW-100 enrichment, MBW-106) ---
    def _fingerprint(self, key: FlowKey, pkt, now: float):
        """Get or create this gateway's fingerprint and fold in the packet."""
        slot = (key.family, pkt.gw_eui)
        fp = self.gw_fingerprints.get(slot)
        if fp is None:
            oui, vendor = FP.eui_vendor(pkt.gw_eui)
            fp = FP.GatewayFingerprint(family=key.family, gw_eui=pkt.gw_eui,
                                       first_seen=now)
            self.gw_fingerprints[slot] = fp
            fp.note_gateway(oui, vendor, pkt.version, key.src, key.dst,
                            self._lora_dport)
        else:
            fp.note_gateway(fp.gw_oui, fp.gw_vendor, fp.proto_version, key.src,
                            key.dst, self._lora_dport or fp.server_port)
        fp.last_seen = now

        # Coordinates are folded in here but reported by the caller, so the
        # census line (MBW-100) precedes the location finding in the log.
        stat = (pkt.obj or {}).get("stat")
        self._pending_coords = fp.note_stat(stat) if isinstance(stat, dict) else None
        return fp

    def _emit_location(self, key: FlowKey, pkt, fp, now: float) -> None:
        """MBW-106: gateway coordinates carried in the cleartext stat block."""
        coords = self._pending_coords
        self._pending_coords = None
        if coords is None:
            return
        slot = (key.family, pkt.gw_eui)
        if slot in self._lora_location_reported:
            return
        self._lora_location_reported.add(slot)
        lat, lon, alt = coords
        alt_s = f" alt={alt}m" if alt is not None else ""
        self._emit("MBW-106", key,
                   f"gateway {pkt.gw_eui} reports lat={lat} lon={lon}{alt_s} "
                   f"in cleartext stat (rounded to {FP.COORD_DECIMALS} dp)",
                   now, fp=fp)

    def _fingerprint_phy(self, fp, key: FlowKey, phy, now: float) -> None:
        """Fold one PHYPayload into the gateway fingerprint and device profile."""
        if phy.mtype == L.MT_JOIN_REQUEST and phy.dev_eui:
            fp.note_join(phy.dev_eui, phy.join_eui)
            return
        if phy.uplink and phy.mtype in L.DATA_UP and phy.dev_addr:
            fp.note_uplink(phy.dev_addr)
            slot = (key.family, phy.dev_addr)
            prof = self.device_profiles.get(slot)
            if prof is None:
                if len(self.device_profiles) >= FP.MAX_DEVADDRS_PER_GW:
                    return
                prof = FP.DeviceProfile()
                self.device_profiles[slot] = prof
            prof.observe(phy, now)

    def device_profile(self, family: int, dev_addr: str):
        """The behavioural profile for one device, or None."""
        return self.device_profiles.get((family, dev_addr))

    def _in_declared_ot(self, key: FlowKey) -> bool:
        import ipaddress
        try:
            s = ipaddress.ip_address(key.src)
            d = ipaddress.ip_address(key.dst)
        except ValueError:
            return True  # can't judge -> don't false-positive
        for fam, net in self.ot_subnets:
            if fam == key.family and (s in net or d in net):
                return True
        return False
