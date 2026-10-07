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
from dataclasses import dataclass

# Ragnar: relative imports inside the vendored package (a flat "findings"/"state"
# would collide with python/dns_doctor_passive's modules of the same name); the
# bare form keeps the files runnable as a flat standalone directory.
try:
    from .parser import (
        Adu, FC, WRITE_FCS,
        DIAG_RESTART_COMM, DIAG_FORCE_LISTEN_ONLY, DIAG_CLEAR_COUNTERS,
        MEI_READ_DEVICE_ID, MODBUS_SECURITY_PORT,
        diag_subfunction, mei_type, umas_subcode,
    )
    from .state import (
        FlowKey, Baseline, SweepTracker, EnumTracker, UmasSession,
    )
except ImportError:
    from parser import (
        Adu, FC, WRITE_FCS,
        DIAG_RESTART_COMM, DIAG_FORCE_LISTEN_ONLY, DIAG_CLEAR_COUNTERS,
        MEI_READ_DEVICE_ID, MODBUS_SECURITY_PORT,
        diag_subfunction, mei_type, umas_subcode,
    )
    from state import (
        FlowKey, Baseline, SweepTracker, EnumTracker, UmasSession,
    )

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
}


@dataclass
class Finding:
    code: str
    key: FlowKey
    detail: str
    ts: float

    @property
    def meta(self):
        return REGISTRY[self.code]

    def __str__(self) -> str:
        title, cls, sev, conf = self.meta
        fam = "v6" if self.key.family == socket.AF_INET6 else "v4"
        return (f"[{self.code}] {sev.upper()} ({conf} conf) {title} "
                f"| {fam} {self.key.src}->{self.key.dst} unit={self.key.unit_id} "
                f"| {self.detail}")


class Engine:
    """
    Feed decoded ADUs with their flow key; collect findings. One engine per
    sensor. Dual-stack by construction: every tracker is family-aware.
    """

    def __init__(self, baseline: Baseline | None = None, ot_subnets=None,
                 security_hosts=None):
        self.baseline = baseline or Baseline()
        self.sweeps = SweepTracker()
        self.enums = EnumTracker()
        self.umas = UmasSession()
        self.findings: list[Finding] = []
        # operator-declared OT subnets as list of (family, ip_network); enables MBW-040
        self.ot_subnets = ot_subnets or []
        # (family, host) pairs ever seen speaking port 802; enables MBW-041
        self.security_hosts = security_hosts or set()

    def _emit(self, code: str, key: FlowKey, detail: str, now: float) -> None:
        self.findings.append(Finding(code, key, detail, now))

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

        # --- MBW-041: plain 502 where the talker is known to offer 802 ---
        if is_req and dst_port != MODBUS_SECURITY_PORT:
            if (key.family, key.dst) in self.security_hosts:
                self._emit("MBW-041", key, "plain 502 to a host that offers 802", now)

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
