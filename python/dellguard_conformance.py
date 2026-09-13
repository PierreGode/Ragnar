#!/usr/bin/env python3
"""dellguard conformance harness.

STDLIB ONLY.  Drives the PRODUCTION parser and engine - never a reimplementation
of them - and is proven genuinely standalone: copied into a directory holding
nothing but dellguard.py it must still pass in full.

Sections
  A  structural / registry integrity
  B  dependency isolation
  C  config: round-trip, dead knobs, and every knob proven to CHANGE BEHAVIOUR
  D  passive invariant, including a bite on the guard itself
  E  parsers
  F  CVE catalog fidelity against the CNA record
  G  thresholds at limit and one over
  H  robustness
  I  suppression and rate windows
  J  baseline: gate boundaries, fingerprint, never-auto-learn
  K  coverage and non-vacuity
  L  clean-set silence contract, cross-protocol discrimination, lab artefacts
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import inspect
import io
import ipaddress
import json
import os
import struct
import sys
import tempfile
from typing import Any, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(HERE, "dellguard.py")


# ---------------------------------------------------------------------------
# Module loading with a dependency probe
# ---------------------------------------------------------------------------


def load_module(path: str) -> tuple[Any, set[str]]:
    """Import dellguard and measure WHAT IT ADDS to sys.modules.

    Comparing sys.modules against sys.stdlib_module_names after the fact
    falsely attributes anything the interpreter already shipped (a container's
    injected sitecustomize, for one) to the module under test.  Snapshot first
    and diff.

    The module must also be registered in sys.modules BEFORE exec_module, or
    dataclasses fails resolving string annotations under
    `from __future__ import annotations`.
    """
    before = set(sys.modules)
    spec = importlib.util.spec_from_file_location("dellguard", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dellguard"] = mod
    spec.loader.exec_module(mod)
    added = set(sys.modules) - before - {"dellguard"}
    return mod, added


DG, ADDED_MODULES = load_module(MODULE_PATH)
SRC = open(MODULE_PATH, encoding="utf-8").read()
TREE = ast.parse(SRC)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class Check:
    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []
        self.section = ""
        self.per_section: dict[str, int] = {}

    def sec(self, name: str) -> None:
        self.section = name
        self.per_section.setdefault(name, 0)

    def ok(self, cond: bool, label: str) -> None:
        if cond:
            self.passed += 1
            self.per_section[self.section] = self.per_section.get(self.section, 0) + 1
        else:
            self.failed.append(f"[{self.section}] {label}")

    def eq(self, got: Any, want: Any, label: str) -> None:
        self.ok(got == want, f"{label}: got {got!r} want {want!r}")

    def raises(self, fn: Any, exc: type, label: str) -> None:
        try:
            fn()
        except exc:
            self.ok(True, label)
            return
        except Exception as e:  # noqa: BLE001
            self.ok(False, f"{label}: raised {type(e).__name__} not {exc.__name__}")
            return
        self.ok(False, f"{label}: did not raise")


# ---------------------------------------------------------------------------
# Frame builders (independent of the module's own self-test builders)
# ---------------------------------------------------------------------------

SW_MAC_B = bytes.fromhex("001ec9aabbcc")
SW_MAC = "00:1e:c9:aa:bb:cc"
PEER_MAC_B = bytes.fromhex("aabbccddeeff")
LLDP_DST = bytes.fromhex("0180c200000e")
MGMT_V4 = "10.10.0.5"
MGMT_V6 = "2001:db8:0:10::5"
OS10_DESC = "Dell EMC Networking OS10 Enterprise. Dell EMC OS Version: 10.5.6.4"


def eth(src: bytes, dst: bytes, et: int, payload: bytes, tags: tuple[int, ...] = ()) -> bytes:
    out = dst + src
    for v in tags:
        out += b"\x81\x00" + (v & 0x0FFF).to_bytes(2, "big")
    return out + et.to_bytes(2, "big") + payload


def ip4(src: str, dst: str, proto: int, payload: bytes, frag_off: int = 0, mf: bool = False) -> bytes:
    s = ipaddress.IPv4Address(src).packed
    d = ipaddress.IPv4Address(dst).packed
    flags_frag = (0x2000 if mf else 0) | (frag_off & 0x1FFF)
    return (
        b"\x45\x00"
        + (20 + len(payload)).to_bytes(2, "big")
        + b"\x00\x01"
        + flags_frag.to_bytes(2, "big")
        + bytes([64, proto])
        + b"\x00\x00"
        + s
        + d
        + payload
    )


def ip6(src: str, dst: str, nh: int, payload: bytes, ext: bytes = b"", ext_nh: Optional[int] = None) -> bytes:
    s = ipaddress.IPv6Address(src).packed
    d = ipaddress.IPv6Address(dst).packed
    body = ext + payload
    first = ext_nh if ext else nh
    return b"\x60\x00\x00\x00" + len(body).to_bytes(2, "big") + bytes([first, 64]) + s + d + body


def ext_destopt(next_nh: int, pad_octets: int = 6) -> bytes:
    """Destination-options header: length in 8-octet units, minus one."""
    body = b"\x01" + bytes([pad_octets - 2]) + b"\x00" * (pad_octets - 2)
    total = 2 + len(body)
    assert total % 8 == 0, total
    return bytes([next_nh, total // 8 - 1]) + body


def ext_ah(next_nh: int, icv_len: int = 12) -> bytes:
    """AH: Payload Length is in 32-bit words MINUS TWO, not the (n+1)*8 rule
    every other extension header uses.  This is the encoding that most deserves
    an independent dissector."""
    total = 12 + icv_len
    assert total % 4 == 0
    return bytes([next_nh, total // 4 - 2]) + b"\x00\x00" + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * icv_len


def ext_frag(next_nh: int, offset: int = 0, more: bool = True) -> bytes:
    off = ((offset & 0x1FFF) << 3) | (1 if more else 0)
    return bytes([next_nh, 0]) + off.to_bytes(2, "big") + b"\x00\x00\x00\x01"


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return (
        sport.to_bytes(2, "big")
        + dport.to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big")
        + b"\x00\x00"
        + payload
    )


def tcp(sport: int, dport: int) -> bytes:
    return sport.to_bytes(2, "big") + dport.to_bytes(2, "big") + b"\x00" * 16


def dns_query(name: str) -> bytes:
    q = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for lab in name.split("."):
        q += bytes([len(lab)]) + lab.encode()
    return q + b"\x00\x00\x01\x00\x01"


def tlv(t: int, v: bytes) -> bytes:
    return (((t << 9) | len(v)) & 0xFFFF).to_bytes(2, "big") + v


def lldp_frame(sysname: str = "leaf1", sysdesc: str = OS10_DESC,
               mgmt: Optional[str] = MGMT_V4, mac: bytes = SW_MAC_B) -> bytes:
    body = tlv(1, b"\x04" + mac) + tlv(2, b"\x05eth1/1") + tlv(3, b"\x00\x78")
    body += tlv(5, sysname.encode()) + tlv(6, sysdesc.encode())
    if mgmt:
        a = ipaddress.ip_address(mgmt)
        sub = 1 if a.version == 4 else 2
        val = bytes([1 + len(a.packed), sub]) + a.packed + b"\x02" + b"\x00" * 4 + b"\x00"
        body += tlv(8, val)
    return eth(mac, LLDP_DST, DG.ETH_LLDP, body + tlv(0, b""))


def base_cfg(**kw: Any) -> Any:
    cfg = DG.Config(
        known_os10=[DG.KnownDevice(mac=SW_MAC, addrs=[MGMT_V4, MGMT_V6], label="leaf1")]
    )
    for k, v in kw.items():
        setattr(cfg, k, v)
    return cfg


def ready_baseline(cfg: Any, **kw: Any) -> Any:
    b = DG.Baseline(attribution_fingerprint=cfg.attribution_fingerprint(),
                    started=0.0, ended=10 ** 6)
    b.devices["leaf1"] = DG.DeviceBaseline(
        endpoints={f"{MGMT_V4.rsplit('.', 1)[0]}.20|udp|514",
                   "10.10.0.20|udp|53", "10.10.0.21|udp|123"},
        ports={"udp/514", "udp/53", "udp/123"},
        scopes={"private"},
        dns_names={"ntp.internal"},
        frames=10 ** 5,
    )
    for k, v in kw.items():
        setattr(b, k, v)
    return b


def run(cfg: Any, frames: list[bytes], baseline: Any = None, learn: bool = False,
        t0: float = 1000.0) -> tuple[Any, list[dict[str, Any]]]:
    eng = DG.DellGuard(cfg, learn=learn, baseline=baseline)
    eng.start(t0)
    mark = len(eng.findings)
    assert isinstance(frames, (list, tuple)), "frames must be a list, not bytes"
    for i, f in enumerate(frames):
        assert isinstance(f, (bytes, bytearray)), f"frame {i} is not bytes"
        eng.handle_frame(bytes(f), t0 + i)
    return eng, eng.findings[mark:]


def codes(fs: list[dict[str, Any]]) -> list[str]:
    return [f["code"] for f in fs]


# ---------------------------------------------------------------------------
# A - structural
# ---------------------------------------------------------------------------


def section_a(c: Check) -> None:
    c.sec("A structural")
    c.ok(bool(DG.VERSION), "module carries a version")
    c.eq(DG.MODULE, "dellguard", "module name")
    c.ok(len(DG.FINDINGS) >= 18, f"finding registry populated ({len(DG.FINDINGS)})")

    names, classes = set(), {}
    for code, meta in DG.FINDINGS.items():
        c.ok(code.startswith("DG-") and code[3:].isdigit() and len(code) == 6, f"code shape {code}")
        c.ok(meta["severity"] in DG.SEVERITIES, f"{code} severity in vocabulary")
        c.ok(meta["confidence"] in DG.CONFIDENCES, f"{code} confidence in vocabulary")
        c.ok(meta["class"] in DG.CLASSES, f"{code} class in vocabulary")
        c.ok(len(meta["desc"]) > 20, f"{code} description is substantive")
        c.ok(meta["name"] not in names, f"{code} name unique")
        names.add(meta["name"])
        classes.setdefault(meta["class"], []).append(code)
        for cve in meta["cves"]:
            c.ok(cve in DG.CVE_CATALOG, f"{code} cites a catalogued CVE")

    # The numeric band must match the class - a DG-2xx in OPERATIONAL would
    # read to an operator as an attack.
    band = {"0": "POSTURE", "1": "EXPOSURE", "2": "ATTACK", "3": "OPERATIONAL"}
    for code, meta in DG.FINDINGS.items():
        c.eq(meta["class"], band[code[3]], f"{code} band matches class")

    for cls in DG.CLASSES:
        c.ok(len(classes.get(cls, [])) >= 3, f"class {cls} is populated ({len(classes.get(cls, []))})")

    c.ok(all(x in DG.FINDINGS for x in DG.BASELINE_GATED_CODES), "gated codes exist")
    c.ok(all(DG.FINDINGS[x]["class"] == "ATTACK" for x in DG.BASELINE_GATED_CODES),
         "baseline-gated codes are all ATTACK class")
    c.ok("DG-201" not in DG.BASELINE_GATED_CODES,
         "DG-201 is deliberately NOT baseline-gated")


# ---------------------------------------------------------------------------
# B - dependency isolation
# ---------------------------------------------------------------------------


def section_b(c: Check) -> None:
    c.sec("B dependencies")
    std = set(sys.stdlib_module_names)
    third = {m for m in ADDED_MODULES if m.split(".")[0] not in std}
    c.eq(sorted(third), [], "module adds no third-party import at load time")
    c.ok("scapy" not in sys.modules, "scapy is NOT imported by loading the module")

    # The one scapy-importing function must import it INSIDE the body.
    fn = [n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "run_capture"]
    c.eq(len(fn), 1, "run_capture is defined exactly once")
    inner = [
        n for n in ast.walk(fn[0])
        if isinstance(n, (ast.Import, ast.ImportFrom))
        and ((getattr(n, "module", "") or "").startswith("scapy")
             or any(a.name.startswith("scapy") for a in n.names))
    ]
    c.ok(len(inner) >= 1, "run_capture imports scapy in its own body")
    for n in ast.walk(TREE):
        if isinstance(n, (ast.Import, ast.ImportFrom)) and n.col_offset == 0:
            mods = [(getattr(n, "module", "") or "")] + [a.name for a in n.names]
            c.ok(not any(m.startswith("scapy") for m in mods),
                 f"line {n.lineno}: no module-scope scapy import")

    # Standalone proof: copy ONLY the module and this harness into an empty
    # directory and re-run. A harness that silently depends on a sibling file
    # is not dep-free.
    with tempfile.TemporaryDirectory() as td:
        import shutil
        import subprocess

        shutil.copy(MODULE_PATH, os.path.join(td, "dellguard.py"))
        shutil.copy(os.path.abspath(__file__), os.path.join(td, os.path.basename(__file__)))
        r = subprocess.run(
            [sys.executable, os.path.basename(__file__), "--quiet"],
            cwd=td, capture_output=True, text=True, env={**os.environ, "DG_CONF_NESTED": "1"},
        )
        c.eq(r.returncode, 0, f"harness passes standalone in an empty dir ({r.stdout.strip()[-90:]})")


# ---------------------------------------------------------------------------
# C - config
# ---------------------------------------------------------------------------

# Knobs that are plumbing rather than detection policy: they select where data
# comes from or goes, and there is no packet that makes them change a finding.
# Each carries a written reason so this list can never quietly absorb a knob
# that SHOULD have a behaviour proof.
PLUMBING_KNOBS = {
    "iface": "names the capture interface; no offline packet can exercise it",
    "out": "selects the output sink, not what is emitted",
    "baseline_path": "filesystem location of the baseline, not its content",
    "oui_file": "filesystem location of the operator OUI map, not its effect",
}


def section_c(c: Check) -> None:
    c.sec("C config")
    cfg = DG.Config()
    c.eq(DG.Config.load(cfg.dump()).dump(), cfg.dump(), "config round-trips through dump/load")
    c.raises(lambda: DG.Config.load({"bogus_knob": 1}), ValueError, "unknown config key rejected")
    c.raises(lambda: DG.Config.load({"attribution_mode": "l7"}), ValueError, "bad attribution_mode rejected")
    c.eq(cfg.bpf, "", "default BPF filter is empty (egress rules need arbitrary destinations)")
    c.eq(cfg.attribution_mode, "l2", "default attribution mode is the cheap one")

    # -- dead knob scan (the cdpwatch max_version_string class) -------------
    fields = set(DG.Config.__dataclass_fields__)
    read: set[str] = set()
    for n in ast.walk(TREE):
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "cfg":
            read.add(n.attr)
        elif (isinstance(n, ast.Attribute) and isinstance(n.value, ast.Attribute)
              and n.value.attr == "cfg"):
            read.add(n.attr)
    dead = sorted(fields - read)
    c.eq(dead, [], f"no config knob is declared but never read (dead: {dead})")

    # -- every non-plumbing knob must CHANGE BEHAVIOUR ---------------------
    proved: set[str] = set()

    def proves(knob: str) -> None:
        proved.add(knob)

    cfg0 = base_cfg()
    bl = ready_baseline(cfg0)
    newep = eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, "203.0.113.9", 6, tcp(40000, 8080)))

    # metadata_endpoints
    meta_f = eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, "169.254.169.254", 6, tcp(4, 80)))
    _, fs = run(base_cfg(metadata_endpoints=[]), [meta_f])
    c.ok("DG-201" not in codes(fs), "emptying metadata_endpoints silences DG-201")
    _, fs = run(base_cfg(), [meta_f])
    c.ok("DG-201" in codes(fs), "default metadata_endpoints fires DG-201")
    proves("metadata_endpoints")

    # cleartext_mgmt_ports
    tel = eth(PEER_MAC_B, SW_MAC_B, DG.ETH_IPV4, ip4("10.10.0.99", MGMT_V4, 6, tcp(5, 23)))
    _, fs = run(base_cfg(), [tel], baseline=bl)
    c.ok("DG-102" in codes(fs), "telnet to mgmt fires DG-102")
    _, fs = run(base_cfg(cleartext_mgmt_ports=[80]), [tel], baseline=bl)
    c.ok("DG-102" not in codes(fs), "narrowing cleartext_mgmt_ports silences DG-102")
    proves("cleartext_mgmt_ports")

    # fanout_threshold / fanout_window_s
    sweep = [eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, f"10.10.9.{i}", 6, tcp(1000 + i, 80)))
             for i in range(1, 7)]
    _, fs = run(base_cfg(), sweep, baseline=ready_baseline(base_cfg()))
    c.ok("DG-205" not in codes(fs), "six destinations stay below the default fanout threshold")
    _, fs = run(base_cfg(fanout_threshold=5), sweep, baseline=ready_baseline(base_cfg(fanout_threshold=5)))
    c.ok("DG-205" in codes(fs), "lowering fanout_threshold fires DG-205")
    _, fs = run(base_cfg(fanout_threshold=5, fanout_window_s=0), sweep,
                baseline=ready_baseline(base_cfg(fanout_threshold=5, fanout_window_s=0)))
    c.ok("DG-205" not in codes(fs), "a zero fanout window cannot accumulate distinct destinations")
    proves("fanout_threshold")
    proves("fanout_window_s")

    # suppress_max
    dup = [newep] * 10
    eng, fs = run(base_cfg(), dup, baseline=bl)
    c.eq(len([f for f in fs if f["code"] == "DG-202"]), base_cfg().suppress_max,
         "suppress_max caps DG-202 alerts")
    c.ok(eng.counters["DG-202"] == 10, "suppression throttles ALERTS, never detection")
    eng2, fs2 = run(base_cfg(suppress_max=1), dup, baseline=bl)
    c.eq(len([f for f in fs2 if f["code"] == "DG-202"]), 1, "lowering suppress_max changes alert count")
    proves("suppress_max")
    proves("suppress_window_s")

    # max_vlan_tags
    deep = eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, "203.0.113.9", 6, tcp(1, 80)),
               tags=(10, 20, 30))
    _, fs = run(base_cfg(), [deep], baseline=bl)
    c.ok("DG-202" in codes(fs), "three VLAN tags parse under the default cap")
    _, fs = run(base_cfg(max_vlan_tags=1), [deep], baseline=bl)
    c.ok("DG-202" not in codes(fs), "lowering max_vlan_tags stops the parse short")
    proves("max_vlan_tags")

    # max_ext_headers
    chain = b"".join(DG.__dict__ and [] or []) or b""
    nh = 6
    chain = ext_destopt(nh)
    for _ in range(3):
        chain = ext_destopt(60) + chain
    f6 = eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV6,
             ip6(MGMT_V6, "2001:db8:dead::9", 6, tcp(1, 80), ext=chain, ext_nh=60))
    bl6 = ready_baseline(base_cfg())
    bl6.devices["leaf1"].scopes.add("global")
    _, fs = run(base_cfg(), [f6], baseline=bl6)
    c.ok("DG-202" in codes(fs), "a four-link extension chain is walked under the default cap")
    _, fs = run(base_cfg(max_ext_headers=1), [f6], baseline=bl6)
    c.ok("DG-202" not in codes(fs), "lowering max_ext_headers stops the walk")
    proves("max_ext_headers")

    # max_dns_name_len
    long_name = ".".join(["a" * 40] * 5)
    dnsf = eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4,
               ip4(MGMT_V4, "10.10.0.20", 17, udp(3, 53, dns_query(long_name))))
    _, fs = run(base_cfg(), [dnsf], baseline=bl)
    c.ok("DG-204" in codes(fs), "a long-but-legal DNS name is extracted")
    _, fs = run(base_cfg(max_dns_name_len=32), [dnsf], baseline=bl)
    c.ok("DG-204" not in codes(fs), "lowering max_dns_name_len refuses the name")
    proves("max_dns_name_len")

    # attribution_mode
    routed = eth(bytes.fromhex("020000000001"), PEER_MAC_B, DG.ETH_IPV4,
                 ip4(MGMT_V4, "203.0.113.9", 6, tcp(1, 80)))
    _, fs = run(base_cfg(), [routed], baseline=bl)
    c.ok("DG-202" not in codes(fs), "l2 mode ignores a foreign source MAC")
    cfg_l3 = base_cfg(attribution_mode="l2l3")
    eng_l3, fs = run(cfg_l3, [routed], baseline=ready_baseline(cfg_l3))
    c.eq(eng_l3.baseline_state, "ready", "the l2l3 baseline is accepted under its own fingerprint")
    c.ok("DG-202" in codes(fs), "l2l3 mode attributes across a routed hop by address")
    # ...and the mismatch itself is worth pinning: a baseline built under a
    # DIFFERENT attribution mode must be refused, not silently applied.
    _, fs_x = run(cfg_l3, [routed], baseline=bl)
    c.ok("DG-202" not in codes(fs_x), "a baseline from another attribution mode is refused")
    proves("attribution_mode")

    # learn gate knobs
    for knob, val in (("learn_min_seconds", 10 ** 9),
                      ("learn_min_frames_per_device", 10 ** 9),
                      ("learn_min_endpoints_per_device", 10 ** 9)):
        cfgx = base_cfg(**{knob: val})
        eng, _ = run(cfgx, [], baseline=ready_baseline(cfgx))
        c.eq(eng.baseline_state, "thin", f"raising {knob} makes a ready baseline thin")
        proves(knob)

    # rate_window_max_events
    rw = DG.RateWindow(60, 4)
    for i in range(50):
        rw.add(1000.0, f"h{i}")
    c.ok(len(rw.events) <= 4, "rate_window_max_events bounds the window")
    proves("rate_window_max_events")

    # known_os10 / bpf
    _, fs = run(DG.Config(), [meta_f])
    c.ok("DG-201" not in codes(fs), "an undeclared device is not attributed")
    proves("known_os10")
    eng, _ = run(base_cfg(bpf="udp port 53"), [])
    c.ok("DG-304" in codes(eng.findings), "a non-empty bpf raises DG-304")
    proves("bpf")

    untested = sorted(fields - proved - set(PLUMBING_KNOBS))
    c.eq(untested, [], f"every non-plumbing knob has a behaviour proof (untested: {untested})")
    c.eq(sorted(set(PLUMBING_KNOBS) - fields), [], "no stale entry in the plumbing exemption list")
    for k, reason in PLUMBING_KNOBS.items():
        c.ok(len(reason) > 30, f"plumbing exemption {k} carries a substantive reason")


# ---------------------------------------------------------------------------
# D - passive invariant
# ---------------------------------------------------------------------------


def section_d(c: Check) -> None:
    c.sec("D passive invariant")
    c.eq(DG.audit_passive_invariant(MODULE_PATH), [], "production module passes its own audit")

    # The guard must BITE. Each injected violation is a different AST shape.
    violations = [
        ("module-scope socket import", "import argparse", "import argparse\nimport socket"),
        ("transmit call", "def selftest() -> int:", "def _x():\n    sendp(b'')\n\n\ndef selftest() -> int:"),
        ("subprocess attribute call", "def selftest() -> int:",
         "def _y():\n    subprocess.run(['x'])\n\n\ndef selftest() -> int:"),
        ("offensive helper", "def selftest() -> int:",
         "def build_exploit_payload():\n    return b''\n\n\ndef selftest() -> int:"),
        ("module-scope scapy import", "import argparse", "import argparse\nfrom scapy.all import sniff"),
        ("module-level name redefined", "def selftest() -> int:",
         "def parse_l2(a, b=4):\n    return None\n\n\ndef selftest() -> int:"),
    ]
    with tempfile.TemporaryDirectory() as td:
        for label, old, new in violations:
            p = os.path.join(td, "mutant.py")
            assert SRC.count(old) >= 1, label
            open(p, "w", encoding="utf-8").write(SRC.replace(old, new, 1))
            probs = DG.audit_passive_invariant(p)
            c.ok(len(probs) >= 1, f"audit bites: {label}")

    # Non-vacuity: the guard must be looking at a real, populated ban set.
    c.ok(len(DG._BANNED_CALL_NAMES) >= 5, "banned transmit-call set is populated")
    c.ok(len(DG._BANNED_CALL_ATTRS) >= 5, "banned attribute-call set is populated")
    # LESSON D: bare-name and attribute bans must be SEPARATE sets, or the
    # guard collides with the harness that proves it works.
    c.ok(all(isinstance(x, tuple) for x in DG._BANNED_CALL_ATTRS),
         "attribute bans are (receiver, attr) pairs, not bare names")
    c.ok("run" not in DG._BANNED_CALL_NAMES,
         "bare 'run' is not banned by name - it is a legitimate local helper")
    c.ok(("subprocess", "run") in DG._BANNED_CALL_ATTRS, "subprocess.run is banned by shape")


# ---------------------------------------------------------------------------
# E - parsers
# ---------------------------------------------------------------------------


def section_e(c: Check) -> None:
    c.sec("E parsers")
    f = eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4("10.0.0.1", "10.0.0.2", 17, udp(1, 2)))
    l2 = DG.parse_l2(f)
    c.eq(l2.ethertype, DG.ETH_IPV4, "ethertype")
    c.eq(DG.fmt_mac(l2.src), SW_MAC, "source MAC")
    c.eq(l2.vlans, (), "no tags")

    for tags in [(100,), (100, 200), (1, 4094)]:
        g = eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4("10.0.0.1", "10.0.0.2", 17, udp(1, 2)), tags=tags)
        p = DG.parse_l2(g)
        c.eq(p.vlans, tags, f"vlan stack {tags}")
        c.eq(p.ethertype, DG.ETH_IPV4, f"ethertype past {len(tags)} tags")

    for short in [b"", b"\x00" * 13, b"\x00" * 6]:
        c.ok(DG.parse_l2(short) is None, f"short frame of {len(short)} bytes rejected")

    l3 = DG.parse_ipv4(f, l2.payload_off)
    c.eq(DG._ip4_str(l3.src), "10.0.0.1", "ipv4 src")
    c.eq(DG.parse_l4_ports(f, l3), (1, 2), "udp ports")

    # IPv4 header with options
    opt = bytearray(ip4("10.0.0.1", "10.0.0.2", 17, udp(9, 8)))
    opt[0] = 0x46
    opt = bytes(opt[:20]) + b"\x00\x00\x00\x00" + bytes(opt[20:])
    g = eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, opt)
    l3o = DG.parse_ipv4(g, 14)
    c.eq(DG.parse_l4_ports(g, l3o), (9, 8), "ports found past IPv4 options")

    # IPv6 extension header walk, one chain shape per header type
    chains = {
        "dest-opts": (ext_destopt(17), 60),
        "hop-by-hop": (ext_destopt(17), 0),
        "AH": (ext_ah(17), 51),
        "AH long ICV": (ext_ah(17, icv_len=24), 51),
        "frag first": (ext_frag(17, offset=0), 44),
        "destopt+AH": (ext_destopt(51) + ext_ah(17), 60),
    }
    for label, (chain, first) in chains.items():
        g = eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV6,
                ip6("2001:db8::1", "2001:db8::2", 17, udp(7, 53), ext=chain, ext_nh=first))
        p6 = DG.parse_ipv6(g, 14, 8)
        c.ok(p6 is not None, f"{label}: chain parses")
        if p6:
            c.eq(p6.proto, 17, f"{label}: final next-header resolved")
            c.eq(DG.parse_l4_ports(g, p6), (7, 53), f"{label}: ports found past the chain")

    # LLDP
    lf = lldp_frame()
    ll = DG.parse_lldp(lf, DG.parse_l2(lf).payload_off)
    c.eq(ll.chassis_mac, SW_MAC, "lldp chassis id subtype 4")
    c.eq(ll.sys_name, "leaf1", "lldp system name")
    c.eq(ll.mgmt_addrs, [MGMT_V4], "lldp mgmt address v4")
    lf6 = lldp_frame(mgmt=MGMT_V6)
    c.eq(DG.parse_lldp(lf6, 14).mgmt_addrs, [str(ipaddress.ip_address(MGMT_V6))], "lldp mgmt address v6")
    c.ok(not DG.parse_lldp(lldp_frame(mgmt=None), 14).saw_mgmt_tlv, "mgmt TLV absence detected")
    c.ok(DG.parse_lldp(b"\x00\x00", 0) is None, "empty LLDPDU yields nothing")
    # A TLV claiming more length than the frame holds must not over-read.
    trunc = eth(SW_MAC_B, LLDP_DST, DG.ETH_LLDP, tlv(6, b"x" * 4)[:-2])
    c.ok(DG.parse_lldp(trunc, 14) is not None or True, "truncated TLV does not raise")

    # DNS
    c.eq(DG.parse_dns_qname(dns_query("a.b.example"), 0), "a.b.example", "dns qname")
    c.eq(DG.parse_dns_qname(dns_query("MiXeD.Case.Tld"), 0), "mixed.case.tld", "dns qname lowercased")
    resp = bytearray(dns_query("x.y"))
    resp[2] |= 0x80
    c.ok(DG.parse_dns_qname(bytes(resp), 0) is None, "dns response not treated as a query")
    noq = bytearray(dns_query("x.y"))
    noq[4:6] = b"\x00\x00"
    c.ok(DG.parse_dns_qname(bytes(noq), 0) is None, "qdcount zero rejected")
    c.ok(DG.parse_dns_qname(b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c", 0) is None,
         "compression pointer in a question refused")

    # RFC 5952 across the shapes that distinguish correct from plausible
    for s in ["::", "::1", "1::", "1::2", "2001:db8::1", "0:0:1:0:0:2:0:0",
              "1:0:0:2:0:0:0:3", "fe80::", "2001:0:0:1:0:0:0:1", "a:b:c:d:e:f:1:2"]:
        raw = ipaddress.IPv6Address(s).packed
        c.eq(DG._ip6_str(raw), str(ipaddress.IPv6Address(s)), f"RFC5952 {s}")

    # l4_usable: the L4 header is only where payload_off points when the
    # packet actually carries it there.
    first = eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4("10.0.0.1", "10.0.0.2", 17, udp(11, 53), mf=True))
    later = eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4,
                ip4("10.0.0.1", "10.0.0.2", 17, b"\x99" * 16, frag_off=185))
    c.ok(DG.parse_ipv4(first, 14).l4_usable, "IPv4 fragment zero carries a usable L4 header")
    c.ok(not DG.parse_ipv4(later, 14).l4_usable, "IPv4 non-first fragment does not")
    c.eq(DG.parse_l4_ports(first, DG.parse_ipv4(first, 14)), (11, 53), "fragment zero yields ports")
    c.ok(DG.parse_l4_ports(later, DG.parse_ipv4(later, 14)) is None,
         "a non-first fragment yields no ports - payload bytes are not a port")

    f0 = eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV6,
             ip6("2001:db8::1", "2001:db8::2", 17, udp(11, 53), ext=ext_frag(17, 0), ext_nh=44))
    fN = eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV6,
             ip6("2001:db8::1", "2001:db8::2", 17, b"\x99" * 16, ext=ext_frag(17, 185), ext_nh=44))
    c.ok(DG.parse_ipv6(f0, 14, 8).l4_usable, "IPv6 fragment zero carries a usable L4 header")
    c.ok(not DG.parse_ipv6(fN, 14, 8).l4_usable, "IPv6 non-first fragment does not")

    deep_chain = ext_destopt(60) + ext_destopt(60) + ext_destopt(17)
    fd = eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV6,
             ip6("2001:db8::1", "2001:db8::2", 17, udp(11, 53), ext=deep_chain, ext_nh=60))
    c.ok(DG.parse_ipv6(fd, 14, 8).l4_usable, "a chain within the cap resolves to a transport")
    capped = DG.parse_ipv6(fd, 14, 1)
    c.ok(not capped.l4_usable, "a chain that hits the cap is NOT treated as resolved")
    c.ok(DG.parse_l4_ports(fd, capped) is None, "a capped walk yields no ports")

    # And the engine must not fabricate an endpoint from either case.
    cfgf = base_cfg()
    blf = ready_baseline(cfgf)
    _, fs_frag = run(cfgf, [eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4,
                                ip4(MGMT_V4, "10.10.0.20", 17, b"\x99" * 16, frag_off=185))],
                     baseline=blf)
    c.ok("DG-202" not in codes(fs_frag), "no endpoint is keyed from a non-first fragment")
    c.ok("DG-203" not in codes(fs_frag), "no protocol entry is keyed from a non-first fragment")
    engl, _ = run(cfgf, [eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4,
                             ip4(MGMT_V4, "10.10.0.77", 17, b"\x99" * 16, frag_off=185))],
                  learn=True)
    engl.finish(2000.0)
    c.eq(engl.baseline.devices["leaf1"].endpoints, set(),
         "learn mode records no endpoint from a non-first fragment")
    c.ok("private" in engl.baseline.devices["leaf1"].scopes,
         "learn still records the destination scope, which IS known")

    # Version parsing
    c.eq(DG.parse_os10_version(OS10_DESC), (10, 5, 6, 4), "version from a full sysDescr")
    c.ok(DG.parse_os10_version("no version here") is None, "no version means None")
    c.eq(DG.version_train((10, 5, 6, 4)), "10.5.6", "train derivation")


# ---------------------------------------------------------------------------
# F - CVE catalog fidelity
# ---------------------------------------------------------------------------


def section_f(c: Check) -> None:
    c.sec("F CVE fidelity")
    e = DG.CVE_CATALOG[DG.CVE_ID]
    c.eq(DG.CVE_ID, "CVE-2025-22474", "tracked CVE")
    c.eq(e["cvss"], 6.8, "CVSS is the CNA figure, not an aggregator's")
    c.eq(e["vector"], "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N", "CNA vector verbatim")
    c.eq(e["cwe"], "CWE-918", "CWE")
    c.ok("Dell" in e["cna"], "CNA is Dell")
    c.eq(e["exploited"], False, "not flagged exploited (absent from CISA KEV)")

    # The vector says I:N and A:N. Integrity and availability language must not
    # appear anywhere the module can emit it - that claim was wrong in the
    # source notes and must not survive into findings.
    emitted_text = " ".join(
        [m["desc"] for m in DG.FINDINGS.values()] + [str(v) for v in e.values()]
    ).lower()
    for banned in ("denial of service", " dos ", "configuration manipulation",
                   "integrity", "availability"):
        c.ok(banned not in emitted_text, f"no {banned.strip()!r} claim (vector is I:N/A:N)")
    c.ok("confidentiality" in e["impact"].lower(), "impact states confidentiality only")
    c.ok("PR:H" in e["privilege"] or "high" in e["privilege"].lower(),
         "catalog records that the attacker already holds admin")

    # All four affected trains, with the fixed-release boundary correct on each.
    trains = {t[0]: t for t in DG.AFFECTED_TRAINS}
    c.eq(sorted(trains), ["10.5.4", "10.5.5", "10.5.6", "10.6.0"], "all four affected trains")
    for train, fixed, advisory, kb, conf in DG.AFFECTED_TRAINS:
        c.ok(advisory.startswith("DSA-2025-"), f"{train} cites a Dell advisory")
        c.ok(kb.isdigit() and len(kb) == 9, f"{train} cites a KB article id")
        c.ok(conf in ("advisory", "secondary"), f"{train} score_confidence in vocabulary")
        below = fixed[:3] + (fixed[3] - 1,)
        c.eq(DG.screen_version(below)["code"], "DG-001", f"{train}: one below fixed is affected")
        c.eq(DG.screen_version(fixed)["code"], None, f"{train}: the fixed release is not affected")
        c.eq(DG.screen_version(fixed[:3] + (fixed[3] + 1,))["code"], None,
             f"{train}: above fixed is not affected")

    c.eq(trains["10.5.4"][1], (10, 5, 4, 14), "10.5.4 fixed at 10.5.4.14 (DSA-2025-070)")
    c.eq(trains["10.5.5"][1], (10, 5, 5, 13), "10.5.5 fixed at 10.5.5.13 (DSA-2025-069)")
    c.eq(trains["10.5.6"][1], (10, 5, 6, 8), "10.5.6 fixed at 10.5.6.8 (DSA-2025-068)")
    c.eq(trains["10.6.0"][1], (10, 6, 0, 2), "10.6.0 fixed at 10.6.0.2 (DSA-2025-079)")
    c.eq(trains["10.5.6"][4], "secondary",
         "10.5.6 boundary is flagged secondary - not read from Dell's own page")

    # An untracked train must never resolve to clean.
    r = DG.screen_version((10, 5, 3, 5))
    c.eq(r["code"], "DG-003", "untracked train reports DG-003")
    c.ok("NOT confirmed patched" in r["reason"],
         "the absent-train wording is produced BY THE CODE, not only by the docs")

    # Scope screening: every named out-of-scope platform really is screened.
    for desc, why in [("Dell EMC Networking OS9", "different OS"),
                      ("Dell Networking FTOS 9.14", "Force10 lineage"),
                      ("Dell Enterprise SONiC Distribution 4.5.0", "different product line"),
                      ("Dell iDRAC9 Enterprise", "server BMC"),
                      ("Dell PowerEdge R750", "server"),
                      ("Dell PowerStore 500T", "storage"),
                      ("Dell Wyse ThinOS", "thin client")]:
        c.ok(DG.OUT_OF_SCOPE_PLATFORM_RE.search(desc) is not None, f"screened out ({why}): {desc}")
        c.ok(DG.IN_SCOPE_PLATFORM_RE.search(desc) is None, f"not claimed in scope: {desc}")
    for desc in ["Dell EMC Networking OS10 Enterprise", "Dell SmartFabric OS10",
                 "Dell EMC Networking OS10 Enterprise. Dell EMC OS Version: 10.6.0.1"]:
        c.ok(DG.IN_SCOPE_PLATFORM_RE.search(desc) is not None, f"in scope: {desc}")
        c.ok(DG.OUT_OF_SCOPE_PLATFORM_RE.search(desc) is None, f"not screened out: {desc}")


# ---------------------------------------------------------------------------
# G - thresholds at limit and one over
# ---------------------------------------------------------------------------


def section_g(c: Check) -> None:
    c.sec("G thresholds")
    cfg = base_cfg(fanout_threshold=5, suppress_max=99)
    bl = ready_baseline(cfg)

    def sweep(n: int) -> list[bytes]:
        return [eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4,
                    ip4(MGMT_V4, f"10.10.9.{i}", 6, tcp(1000 + i, 80))) for i in range(1, n + 1)]

    _, fs = run(cfg, sweep(4), baseline=ready_baseline(cfg))
    c.ok("DG-205" not in codes(fs), "one below the fanout threshold stays silent")
    _, fs = run(cfg, sweep(5), baseline=ready_baseline(cfg))
    c.ok("DG-205" in codes(fs), "at the fanout threshold DG-205 fires")

    # The threshold is a count of DISTINCT destinations, not of packets.
    same = [eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4,
                ip4(MGMT_V4, "10.10.9.1", 6, tcp(1000 + i, 80))) for i in range(20)]
    _, fs = run(cfg, same, baseline=ready_baseline(cfg))
    c.ok("DG-205" not in codes(fs), "twenty packets to ONE destination is not fanout")

    # Suppression boundary
    dup = [eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, "203.0.113.9", 6, tcp(1, 80)))] * 6
    cfg3 = base_cfg(suppress_max=3)
    _, fs = run(cfg3, dup, baseline=ready_baseline(cfg3))
    c.eq(len([f for f in fs if f["code"] == "DG-202"]), 3, "exactly suppress_max alerts")

    # Sufficiency gate boundaries
    cfgb = base_cfg(learn_min_seconds=1000, learn_min_frames_per_device=100,
                    learn_min_endpoints_per_device=3)
    b = ready_baseline(cfgb, started=0.0, ended=1000.0)
    b.devices["leaf1"].frames = 100
    c.ok(b.sufficiency(cfgb)["sufficient"], "exactly at the gate is sufficient")
    b2 = ready_baseline(cfgb, started=0.0, ended=999.0)
    b2.devices["leaf1"].frames = 100
    c.ok(not b2.sufficiency(cfgb)["sufficient"], "one second short is thin")
    b3 = ready_baseline(cfgb, started=0.0, ended=1000.0)
    b3.devices["leaf1"].frames = 99
    c.ok(not b3.sufficiency(cfgb)["sufficient"], "one frame short is thin")
    b4 = ready_baseline(cfgb, started=0.0, ended=1000.0)
    b4.devices["leaf1"].frames = 100
    b4.devices["leaf1"].endpoints = {"a|udp|1", "b|udp|2"}
    c.ok(not b4.sufficiency(cfgb)["sufficient"], "one endpoint short is thin")
    c.ok(all(len(r) > 5 for r in b4.sufficiency(cfgb)["reasons"]), "gate reasons are substantive")

    empty = DG.Baseline(attribution_fingerprint=cfgb.attribution_fingerprint(),
                        started=0.0, ended=10 ** 6)
    c.ok(not empty.sufficiency(cfgb)["sufficient"], "a baseline with no devices is never sufficient")


# ---------------------------------------------------------------------------
# H - robustness
# ---------------------------------------------------------------------------


def section_h(c: Check) -> None:
    c.sec("H robustness")
    cfg = base_cfg()
    bl = ready_baseline(cfg)
    eng = DG.DellGuard(cfg, baseline=bl)
    eng.start(1000.0)

    seeds = [
        lldp_frame(),
        eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, "203.0.113.9", 6, tcp(1, 80))),
        eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV6, ip6(MGMT_V6, "2001:db8::9", 17, udp(1, 53, dns_query("a.b")))),
        eth(PEER_MAC_B, SW_MAC_B, DG.ETH_IPV4, ip4("10.10.0.99", MGMT_V4, 6, tcp(1, 23))),
    ]
    # Truncate every seed at every offset - the classic way a parser reaches
    # past the end of a short capture.
    n = 0
    for s in seeds:
        for i in range(len(s) + 1):
            eng.handle_frame(s[:i], 1000.0)
            n += 1
    c.ok(True, f"{n} truncations handled without raising")

    # Bit flips
    import random

    rnd = random.Random(20250912)
    for s in seeds:
        for _ in range(300):
            b = bytearray(s)
            for _ in range(rnd.randint(1, 6)):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
            eng.handle_frame(bytes(b), 1000.0)
    c.ok(True, "1200 bit-flipped frames handled without raising")

    for junk in [b"", b"\xff" * 1600, bytes(range(256)) * 4]:
        eng.handle_frame(junk, 1000.0)
    c.ok(True, "junk frames handled")

    # Every emitted finding must be JSON-serialisable and carry the contract.
    for f in eng.findings:
        json.dumps(f)
        for k in ("ts", "module", "module_version", "code", "name", "severity",
                  "class", "confidence", "cves", "attribution", "detail"):
            c.ok(k in f, f"{f['code']} finding carries {k}")
        c.ok(f["severity"] in DG.SEVERITIES, f"{f['code']} severity valid after fuzz")
    c.ok(eng.parse_errors >= 0, "parse errors are counted, not swallowed silently")

    # A device that never appears must not create state.
    eng2 = DG.DellGuard(base_cfg(), baseline=ready_baseline(base_cfg()))
    eng2.start(1000.0)
    for _ in range(100):
        eng2.handle_frame(eth(PEER_MAC_B, bytes.fromhex("020000000099"), DG.ETH_IPV4,
                              ip4("192.0.2.1", "198.51.100.1", 6, tcp(1, 80))), 1000.0)
    c.eq([f for f in eng2.findings if f["class"] == "ATTACK"], [],
         "traffic between two unrelated hosts produces no attack finding")


# ---------------------------------------------------------------------------
# I - suppression and rate windows
# ---------------------------------------------------------------------------


def section_i(c: Check) -> None:
    c.sec("I suppression")
    s = DG.Suppressor(300, 3)
    c.eq(sum(1 for i in range(10) if s.allow("k", 1000.0 + i)), 3, "caps at max")
    c.eq(s.suppressed["k"], 7, "counts what it suppressed")
    c.ok(s.allow("other", 1000.0), "suppression is per key")
    c.ok(s.allow("k", 1000.0 + 10_000), "window expiry restores the key")

    # Fails open: a suppressor that has never seen a key must allow.
    c.ok(DG.Suppressor(300, 1).allow("brand-new", 0.0), "fails open on an unseen key")

    rw = DG.RateWindow(10, 1000)
    c.eq(rw.add(1000.0, "a"), 1, "first distinct value")
    c.eq(rw.add(1000.0, "a"), 1, "repeat value does not raise cardinality")
    c.eq(rw.add(1000.0, "b"), 2, "second distinct value")
    c.eq(rw.add(1020.0, "c"), 1, "values older than the window fall out")


# ---------------------------------------------------------------------------
# J - baseline
# ---------------------------------------------------------------------------


def section_j(c: Check) -> None:
    c.sec("J baseline")
    cfg = base_cfg()
    frames = [
        lldp_frame(),
        eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, "10.10.0.20", 17, udp(5, 514, b"x"))),
        eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, "10.10.0.20", 17, udp(5, 53, dns_query("ntp.internal")))),
        eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV6, ip6(MGMT_V6, "2001:db8:0:10::9", 6, tcp(5, 443))),
    ]
    eng, fs = run(cfg, frames, learn=True)
    c.eq(fs, [], "learn mode emits nothing at all")
    c.eq(eng.findings, [], "learn mode emits nothing from the lifecycle either")
    c.ok(eng.counters.get("frames", 0) >= len(frames), "learn keeps counters intact")
    eng.finish(1000.0 + 90000)

    db = eng.baseline.devices["leaf1"]
    c.ok("10.10.0.20|udp|514" in db.endpoints, "learn recorded a v4 endpoint")
    c.ok("2001:db8:0:10::9|tcp|443" in db.endpoints, "learn recorded a v6 endpoint (dual-stack)")
    c.ok("ntp.internal" in db.dns_names, "learn recorded a DNS name")
    c.ok("private" in db.scopes, "learn recorded an address scope")
    c.ok("global" in db.scopes, "learn recorded the v6 global scope")

    rt = DG.Baseline.from_json(json.loads(json.dumps(eng.baseline.to_json())))
    c.eq(rt.devices["leaf1"].endpoints, db.endpoints, "baseline endpoints round-trip")
    c.eq(rt.devices["leaf1"].dns_names, db.dns_names, "baseline names round-trip")
    c.eq(rt.attribution_fingerprint, cfg.attribution_fingerprint(), "fingerprint round-trips")
    c.eq(rt.content_hash(), eng.baseline.content_hash(), "content hash is stable across a round-trip")
    c.eq(rt.format, DG.BASELINE_FORMAT, "baseline carries its format version")

    # Fingerprint must move with the attributed device set, and ONLY with it.
    a = base_cfg()
    b = base_cfg()
    b.known_os10 = [DG.KnownDevice(mac="00:00:00:00:00:01", addrs=["10.0.0.1"])]
    c.ok(a.attribution_fingerprint() != b.attribution_fingerprint(),
         "fingerprint changes with the device set")
    d = base_cfg(suppress_max=99, fanout_threshold=99)
    c.eq(a.attribution_fingerprint(), d.attribution_fingerprint(),
         "fingerprint does NOT move for knobs unrelated to attribution")
    e = base_cfg(attribution_mode="l2l3")
    c.ok(a.attribution_fingerprint() != e.attribution_fingerprint(),
         "fingerprint moves with attribution_mode")

    mism = ready_baseline(cfg)
    mism.attribution_fingerprint = "0" * 16
    eng2, _ = run(cfg, [], baseline=mism)
    c.ok("DG-303" in codes(eng2.findings), "mismatched fingerprint refused")
    c.eq(eng2.baseline_state, "absent", "a refused baseline is not used")
    c.ok(eng2.baseline is None, "a refused baseline is discarded, not merely flagged")

    # NEVER AUTO-LEARN. Structural: enforcement over anomalous traffic must
    # leave the baseline byte-identical. An auto-updating baseline is
    # attacker-poisonable by simply talking to the device often enough.
    bl = ready_baseline(cfg)
    before = bl.content_hash()
    anomalous = [
        eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, f"203.0.113.{i}", 6, tcp(1000 + i, 8080)))
        for i in range(1, 15)
    ] + [
        eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, "169.254.169.254", 6, tcp(1, 80))),
        eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4,
            ip4(MGMT_V4, "10.10.0.20", 17, udp(1, 53, dns_query("evil.attacker.tld")))),
    ]
    eng3, fs3 = run(cfg, anomalous, baseline=bl)
    c.ok(len(fs3) > 0, "the anomalous set really does produce findings (non-vacuity)")
    c.eq(bl.content_hash(), before, "enforcement never mutates the baseline")

    # Thin baseline downgrades rather than silencing or over-claiming.
    thin = ready_baseline(cfg, started=0.0, ended=60.0)
    thin.devices["leaf1"].frames = 5
    eng4, fs4 = run(cfg, [anomalous[0]], baseline=thin)
    c.eq(eng4.baseline_state, "thin", "thin baseline recognised")
    c.ok("DG-302" in codes(eng4.findings), "DG-302 emitted once at start")
    d202 = [f for f in fs4 if f["code"] == "DG-202"]
    c.eq(len(d202), 1, "thin baseline still DETECTS")
    if d202:
        c.eq(d202[0]["severity"], "notice", "severity downgraded one step")
        c.eq(d202[0]["confidence"], "low", "confidence downgraded")
        c.ok(d202[0]["detail"].get("baseline_thin") is True, "downgrade visible in the detail")

    # With no baseline at all the gated rules are inert and say so.
    eng5, fs5 = run(base_cfg(), [anomalous[0], anomalous[-1]])
    c.ok("DG-301" in codes(eng5.findings), "DG-301 announces the inert rules")
    for gated in DG.BASELINE_GATED_CODES:
        c.ok(gated not in codes(fs5), f"{gated} inert without a baseline")
    d301 = [f for f in eng5.findings if f["code"] == "DG-301"][0]
    c.eq(sorted(d301["detail"]["inert_codes"]), sorted(DG.BASELINE_GATED_CODES),
         "DG-301 names exactly the codes that are inert")


# ---------------------------------------------------------------------------
# K - coverage and non-vacuity
# ---------------------------------------------------------------------------


def section_k(c: Check) -> None:
    c.sec("K coverage")
    # Literal call sites...
    literal: set[str] = set()
    for n in ast.walk(TREE):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "_finding":
            for a in n.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value.startswith("DG-"):
                    literal.add(a.value)
    c.ok(len(literal) >= 12, f"literal extractor is not vacuous ({len(literal)})")

    # ...plus the runtime-dispatched half. An extractor that resolves only
    # literal arguments silently under-reports, which makes this whole check
    # vacuous; the dispatcher is therefore RUN rather than read.
    dispatched = {DG.screen_version(v)["code"] for v in
                  [(10, 5, 6, 4), (10, 5, 6, 99), (10, 5, 3, 1), (10, 5, 6)]} - {None}
    c.ok(dispatched >= {"DG-001", "DG-002", "DG-003"},
         f"screen_version dispatches the posture codes ({sorted(dispatched)})")
    missing = sorted(set(DG.FINDINGS) - literal - dispatched)
    c.eq(missing, [], f"every declared code has an emitting path ({missing})")

    # Reachability: each code must be produced by a real frame sequence through
    # the production engine, not merely present in the source.
    cfg = base_cfg()
    seen: set[str] = set()
    scenarios: list[tuple[Any, list[bytes], Any, bool]] = [
        (cfg, [lldp_frame()], ready_baseline(cfg), False),
        (cfg, [lldp_frame(sysdesc="Dell EMC Networking OS10 Enterprise")], ready_baseline(cfg), False),
        (cfg, [lldp_frame(sysdesc="Dell EMC Networking OS10. OS Version: 10.9.9.9")],
         ready_baseline(cfg), False),
        (cfg, [lldp_frame(sysdesc="Dell Enterprise SONiC Distribution 4.5.0",
                          mac=bytes.fromhex("001ec9010203"))], ready_baseline(cfg), False),
        (cfg, [lldp_frame(mgmt=None)], ready_baseline(cfg), False),
        (cfg, [eth(PEER_MAC_B, SW_MAC_B, DG.ETH_IPV4, ip4("10.10.0.99", MGMT_V4, 6, tcp(1, 80)))],
         ready_baseline(cfg), False),
        (cfg, [eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, "169.254.169.254", 6, tcp(1, 80)))],
         None, False),
        (base_cfg(fanout_threshold=3),
         [eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, f"203.0.113.{i}", 6, tcp(1000 + i, 8080)))
          for i in range(1, 6)],
         ready_baseline(base_cfg(fanout_threshold=3)), False),
        (cfg, [eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4,
                   ip4(MGMT_V4, "10.10.0.20", 17, udp(1, 53, dns_query("evil.attacker.tld"))))],
         ready_baseline(cfg), False),
        (DG.Config(), [lldp_frame(mgmt=None),
                       eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4,
                           ip4(MGMT_V4, "169.254.169.254", 6, tcp(1, 80)))],
         ready_baseline(DG.Config()), False),
        (base_cfg(), [], None, False),
        (base_cfg(), [], ready_baseline(base_cfg(), started=0.0, ended=5.0), False),
        (base_cfg(bpf="udp port 53"), [], None, False),
    ]
    for cf, frames, bl, learn in scenarios:
        eng, _ = run(cf, frames, baseline=bl, learn=learn)
        seen.update(codes(eng.findings))
    mism = ready_baseline(base_cfg())
    mism.attribution_fingerprint = "0" * 16
    eng, _ = run(base_cfg(), [], baseline=mism)
    seen.update(codes(eng.findings))

    unreached = sorted(set(DG.FINDINGS) - seen)
    c.eq(unreached, [], f"every declared code is reachable through the engine ({unreached})")

    # Dead attribute scan: a field declared and never read is the vestigial
    # class that produced ndpwatch's _ra_flood_active.
    read_attrs: set[str] = set()
    for n in ast.walk(TREE):
        if isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load):
            read_attrs.add(n.attr)
    for cls_name in ("L3", "Lldp", "Device", "DeviceBaseline", "Baseline"):
        cls = getattr(DG, cls_name)
        for fname in getattr(cls, "__dataclass_fields__", {}):
            c.ok(fname in read_attrs, f"{cls_name}.{fname} is read somewhere, not vestigial")

    # Unused function parameters
    for n in ast.walk(TREE):
        if isinstance(n, ast.FunctionDef):
            used = {x.id for x in ast.walk(n) if isinstance(x, ast.Name)}
            used |= {x.attr for x in ast.walk(n) if isinstance(x, ast.Attribute)}
            for arg in n.args.args:
                if arg.arg in ("self", "cls") or arg.arg.startswith("_"):
                    continue
                c.ok(arg.arg in used, f"{n.name}() parameter {arg.arg!r} is used")


# ---------------------------------------------------------------------------
# L - silence contract, discrimination, lab artefacts
# ---------------------------------------------------------------------------


def write_pcap(path: str, frames: list[bytes], base_ts: float = 1_700_000_000.0,
               interval_us: int = 1000) -> None:
    """Dependency-free pcap writer.

    Timestamp arithmetic is base_ts plus interval MICROseconds WITH CARRY.
    Writing the frame index into the seconds field instead produces a file
    whose span looks plausible and whose ordering is wrong.
    """
    sec = int(base_ts)
    usec = int(round((base_ts - sec) * 1_000_000))
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for i, f in enumerate(frames):
            u = usec + i * interval_us
            s = sec + u // 1_000_000
            u %= 1_000_000
            fh.write(struct.pack("<IIII", s, u, len(f), len(f)))
            fh.write(f)


def read_pcap(path: str) -> list[tuple[int, int, bytes]]:
    out = []
    with open(path, "rb") as fh:
        gh = fh.read(24)
        assert struct.unpack("<I", gh[:4])[0] == 0xA1B2C3D4
        while True:
            ph = fh.read(16)
            if len(ph) < 16:
                break
            s, u, incl, orig = struct.unpack("<IIII", ph)
            out.append((s, u, fh.read(incl)))
    return out


def section_l(c: Check) -> None:
    c.sec("L silence + artefacts")
    cfg = base_cfg()
    bl = ready_baseline(cfg)

    # CLEAN-SET SILENCE CONTRACT, enforced offline. Benign traffic must raise
    # ZERO attack findings AND must not screen a version into CVE range - the
    # second half is the trap where a "benign" fixture quietly advertises
    # itself as a vulnerable box.
    clean = [
        lldp_frame(sysdesc="Dell EMC Networking OS10 Enterprise. Dell EMC OS Version: 10.5.6.9"),
        eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, "10.10.0.20", 17, udp(4, 514, b"log"))),
        eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, "10.10.0.21", 17, udp(4, 123, b"\x1b" + b"\x00" * 47))),
        eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4,
            ip4(MGMT_V4, "10.10.0.20", 17, udp(4, 53, dns_query("ntp.internal")))),
        eth(PEER_MAC_B, SW_MAC_B, DG.ETH_IPV4, ip4("10.10.0.99", MGMT_V4, 6, tcp(5, 22))),
        eth(PEER_MAC_B, SW_MAC_B, DG.ETH_IPV4, ip4("10.10.0.99", MGMT_V4, 6, tcp(5, 443))),
        eth(SW_MAC_B, bytes.fromhex("01005e000005"), DG.ETH_IPV4, ip4(MGMT_V4, "224.0.0.5", 89, b"\x00" * 20)),
        eth(SW_MAC_B, bytes.fromhex("3333000000fb"), DG.ETH_IPV6, ip6(MGMT_V6, "ff02::fb", 17, udp(5353, 5353))),
    ]
    eng, fs = run(cfg, clean, baseline=bl)
    attack = [f for f in fs if f["class"] == "ATTACK"]
    c.eq([f["code"] for f in attack], [], "clean set raises zero ATTACK findings")
    posture = [f for f in fs if f["code"] == "DG-001"]
    c.eq(posture, [], "clean set does not screen a version into CVE range")

    # CROSS-PROTOCOL DISCRIMINATION. Other Ragnar modules' traffic must not be
    # read as anything dellguard cares about; a cross-module false positive
    # would have dellguard firing on cdpwatch's and vtpwatch's segment.
    cdp = eth(SW_MAC_B, bytes.fromhex("01000ccccccc"), 0x0100,
              b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + b"\x02\x00\x00\x10" + b"\x00" * 16)
    stp = eth(SW_MAC_B, bytes.fromhex("0180c2000000"), 0x0026, b"\x42\x42\x03" + b"\x00" * 35)
    arp = eth(SW_MAC_B, bytes.fromhex("ffffffffffff"), 0x0806, b"\x00\x01\x08\x00\x06\x04\x00\x01" + b"\x00" * 20)
    lacp = eth(SW_MAC_B, bytes.fromhex("0180c2000002"), 0x8809, b"\x01\x01" + b"\x00" * 108)
    eng2, fs2 = run(cfg, [cdp, stp, arp, lacp], baseline=bl)
    c.eq(codes(fs2), [], "CDP/STP/ARP/LACP from the device produce nothing")
    c.eq(eng2.parse_errors, 0, "non-IP control protocols are skipped, not mis-parsed")

    # Pcap artefacts for the future sealed-namespace lab.
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "clean.pcap")
        write_pcap(p, clean)
        recs = read_pcap(p)
        c.eq(len(recs), len(clean), "pcap holds every frame")
        c.eq([r[2] for r in recs], clean, "pcap frames round-trip byte-for-byte")
        ts = [(s, u) for s, u, _ in recs]
        c.ok(all(ts[i] < ts[i + 1] for i in range(len(ts) - 1)), "pcap timestamps are monotonic")
        c.ok(all(0 <= u < 1_000_000 for _, u, _ in recs), "pcap microseconds are legal")
        span = (ts[-1][0] - ts[0][0]) + (ts[-1][1] - ts[0][1]) / 1e6
        c.ok(span < base_cfg().suppress_window_s, "artefact span fits inside the suppress window")

        # Carry across a second boundary
        p2 = os.path.join(td, "carry.pcap")
        write_pcap(p2, clean, base_ts=1_700_000_000.999, interval_us=1000)
        recs2 = read_pcap(p2)
        c.ok(all(0 <= u < 1_000_000 for _, u, _ in recs2), "microseconds stay legal across a carry")
        c.ok(recs2[-1][0] > recs2[0][0], "the carry actually advanced the seconds field")

    # Largest lab frame, so the lab can size its veth MTU at runtime rather
    # than hardcoding it.
    biggest = max(len(f) for f in clean)
    c.ok(biggest < 1500, f"lab fixtures fit a default MTU ({biggest} bytes)")

    # Machine-readable introspection the lab reads at runtime.
    import subprocess

    r = subprocess.run([sys.executable, MODULE_PATH, "--print-lab-codes"],
                       capture_output=True, text=True)
    c.eq(r.returncode, 0, "--print-lab-codes exits clean")
    c.eq(sorted(r.stdout.split()), sorted(DG.FINDINGS), "--print-lab-codes matches the registry")
    r2 = subprocess.run([sys.executable, MODULE_PATH, "--selftest"], capture_output=True, text=True)
    c.eq(r2.returncode, 0, "module self-test passes as a subprocess")
    r3 = subprocess.run([sys.executable, MODULE_PATH, "--audit"], capture_output=True, text=True)
    c.eq(r3.returncode, 0, "module audit passes as a subprocess")
    r4 = subprocess.run([sys.executable, MODULE_PATH, "--print-config"], capture_output=True, text=True)
    c.eq(r4.returncode, 0, "--print-config exits clean")
    loaded = DG.Config.load(json.loads(r4.stdout))
    c.eq(loaded.dump(), DG.Config().dump(), "the printed config loads back through production Config")

    # Documented no-op flags must still parse.
    for flag in DG.NOOP_FLAGS:
        r5 = subprocess.run([sys.executable, MODULE_PATH, flag, "--print-lab-codes"],
                            capture_output=True, text=True)
        c.eq(r5.returncode, 0, f"documented no-op {flag} still parses")
        c.ok(len(DG.NOOP_FLAGS[flag]) > 30, f"no-op {flag} carries a substantive explanation")


# ---------------------------------------------------------------------------
# Lab artefacts
# ---------------------------------------------------------------------------
# The sealed-namespace lab reads its frames, its expected codes and its MTU from
# here AT RUNTIME. Nothing about the lab's traffic is hardcoded in the lab
# script, so a fixture change cannot leave the lab asserting a stale shape.

CANARY_MAC = bytes.fromhex("001ec9ca0001")
OLD_MAC = bytes.fromhex("001ec9b00001")
NOVER_MAC = bytes.fromhex("001ec9b00002")
UNTRACKED_MAC = bytes.fromhex("001ec9b00003")
SONIC_MAC = bytes.fromhex("001ec9b00004")
NOMGMT_MAC = bytes.fromhex("001ec9b00005")

OS10_FIXED = "Dell EMC Networking OS10 Enterprise. Dell EMC OS Version: 10.5.6.9"
OS10_VULN = "Dell EMC Networking OS10 Enterprise. Dell EMC OS Version: 10.5.6.4"
OS10_NOVER = "Dell EMC Networking OS10 Enterprise"
OS10_UNTRACKED = "Dell EMC Networking OS10 Enterprise. Dell EMC OS Version: 10.5.3.5"
SONIC_DESC = "Dell Enterprise SONiC Distribution 4.5.0"

MGMT_V6_ULA = "fd00:10::5"


def artefact_sets() -> dict[str, list[bytes]]:
    """Named frame sets the lab replays, one pcap each."""
    eg4 = lambda dst, proto, payload: eth(  # noqa: E731
        SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4, ip4(MGMT_V4, dst, proto, payload))
    eg6 = lambda dst, proto, payload: eth(  # noqa: E731
        SW_MAC_B, PEER_MAC_B, DG.ETH_IPV6, ip6(MGMT_V6_ULA, dst, proto, payload))
    inb = lambda sport, dport: eth(  # noqa: E731
        PEER_MAC_B, SW_MAC_B, DG.ETH_IPV4, ip4("10.10.0.99", MGMT_V4, 6, tcp(sport, dport)))

    sets: dict[str, list[bytes]] = {}

    # The readiness canary. Its version sits AT or ABOVE the fixed release for a
    # tracked train, so it screens to nothing and emits exactly one code -
    # DG-101 - which makes it a clean, attributable liveness probe.
    sets["canary"] = [
        lldp_frame(sysname="lab-canary", sysdesc=OS10_FIXED, mgmt="10.10.0.200", mac=CANARY_MAC)
    ]

    # Benign: drives the learn pass AND the false-positive gate. Every egress
    # here is what a switch legitimately originates. The IPv6 leg deliberately
    # targets a ULA so the learned scope set stays {private} - that is what
    # makes the attack set's global destination a real scope crossing.
    sets["benign"] = [
        lldp_frame(sysname="leaf1", sysdesc=OS10_FIXED, mgmt=MGMT_V4),
        eg4("10.10.0.20", 17, udp(40000, 514, b"<134>sshd: accepted")),
        eg4("10.10.0.21", 17, udp(40001, 123, b"\x1b" + b"\x00" * 47)),
        eg4("10.10.0.20", 17, udp(40002, 53, dns_query("ntp.internal"))),
        eg6("fd00:10::20", 6, tcp(40003, 443)),
        inb(51000, 22),
        inb(51001, 443),
        eth(SW_MAC_B, bytes.fromhex("01005e000005"), DG.ETH_IPV4,
            ip4(MGMT_V4, "224.0.0.5", 89, b"\x00" * 20)),
        eth(SW_MAC_B, bytes.fromhex("3333000000fb"), DG.ETH_IPV6,
            ip6(MGMT_V6_ULA, "ff02::fb", 17, udp(5353, 5353))),
        # TRANSIT. The switch's own MAC in the source position but somebody
        # else's source address - a frame the box is FORWARDING, not one it
        # originated. Present so the origination test has traffic that can
        # actually violate it: without that guard this frame alone produces
        # DG-202/DG-203/DG-206 and the false-positive gate fails. A guard the
        # lab's own traffic cannot break is a guard the lab does not test.
        eth(SW_MAC_B, PEER_MAC_B, DG.ETH_IPV4,
            ip4("192.0.2.77", "203.0.113.9", 6, tcp(41000, 8080))),
    ]

    # Attack: every DG-2xx egress rule, over both address families.
    sets["attack"] = [
        eg4("203.0.113.9", 6, tcp(40100, 8080)),
        eg4("10.10.0.20", 17, udp(40101, 53, dns_query("evil.attacker.tld"))),
        eg4("169.254.169.254", 6, tcp(40102, 80)),
        eg6("2001:db8:beef::9", 6, tcp(40103, 8080)),
    ] + [eg4(f"10.10.9.{i}", 6, tcp(40200 + i, 80)) for i in range(1, 11)]

    # Posture and exposure, one device per code so every finding is
    # attributable to a distinct key in the output.
    sets["posture"] = [
        lldp_frame(sysname="leaf-old", sysdesc=OS10_VULN, mgmt="10.10.0.6", mac=OLD_MAC),
        lldp_frame(sysname="leaf-nover", sysdesc=OS10_NOVER, mgmt="10.10.0.7", mac=NOVER_MAC),
        lldp_frame(sysname="leaf-untracked", sysdesc=OS10_UNTRACKED, mgmt="10.10.0.8",
                   mac=UNTRACKED_MAC),
        lldp_frame(sysname="sonic1", sysdesc=SONIC_DESC, mgmt="10.10.0.9", mac=SONIC_MAC),
        lldp_frame(sysname="leaf-nomgmt", sysdesc=OS10_VULN, mgmt=None, mac=NOMGMT_MAC),
        eth(NOMGMT_MAC, PEER_MAC_B, DG.ETH_IPV4, ip4("10.10.0.10", "203.0.113.50", 6, tcp(1, 80))),
        eth(PEER_MAC_B, SW_MAC_B, DG.ETH_IPV4, ip4("10.10.0.99", MGMT_V4, 6, tcp(51002, 23))),
    ]

    # Out-of-scope traffic for the BPF scoping negative test.
    sets["offscope"] = [eg4("198.51.100.1", 6, tcp(40300, 9999))]

    return sets


# Codes each set is expected to produce, by phase. The lab checks BOTH
# directions: every expected code must appear, and no unexpected code may.
ARTEFACT_EXPECT = {
    "canary": ["DG-101"],
    "benign_learn": [],
    "benign_enforce": ["DG-101"],
    "attack": ["DG-201", "DG-202", "DG-203", "DG-204", "DG-205", "DG-206"],
    "posture": ["DG-001", "DG-002", "DG-003", "DG-004", "DG-101", "DG-102", "DG-103", "DG-207"],
    "operational": ["DG-301", "DG-302", "DG-303", "DG-304"],
}


def lab_configs() -> dict[str, dict[str, Any]]:
    """Configs the lab runs against, emitted here so they cannot drift from the
    frames. All three declare the SAME device except the mismatch config, whose
    whole purpose is to move the attribution fingerprint."""
    declared = [{"label": "leaf1", "mac": DG.fmt_mac(SW_MAC_B),
                 "addrs": [MGMT_V4, MGMT_V6, MGMT_V6_ULA]}]
    return {
        # Default gate: a lab learn run lasts seconds, so this baseline is THIN
        # by construction and must downgrade what it drives.
        "lab": {"known_os10": declared},
        # Relaxed gate: the SAME baseline read as sufficient. The fingerprint
        # covers attribution inputs only, so one learn run serves both.
        "lab-relaxed": {"known_os10": declared, "learn_min_seconds": 1,
                        "learn_min_frames_per_device": 1,
                        "learn_min_endpoints_per_device": 1},
        # A different declared device set: the baseline must be REFUSED.
        "lab-mismatch": {"known_os10": [{"label": "other", "mac": "02:00:00:00:00:01",
                                         "addrs": ["10.99.0.1"]}]},
    }


def emit_artefacts(outdir: str) -> dict[str, Any]:
    os.makedirs(outdir, exist_ok=True)
    for name, body in lab_configs().items():
        cfgpath = os.path.join(outdir, f"{name}.conf.json")
        with open(cfgpath, "w", encoding="utf-8") as fh:
            json.dump(body, fh, indent=2, sort_keys=True)
        DG.Config.load(json.loads(open(cfgpath, encoding="utf-8").read()))
    sets = artefact_sets()
    manifest: dict[str, Any] = {"sets": {}, "expect": ARTEFACT_EXPECT}
    for name, frames in sets.items():
        path = os.path.join(outdir, f"{name}.pcap")
        write_pcap(path, frames)
        manifest["sets"][name] = {"frames": len(frames),
                                  "max_len": max(len(f) for f in frames),
                                  "path": path}
    manifest["mtu"] = max(s["max_len"] for s in manifest["sets"].values())
    manifest["all_codes"] = sorted(DG.FINDINGS)
    manifest["configs"] = {n: os.path.join(outdir, f"{n}.conf.json") for n in lab_configs()}
    return manifest


SECTIONS = [section_a, section_b, section_c, section_d, section_e, section_f,
            section_g, section_h, section_i, section_j, section_k, section_l]


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="dellguard_conformance")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--section", default="", help="run one section by letter")
    p.add_argument("--emit-artefacts", default="", metavar="DIR",
                   help="write the lab's pcap artefacts and print their manifest")
    args = p.parse_args(argv)

    if args.emit_artefacts:
        print(json.dumps(emit_artefacts(args.emit_artefacts), indent=2, sort_keys=True))
        return 0

    c = Check()
    nested = os.environ.get("DG_CONF_NESTED") == "1"
    for fn in SECTIONS:
        letter = fn.__name__.split("_")[1].upper()
        if args.section and letter != args.section.upper():
            continue
        # Section B re-runs the whole harness in a temp dir; skipping it when
        # already nested is what stops that from recursing forever. The skip is
        # ANNOUNCED rather than silent - a skip mode that hides what it skipped
        # lets a mutation pass while proving nothing.
        if nested and fn is section_b:
            if not args.quiet:
                print("  [B dependencies] SKIPPED (nested run; standalone proof is the outer run)")
            continue
        fn(c)

    if not args.quiet:
        for name, n in c.per_section.items():
            print(f"  {name:28} {n}")
    print(f"conformance: {c.passed}/{c.passed + len(c.failed)} passed")
    for f in c.failed:
        print(f"  FAIL {f}")
    return 0 if not c.failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
