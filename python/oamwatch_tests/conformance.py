#!/usr/bin/env python3
"""oamwatch offline conformance harness.

Dependency-free. Drives the PRODUCTION parser and engine, never a parallel
test implementation. Asserts scapy is never imported on this path - the scapy
cross-check lives in its own tier precisely so an independent dissector sits on
the other side of the length and bounds rules.

Tiers run here:
  1. per-code scenarios, each with a false-positive gate
  2. clean-set silence contract
  3. truncation at every offset
  4. single-bit-flip fuzz
  5. transmit-guard AST scan, with non-vacuity proof
  6. dead-knob configuration check
  7. registry integrity
"""

import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import frames as F                                   # noqa: E402
from oamwatch import registry as reg                 # noqa: E402
from oamwatch.config import Config, ConfigError      # noqa: E402
from oamwatch.engine import Engine                   # noqa: E402
from oamwatch.parser import parse_frame              # noqa: E402

PKG = os.path.join(ROOT, "oamwatch")

_checks = 0
_failures = []


def check(cond, what):
    global _checks
    _checks += 1
    if not cond:
        _failures.append(what)


def run(frame_list, cfg=None, start=1000.0, step=0.2):
    """Drive production parser + engine over frames with sane timestamps."""
    engine = Engine(cfg or Config())
    produced = []
    for i, raw in enumerate(frame_list):
        pdu = parse_frame(raw, strict_tail=(cfg or Config()).strict_tail,
                          ts=start + i * step)
        if pdu is None:
            continue
        produced.extend(engine.observe(pdu))
    return produced


def codes(findings):
    return [f.code for f in findings]


# --------------------------------------------------------------------------
# Tier 1: per-code scenarios, each with an FP gate
# --------------------------------------------------------------------------
def rate_burst(n, src=F.SRC_A):
    return [F.keepalive(src=src) for _ in range(n)]


def flap(times):
    out = []
    for _ in range(times):
        out.append(F.information(flags=F.FLAGS_OPERATIONAL | F.F_DYING_GASP))
        out.append(F.information(flags=F.FLAGS_OPERATIONAL))
    return out


SCENARIOS = {
    # ---- posture --------------------------------------------------------
    "OAM-020": (
        [F.information([F.info_tlv(config=F.C_ACTIVE | F.C_LOOPBACK)])],
        [F.information([F.info_tlv(config=F.C_ACTIVE)])], None),
    "OAM-021": (
        [F.information([F.info_tlv(config=F.C_VARS)])],
        [F.information([F.info_tlv(config=F.C_ACTIVE)])], None),
    "OAM-022": (
        [F.information([F.info_tlv(config=F.C_ACTIVE)])],
        [F.information([F.info_tlv(config=F.C_EVENTS)])], None),
    "OAM-023": (
        [F.information([F.info_tlv(config=F.C_UNIDIR)])],
        [F.information([F.info_tlv(config=F.C_ACTIVE)])], None),
    "OAM-024": (
        [F.information([F.info_tlv(max_pdu=9000)])],
        [F.information([F.info_tlv(max_pdu=1518)])], None),

    # ---- structural -----------------------------------------------------
    "OAM-040": (
        [F.information([F.info_tlv(length=0x40)])],
        [F.information([F.info_tlv()])], None),
    "OAM-041": (
        [F.information([F.info_tlv(length=0x01)])],
        [F.information([F.info_tlv()])], None),
    "OAM-042": (
        [F.information([F.info_tlv(length=0x0E)])],
        [F.information([F.info_tlv()])], None),
    "OAM-043": (
        [F.eth(0x00, bytes([0x01]), pad=False)],
        [F.information([F.info_tlv()])], None),
    "OAM-044": (
        [F.eth(0x07, b"\x00")],
        [F.eth(0x00, b"\x00")], None),
    "OAM-045": (
        [F.information(flags=F.FLAGS_OPERATIONAL | 0x8000)],
        [F.information(flags=F.FLAGS_OPERATIONAL)], None),
    "OAM-046": (
        [F.event_notification(tlvs=[F.event_tlv(0x02, length=24)])],
        [F.event_notification(tlvs=[F.event_tlv(0x02)])], None),
    "OAM-047": (
        [F.information([bytes([0x55, 0x08]) + b"\x00" * 6])],
        [F.information([F.info_tlv()])], None),
    "OAM-048": (
        [F.eth(0x00, F.info_tlv() + b"\x00" + b"SMUGGLED-DATA-HERE")],
        [F.information([F.info_tlv()])], None),
    "OAM-049": (
        [F.information([F.info_tlv(kind=2)])],
        [F.information([F.info_tlv(1), F.info_tlv(2)])], None),
    "OAM-050": (
        [F.information([F.info_tlv(state=0x03)])],
        [F.information([F.info_tlv(state=0x00)])], None),
    "OAM-051": (
        [F.loopback_control(command=0x03)],
        [F.loopback_control(command=0x01)], None),
    "OAM-052": (
        [F.variable_request(descriptors=((0x09, 0x0001),))],
        [F.variable_request(descriptors=((0x07, 0x0001),))], None),
    "OAM-053": (
        [F.variable_response(width_override=0x7F)],
        [F.variable_response()], None),
    "OAM-054": (
        [F.information([F.info_tlv(version=0x02)])],
        [F.information([F.info_tlv(version=0x01)])], None),
    "OAM-055": (
        [F.org_specific(data=b"\x41" * 1600)],
        [F.org_specific(data=b"\x41" * 64)], None),
    "OAM-056": (
        [F.information([bytes([0xFE, 0x04]) + b"\x00\x0a"])],
        [F.information([bytes([0xFE, 0x08]) + F.OUI_A + b"\x01\x02\x03"])],
        None),
    "OAM-057": (
        [F.information([F.info_tlv(1), F.info_tlv(1)])],
        [F.information([F.info_tlv(1), F.info_tlv(2)])], None),

    # ---- abuse ----------------------------------------------------------
    "OAM-060": (
        [F.loopback_control(command=0x01)],
        [F.loopback_control(command=0x02)], None),
    "OAM-061": (
        [F.loopback_control(command=0x02)],
        [F.loopback_control(command=0x01)], None),
    "OAM-062": (
        [F.information([F.info_tlv(state=0x01)])],
        [F.information([F.info_tlv(state=0x00)])], None),
    "OAM-063": (
        [F.information(flags=F.FLAGS_OPERATIONAL | F.F_DYING_GASP)],
        [F.information(flags=F.FLAGS_OPERATIONAL)], None),
    "OAM-064": (
        [F.information(flags=F.FLAGS_OPERATIONAL | F.F_CRITICAL)],
        [F.information(flags=F.FLAGS_OPERATIONAL)], None),
    "OAM-065": (
        [F.information(flags=F.FLAGS_OPERATIONAL | F.F_LINK_FAULT)],
        [F.information(flags=F.FLAGS_OPERATIONAL)], None),
    "OAM-066": (flap(3), flap(1), None),
    "OAM-067": (
        [F.information(flags=F.FLAGS_OPERATIONAL),
         F.information(flags=F.FLAGS_DISCOVERY)],
        [F.information(flags=F.FLAGS_OPERATIONAL),
         F.information(flags=F.FLAGS_OPERATIONAL)], None),
    "OAM-068": (
        [F.information([F.info_tlv(oui=F.OUI_A)]),
         F.information([F.info_tlv(oui=F.OUI_B)])],
        [F.information([F.info_tlv(oui=F.OUI_A)]),
         F.information([F.info_tlv(oui=F.OUI_A)])], None),
    "OAM-069": (
        [F.information([F.info_tlv(config=F.C_ACTIVE)]),
         F.information([F.info_tlv(config=F.C_ACTIVE | F.C_LOOPBACK)])],
        [F.information([F.info_tlv(config=F.C_ACTIVE)]),
         F.information([F.info_tlv(config=F.C_ACTIVE)])], None),
    "OAM-070": (rate_burst(16), rate_burst(4), 0.05),
    "OAM-071": (
        [F.variable_request()],
        [F.information()], None),
    "OAM-072": (
        [F.variable_response()],
        [F.variable_response_error()], None),
    "OAM-073": (
        [F.event_notification(seq=5), F.event_notification(seq=5)],
        [F.event_notification(seq=5), F.event_notification(seq=6)], None),
    "OAM-074": (
        [F.keepalive(src=F.SRC_A), F.keepalive(src=F.SRC_B)],
        [F.keepalive(src=F.SRC_A), F.keepalive(src=F.SRC_A)], None),
}


def tier1():
    missing = set(reg.CODES) - set(SCENARIOS)
    check(not missing, "codes with no scenario: %s" % sorted(missing))
    extra = set(SCENARIOS) - set(reg.CODES)
    check(not extra, "scenarios for unknown codes: %s" % sorted(extra))

    for code, (positive, negative, step) in sorted(SCENARIOS.items()):
        kw = {} if step is None else {"step": step}
        got = codes(run(positive, **kw))
        check(code in got,
              "%s: positive fixture produced %s, expected the code"
              % (code, sorted(set(got)) or "nothing"))
        got_neg = codes(run(negative, **kw))
        check(code not in got_neg,
              "%s: FALSE POSITIVE - negative fixture produced it (%s)"
              % (code, sorted(set(got_neg))))


# --------------------------------------------------------------------------
# Tier 2: clean-set silence contract
# --------------------------------------------------------------------------
def tier2():
    got = run(F.clean_set(), Config(posture_enabled=False))
    check(not got,
          "clean set must be silent with posture off, produced: %s"
          % [(f.code, f.detail) for f in got])

    # With posture on, the clean set may produce posture codes and nothing else.
    got_all = run(F.clean_set(), Config())
    non_posture = [f.code for f in got_all if f.klass != reg.POSTURE]
    check(not non_posture,
          "clean set produced non-posture findings: %s" % non_posture)

    # A long steady-state keepalive run at 1/sec must stay silent, including
    # the rate code: the standard rate is 1 OAMPDU/second.
    got_steady = run([F.keepalive() for _ in range(60)],
                     Config(posture_enabled=False), step=1.0)
    check(not got_steady,
          "60s of 1/sec keepalives must be silent, produced: %s"
          % codes(got_steady))


# --------------------------------------------------------------------------
# Tier 3: truncation at every offset
# --------------------------------------------------------------------------
def tier3():
    corpus = F.clean_set() + [
        F.variable_request(), F.variable_response(),
        F.loopback_control(), F.org_specific(),
        F.event_notification(tlvs=[F.event_tlv(0x01), F.event_tlv(0x03)]),
    ]
    bad = 0
    for raw in corpus:
        for cut in range(len(raw) + 1):
            try:
                pdu = parse_frame(raw[:cut], ts=1.0)
            except Exception as exc:          # noqa: BLE001 - that is the test
                bad += 1
                _failures.append("truncation at %d raised %r" % (cut, exc))
                continue
            if pdu is None:
                continue
            try:
                Engine().observe(pdu)
            except Exception as exc:          # noqa: BLE001
                bad += 1
                _failures.append("engine raised on truncation at %d: %r"
                                 % (cut, exc))
    check(bad == 0, "%d truncation failures" % bad)


# --------------------------------------------------------------------------
# Tier 4: single-bit-flip fuzz
# --------------------------------------------------------------------------
def tier4():
    corpus = [F.information([F.info_tlv(1), F.info_tlv(2)]),
              F.event_notification(tlvs=[F.event_tlv(0x01)]),
              F.variable_response(), F.variable_request(),
              F.loopback_control()]
    bad = 0
    flips = 0
    for raw in corpus:
        for i in range(len(raw)):
            for bit in range(8):
                mutated = bytearray(raw)
                mutated[i] ^= (1 << bit)
                flips += 1
                try:
                    pdu = parse_frame(bytes(mutated), ts=1.0)
                    if pdu is not None:
                        Engine().observe(pdu)
                except Exception as exc:      # noqa: BLE001
                    bad += 1
                    if bad < 6:
                        _failures.append(
                            "bit flip byte %d bit %d raised %r" % (i, bit, exc))
    check(bad == 0, "%d of %d bit flips raised" % (bad, flips))
    check(flips > 2000, "bit-flip corpus too small (%d flips)" % flips)


# --------------------------------------------------------------------------
# Tier 5: transmit-guard AST scan, plus non-vacuity
# --------------------------------------------------------------------------
BANNED_CALLS = {"send", "sendall", "sendto", "sendmsg", "sendp",
                "pcap_sendpacket", "inject", "write_packet"}
BANNED_IDENT = ("exploit", "payload_builder", "build_exploit", "attack_frame")


def scan_source(src, filename="<src>"):
    """Return a list of transmit-guard violations in one source string."""
    tree = ast.parse(src, filename)
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = (fn.attr if isinstance(fn, ast.Attribute)
                    else fn.id if isinstance(fn, ast.Name) else None)
            if name in BANNED_CALLS:
                bad.append("%s:%d calls %s()" % (filename, node.lineno, name))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                             ast.Name)):
            ident = getattr(node, "name", None) or getattr(node, "id", "")
            low = ident.lower()
            for b in BANNED_IDENT:
                if b in low:
                    bad.append("%s:%d defines/uses %r"
                               % (filename, getattr(node, "lineno", 0), ident))
    # module-scope socket/subprocess imports
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mods = ([a.name for a in node.names]
                    if isinstance(node, ast.Import) else [node.module or ""])
            for m in mods:
                root = m.split(".")[0]
                if root in ("socket", "subprocess", "scapy"):
                    bad.append("%s:%d imports %s at module scope"
                               % (filename, node.lineno, m))
    return bad


def tier5():
    violations = []
    files = []
    for fn in sorted(os.listdir(PKG)):
        if fn.endswith(".py"):
            path = os.path.join(PKG, fn)
            files.append(path)
            with open(path) as fh:
                violations.extend(scan_source(fh.read(), fn))
    check(len(files) >= 5, "expected at least 5 package files, found %d" % len(files))
    check(not violations, "transmit-guard violations: %s" % violations)

    # non-vacuity: the guard must bite on sources that genuinely offend
    probes = [
        ("sendall", "import socket\ndef f(s, b):\n    s.sendall(b)\n"),
        ("module socket", "import socket\nX = 1\n"),
        ("module scapy", "import scapy.all\n"),
        ("exploit ident", "def build_exploit():\n    return 1\n"),
    ]
    for label, src in probes:
        check(bool(scan_source(src, label)),
              "transmit guard is VACUOUS: did not flag %s" % label)

    # scapy must not be on the offline path at all
    check("scapy" not in sys.modules,
          "scapy was imported during the offline conformance run")


# --------------------------------------------------------------------------
# Tier 6: dead-knob configuration check
# --------------------------------------------------------------------------
def tier6():
    from oamwatch.config import DEFAULTS
    blob = ""
    for fn in sorted(os.listdir(PKG)):
        if fn.endswith(".py") and fn != "config.py":
            with open(os.path.join(PKG, fn)) as fh:
                blob += fh.read()
    for key in DEFAULTS:
        check(key in blob, "configuration key %r is a dead knob: never read "
                           "outside config.py" % key)

    # strict validation really rejects
    for bad in ({"nonsense": 1}, {"flap_threshold": 0},
                {"flap_window_sec": -1}, {"strict_tail": "yes"},
                {"suppress": ["OAM-999"]}):
        try:
            Config(**bad)
        except ConfigError:
            check(True, "")
        else:
            _failures.append("Config accepted invalid input %r" % bad)
            check(False, "config validation gap")

    # suppress actually suppresses
    got = codes(run([F.loopback_control(command=0x01)],
                    Config(suppress=["OAM-060"])))
    check("OAM-060" not in got, "suppress did not suppress OAM-060")


# --------------------------------------------------------------------------
# Tier 7: registry integrity
# --------------------------------------------------------------------------
def tier7():
    for code, (name, klass, sev, summary) in reg.REGISTRY.items():
        check(code.startswith("OAM-") and len(code) == 7,
              "malformed code %r" % code)
        check(name.isupper() or "_" in name, "odd finding name %r" % name)
        check(klass in (reg.POSTURE, reg.STRUCTURAL, reg.ABUSE),
              "%s: unknown class %r" % (code, klass))
        check(sev in reg.SEVERITY_ORDER, "%s: unknown severity %r" % (code, sev))
        check(len(summary) > 30, "%s: summary too thin" % code)
    names = [v[0] for v in reg.REGISTRY.values()]
    check(len(names) == len(set(names)), "duplicate finding names in registry")
    check(len(reg.CODES) == 38, "registry size changed: %d" % len(reg.CODES))


# --------------------------------------------------------------------------
def main():
    for tier in (tier1, tier2, tier3, tier4, tier5, tier6, tier7):
        tier()
    print("oamwatch conformance: %d checks, %d failure(s)"
          % (_checks, len(_failures)))
    for f in _failures:
        print("  FAIL: %s" % f)
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
