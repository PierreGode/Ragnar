#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cfmwatch tier 1 - conformance.

Registry integrity, parser unit behaviour, and an exact fixture match:
every fixture must fire exactly the codes its manifest entry claims, no
more and no fewer. Exact matching is deliberate - a superset check hides
over-firing, which is the failure mode that makes a detector useless on a
live tap.
"""

from __future__ import annotations

import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import cfmwatch as cw                                           # noqa: E402
import make_fixtures as mk                                      # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append((name, detail))
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name,
                         ("  <- " + detail) if detail and not cond else ""))


def run_pcap(path, extra_args=None):
    ns = cw.build_parser().parse_args(["--pcap", path] + list(extra_args or []))
    eng = cw.Engine(cw.config_from_args(ns))
    for i, (ts, raw) in enumerate(cw.read_pcap(path)):
        eng.feed_raw(raw, i, ts)
    eng.finalize()
    return eng


def feed_one(raw, **cfg):
    eng = cw.Engine(cw.Config(**cfg))
    frame = eng.feed_raw(raw, 0, mk.BASE_TS)
    eng.finalize()
    return eng, frame


# --------------------------------------------------------------------------
print("\n[1] registry integrity")

codes = [s.code for s in cw.SPECS]
check("codes are unique", len(codes) == len(set(codes)))
check("codes sort stably", codes == sorted(codes, key=lambda c: (c.split("-")[1])))
check("registry maps every spec", len(cw.REGISTRY) == len(cw.SPECS))
bad = [s.code for s in cw.SPECS if s.severity not in cw.SEVERITY_ORDER]
check("severities are known", not bad, str(bad))
bad = [s.code for s in cw.SPECS if s.confidence not in ("HIGH", "MEDIUM", "LOW")]
check("confidences are known", not bad, str(bad))
bad = [s.code for s in cw.SPECS if s.cls not in cw.CLASS_NAMES]
check("classes are known", not bad, str(bad))
bad = [s.code for s in cw.SPECS if len(s.summary) < 40]
check("every code has a real summary", not bad, str(bad))
bad = [s.code for s in cw.SPECS if s.confidence == "LOW" and not s.caveat]
check("every LOW-confidence code carries a caveat", not bad, str(bad))
bad = [s.code for s in cw.SPECS if s.cls == "H" and not s.cves]
check("every class H code names its CVE", not bad, str(bad))
check("CVE-2014-3223 has no detector code",
      not any("CVE-2014-3223" in s.cves for s in cw.SPECS))
check("CVE-2023-20233 stays rejected",
      not any("CVE-2023-20233" in s.cves for s in cw.SPECS))

eng = cw.Engine()
dummy = cw.CfmFrame(index=0, ts=0.0, frame_len=60, dst=b"\x00" * 6,
                    src=b"\x00" * 6, vlans=[], md_level=0, version=0,
                    opcode=1, flags=0, first_tlv_offset=70, payload=b"\x00" * 4)
try:
    eng.emit("CFM-999", "k", "d", dummy)
    check("emit() rejects an unregistered code", False)
except KeyError:
    check("emit() rejects an unregistered code", True)

# --------------------------------------------------------------------------
print("\n[2] parser units")

frame = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_A, mk.ccm(3, 10)), 0, 0.0)
check("CCM parses", frame is not None and frame.opcode == cw.OP_CCM)
check("MD level decodes", frame.md_level == 3)
check("MEP ID decodes", frame.body["mepid"] == 10)
check("MAID decodes", frame.body["maid"]["md_name"] == b"DOMAIN1" and
      frame.body["maid"]["ma_name"] == b"MA-100",
      str(frame.body["maid"]))
check("CCM interval decodes", frame.body["interval"] == 4)
check("clean CCM has no structural defect", not frame.structural,
      str(frame.structural))

qinq = mk.eth(mk.D3, mk.MAC_A, mk.ccm(3, 10),
              vlans=((0x88A8, 300), (0x8100, 101)))
frame = cw.parse_cfm(qinq, 0, 0.0)
check("QinQ outer and inner tags both parse",
      frame is not None and frame.vlan_key == (300, 101),
      str(frame.vlan_key if frame else None))

frame = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_A, mk.ccm(3, 10), vlans=()), 0, 0.0)
check("untagged CFM parses", frame is not None and frame.vlan_key == ())

check("non-CFM ethertype is ignored",
      cw.parse_cfm(mk.MAC_A + mk.MAC_B + struct.pack("!H", 0x0800) +
                   b"\x00" * 46, 0, 0.0) is None)
check("802.3ah Link OAM is not claimed by this module",
      cw.parse_cfm(mk.MAC_A + mk.MAC_B + struct.pack("!H", 0x8809) +
                   b"\x00" * 46, 0, 0.0) is None)

# Padding trap: zero padding after the End TLV must stay silent.
padded = mk.eth(mk.D3, mk.MAC_X, mk.lbm(3), minlen=60)
_e, frame = feed_one(padded)
check("zero padding after End TLV is silent",
      not any(c == "CFM-009" for c, _ in frame.structural),
      str(frame.structural))

# FCS allowance: exactly four non-zero octets at padded minimum length.
# A real padded capture: 60 octets of frame, zero padding after the End
# TLV, then the 4-octet FCS the NIC appended -> 64 octets on disk.
body = mk.eth(mk.D3, mk.MAC_X, mk.lbm(3), minlen=60) + b"\xde\xad\xbe\xef"
assert len(body) == 64, len(body)
_e, frame = feed_one(body)
check("4-octet non-zero tail at minimum length is read as FCS",
      not any(c == "CFM-009" for c, _ in frame.structural),
      str(frame.structural))
_e, frame = feed_one(body, strict_tail=True)
check("--strict-tail withdraws the FCS allowance",
      any(c == "CFM-009" for c, _ in frame.structural),
      str(frame.structural))

# MD name format 1 carries no length octet.
m1 = mk.maid(md_fmt=1, md_name=b"", ma_fmt=2, ma_name=b"MA-X")
frame = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_A, mk.ccm(3, 5, m=m1)), 0, 0.0)
check("MD name format 1 parses without a length octet",
      frame.body["maid"]["ma_name"] == b"MA-X" and not frame.structural,
      str(frame.body["maid"]) + str(frame.structural))

# A 256-entry TLV chain must terminate rather than spin.
chain = (mk.tlv(3, b"") * 300)
frame = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_X,
                            mk.cfm(3, 3, 0, 4, struct.pack("!I", 1), chain),
                            minlen=0), 0, 0.0)
check("TLV walk is bounded", frame is not None and
      any(c == "CFM-002" for c, _ in frame.structural),
      str(frame.structural[:2]))

# --------------------------------------------------------------------------
print("\n[3] fixture corpus, exact match")

manifest = json.load(open(os.path.join(mk.FIXDIR, "manifest.json")))
claimed = set()
for entry in manifest:
    path = os.path.join(mk.FIXDIR, entry["pcap"])
    eng = run_pcap(path, entry["args"])
    got = {f.code for f in eng.results()}
    want = set(entry["expect"])
    claimed |= want
    check("%s fires exactly its claimed codes" % entry["name"], got == want,
          "missing=%s extra=%s" % (sorted(want - got), sorted(got - want)))
    check("%s parsed every frame as CFM" % entry["name"],
          eng.frames_cfm == entry["frames"],
          "%d of %d" % (eng.frames_cfm, entry["frames"]))

missing = sorted(set(cw.REGISTRY) - claimed)
check("every registry code is claimed by a fixture", not missing, str(missing))

# --------------------------------------------------------------------------
print("\n[4] baseline quiet")

eng = run_pcap(os.path.join(mk.FIXDIR, "baseline.pcap"))
noisy = [f.code for f in eng.results()
         if cw.REGISTRY[f.code].severity not in (cw.SEV_INFO, cw.SEV_LOW)]
check("healthy traffic raises nothing above LOW", not noisy, str(noisy))

# --------------------------------------------------------------------------
print("\n[5] output renderers")

eng = run_pcap(os.path.join(mk.FIXDIR, "aps.pcap"))
doc = json.loads(cw.render_json(eng))
check("JSON report carries summary and findings",
      "summary" in doc and len(doc["findings"]) == len(eng.results()))
check("JSON findings carry severity, confidence and context",
      all({"severity", "confidence", "context"} <= set(f)
          for f in doc["findings"]))
nd = cw.render_ndjson(eng).strip().splitlines()
check("NDJSON emits one object per finding", len(nd) == len(eng.results()))
check("NDJSON lines parse", all(json.loads(line) for line in nd))
text = cw.render_text(eng)
check("text report names every fired code",
      all(f.code in text for f in eng.results()))
check("text report surfaces the CRITICAL banner", "== CRITICAL ==" in text)
reg = cw.render_registry()
check("registry listing covers every code",
      all(s.code in reg for s in cw.SPECS))

# --------------------------------------------------------------------------
print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
if FAIL:
    for name, detail in FAIL:
        print("  FAILED: %s %s" % (name, detail))
sys.exit(1 if FAIL else 0)
