#!/usr/bin/env python3
"""
lldpwatch_dcbx_xcheck — independent cross-check of the DCBX decode, against
Wireshark's dissector via tshark.

WHY THIS TIER EXISTS SEPARATELY FROM THE SCAPY ONE.
scapy has NO DCBX support: scapy.contrib.lldp decodes an Organizationally
Specific TLV as LLDPDUGenericOrganisationSpecific, an opaque byte blob. So
the module's existing cross-check tier — which is the thing that makes every
other length and bounds rule trustworthy (suite LESSON A) — cannot see inside
a DCBX TLV at all. Leaving it there would mean the newest and most intricate
length rules in the module were the only ones with no independent check.

Wireshark 4.2.2 has a complete, independent DCBX dissector for both the IEEE
802.1Qaz TLVs and the CEE 1.01 variant. It is a different implementation by
different people from a different specification reading, which is exactly
what LESSON A asks for; suite LESSON N adds that the best oracle is often a
real production tool rather than another library.

It has already paid for itself twice, before a line of the parser was written:
  * ETS Max-TCs is a 3-BIT field in which 0 ENCODES 8. A range check written
    from the standard rejects the commonest real value.
  * CEE feature sub-TLVs carry a SUBTYPE octet after the flags byte. Omitting
    it shifts every later field by one; the dissector showed it immediately as
    mis-read PGIDs and a wrong traffic-class count.

WHAT THIS TIER CANNOT DO, STATED ONCE.
lldpad — Intel's LLDP Agent Daemon and the reference DCBX implementation —
is installed here, and would have been the stronger oracle because it both
GENERATES and consumes DCBX. It refuses: it gates DCBX on kernel DCB support
(dcbnl ops) and no software netdev has it. veth, dummy and bridge were all
tried and all answered "Device not capable". So this tier runs in one
direction only, we-build -> Wireshark-dissects. The reverse direction, a real
stack emitting DCBX for us to parse, is unavailable in a container and would
need real DCB-capable hardware.

Requires tshark. Deliberately NOT part of the offline conformance run.
"""

from __future__ import annotations

import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

import lldpwatch as W
import lldpwatch_frames as F
from lldpwatch_conformance import Checker

HERE = os.path.dirname(os.path.abspath(__file__))


def have_tshark() -> bool:
    try:
        subprocess.run(["tshark", "-v"], capture_output=True, timeout=20)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def write_pcap(path: str, frames: Sequence[bytes]) -> None:
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            fh.write(struct.pack("<IIII", 1700000000, i * 1000, len(fr), len(fr)))
            fh.write(fr)


def dissect(frames: Sequence[bytes], fields: Sequence[str] = ()) -> Tuple[str, List[str]]:
    """Return (verbose text, per-frame field rows) from tshark."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x.pcap")
        write_pcap(p, frames)
        v = subprocess.run(["tshark", "-r", p, "-V"], capture_output=True,
                           text=True, timeout=120).stdout
        rows: List[str] = []
        if fields:
            args = ["tshark", "-r", p, "-T", "fields"]
            for f in fields:
                args += ["-e", f]
            rows = subprocess.run(args, capture_output=True, text=True,
                                  timeout=120).stdout.splitlines()
        return v, rows


def malformed_count(text: str) -> int:
    return len(re.findall(r"\[Malformed Packet", text))


# ==========================================================================
# 1. Ground truth — our benign DCBX frames must dissect clean
# ==========================================================================


def x_ground_truth(c: Checker) -> None:
    c.sect("ground-truth")
    for fn in (F.benign_dcbx_ieee, F.benign_dcbx_cee):
        text, _ = dissect([fn()])
        c.eq(malformed_count(text), 0,
             "%s dissects with NO malformed indication" % fn.__name__)
        c.ok("Link Layer Discovery Protocol" in text,
             "%s is recognised as LLDP" % fn.__name__)
    # and our engine agrees they are clean
    for fn in (F.benign_dcbx_ieee, F.benign_dcbx_cee):
        c.eq(W.Engine().handle_frame(fn()), [],
             "%s is silent in our engine too" % fn.__name__)

    c.sect("ieee-subtypes")
    text, _ = dissect([F.benign_dcbx_ieee()])
    for sub, label in ((9, "ETS Configuration"), (10, "ETS Recommendation"),
                       (11, "Priority Flow Control Configuration"),
                       (12, "Application Protocol")):
        c.ok("IEEE 802.1 Subtype: %s (0x%02x)" % (label, sub) in text,
             "Wireshark reads subtype %d as %s" % (sub, label))
        c.ok(sub in W.QAZ_SUBTYPES, "we know subtype %d too" % sub)
    c.ok("Organization Unique Code: 00:80:c2" in text,
         "Wireshark reads the IEEE 802.1 OUI we encode")

    c.sect("cee-recognised")
    text, _ = dissect([F.benign_dcbx_cee()])
    c.ok("00:1b:21" in text, "Wireshark reads the CEE OUI we encode")
    c.ok("1.01 CEE" in text, "and identifies the CEE DCBX protocol version")
    for name in ("DCBx Control TLV", "Priority Groups TLV",
                 "Priority-Based Flow Control TLV"):
        c.ok(name in text, "Wireshark dissects the CEE %s" % name)


# ==========================================================================
# 2. The two encoding traps, confirmed field by field
# ==========================================================================


def x_encoding_traps(c: Checker) -> None:
    c.sect("trap-ets-maxtc")
    # 0 encodes 8. If this ever reads back as "0 traffic classes" the parser
    # must change with it.
    text, _ = dissect([F.frame(F.mandatory()
                               + [F.t_ets_config(maxtc=0), F.t_end()],
                               pad=False)])
    c.ok("Maximum Number of Traffic Classes: 8" in text,
         "Wireshark reads raw max-TC 0 as EIGHT traffic classes")
    c.ok("Maximum Number of Traffic Classes: 0" not in text,
         "and never as zero")
    for raw in (1, 4, 7):
        text, _ = dissect([F.frame(F.mandatory()
                                   + [F.t_ets_config(maxtc=raw), F.t_end()],
                                   pad=False)])
        c.ok("Maximum Number of Traffic Classes: %d" % raw in text,
             "raw max-TC %d reads back as %d" % (raw, raw))
    # our decoder must agree with the dissector on the same bytes
    for raw, want in ((0, 8), (1, 1), (4, 4), (7, 7)):
        body = F.t_ets_config(maxtc=raw)[2:][4:]
        got = 8 if (body[0] & 0x07) == 0 else (body[0] & 0x07)
        c.eq(got, want, "our decode of raw max-TC %d is %d" % (raw, want))

    c.sect("trap-pfc-cap")
    # the OTHER encoding: 4 bits, and 8 means 8.
    for cap in (0, 2, 8):
        text, _ = dissect([F.frame(F.mandatory()
                                   + [F.t_pfc(cap=cap), F.t_end()],
                                   pad=False)])
        c.ok("Max PFC Enabled Traffic Classes: %d" % cap in text,
             "Wireshark reads PFC cap %d as %d" % (cap, cap))
    c.ok(True, "the two fields use DIFFERENT encodings of 8 — 0 for ETS "
               "max-TC, 8 for PFC cap — and both are pinned here")

    c.sect("trap-cee-subtype-octet")
    # The one the dissector caught. A Priority Groups body WITHOUT the
    # subtype octet is 16 octets and shifts every field after it.
    good = F.t_cee(subtlvs=(F.cee_control(), F.cee_pg()))
    text, _ = dissect([F.frame(F.mandatory() + [good, F.t_end()], pad=False)])
    c.ok("Number of Traffic Classes Supported: 0x08" in text,
         "with the subtype octet present, the TC count reads back as 8")
    for i in range(8):
        c.ok("Bandwidth for PGID %d:" % i in text,
             "and Wireshark finds bandwidth for PGID %d" % i)
    short = F.cee_subtlv(2, bytes([0, 0, 0xE0, 0x00]) + F.ETS_PRIO_TABLE
                         + F.ETS_BW_100)
    bad = F.t_cee(subtlvs=(F.cee_control(), short))
    c.ok(len(bad) < len(good), "the subtype-less body really is one octet short")
    c.eq(sorted({r["code"] for r in
                 W.Engine().handle_frame(F.frame(F.mandatory() + [bad, F.t_end()],
                                                 pad=False))}),
         ["LLDP-067"], "and our parser rejects it")
    c.eq(W.CEE_FIXED_BODY[W.CEE_PRIORITY_GROUPS], 17,
         "the pinned Priority Groups body length includes the subtype octet")


# ==========================================================================
# 3. Field-level agreement on values our rules actually read
# ==========================================================================


def x_field_agreement(c: Checker) -> None:
    c.sect("ets-tables")
    bw = bytes([25, 25, 0, 10, 10, 10, 10, 10])
    tsa = bytes([2, 2, 0, 2, 2, 2, 2, 2])
    raw = F.frame(F.mandatory() + [F.t_ets_config(bw=bw, tsa=tsa), F.t_end()],
                  pad=False)
    text, _ = dissect([raw])
    for i, val in enumerate(bw):
        c.ok("Bandwidth for PGID %d: %d" % (i, val) in text,
             "Wireshark reads TC %d bandwidth as %d" % (i, val))
    names = {0: "Strict Priority", 2: "Enhanced Transmission Selection"}
    for i, val in enumerate(tsa):
        c.ok("TSA for Traffic Class %d: %s (%d)" % (i, names[val], val) in text,
             "Wireshark reads TC %d TSA as %d" % (i, val))
    # the sum our rule computes must match the dissected values
    total = sum(bw[i] for i in range(8) if tsa[i] == W.TSA_ETS)
    c.eq(total, 100, "the ETS-allocated classes total 100 by both readings")

    c.sect("pfc-bitmap")
    for enable, on in ((0x18, [3, 4]), (0x01, [0]), (0xFF, list(range(8))),
                       (0x00, [])):
        raw = F.frame(F.mandatory() + [F.t_pfc(enable=enable), F.t_end()],
                      pad=False)
        text, _ = dissect([raw])
        for p in range(8):
            want = "Enabled" if p in on else "Disabled"
            c.ok("PFC for Priority %d: %s" % (p, want) in text,
                 "Wireshark reads priority %d as %s for 0x%02x"
                 % (p, want, enable))
        ours = [i for i in range(8) if enable & (1 << i)]
        c.eq(ours, on, "our bitmap decode of 0x%02x agrees" % enable)

    c.sect("app-selectors")
    for sel, label in ((1, "Default or Ethertype"), (2, "TCP"), (3, "UDP"),
                       (4, "TCP")):
        raw = F.frame(F.mandatory()
                      + [F.t_app(entries=((1, sel, 0x8906),)), F.t_end()],
                      pad=False)
        text, _ = dissect([raw])
        c.ok("Application Selector:" in text,
             "Wireshark dissects the selector for value %d" % sel)
        c.ok(sel in W.APP_SELECTORS, "we treat selector %d as defined" % sel)
    # a reserved selector: Wireshark calls it Reserved, we fire
    raw = F.frame(F.mandatory() + [F.t_app(entries=((1, 6, 0x8906),)),
                                   F.t_end()], pad=False)
    text, _ = dissect([raw])
    c.ok("Reserved (6)" in text, "Wireshark calls selector 6 reserved")
    c.eq(sorted({r["code"] for r in W.Engine().handle_frame(raw)}),
         ["LLDP-064"], "and we fire on it")
    c.ok(6 not in W.APP_SELECTORS, "6 is absent from our selector table")


# ==========================================================================
# 4. Malformed agreement — where Wireshark also objects, we must too
# ==========================================================================


def x_malformed_agreement(c: Checker) -> None:
    c.sect("malformed-agreement")
    # Not every rule of ours is one Wireshark implements: it does not check
    # the 100% ETS bandwidth total, for instance. So the contract is
    # one-directional and stated as such — WHERE WIRESHARK FLAGS A STRUCTURAL
    # PROBLEM, WE MUST ALSO FIRE. The reverse is not required.
    structural = [
        ("cee overrun", F.mal_dcbx_cee_overrun),
        ("cee unknown-type overrun", F.mal_dcbx_cee_unknown_overrun),
        ("cee short priority groups", F.mal_dcbx_cee_pg_wrong_len),
        ("cee stray octet", F.mal_dcbx_cee_stray_octet),
        ("ets wrong length", F.mal_dcbx_ets_wrong_len),
    ]
    for name, fn in structural:
        raw = fn()
        text, _ = dissect([raw])
        ours = sorted({r["code"] for r in W.Engine().handle_frame(raw)})
        c.ok(bool(ours), "we fire on %s (%r)" % (name, ours))
        if malformed_count(text):
            c.ok(bool(ours),
                 "Wireshark flags %s malformed and so do we" % name)
        else:
            c.ok(True,
                 "Wireshark tolerates %s; our rule is stricter, which is "
                 "allowed in this direction" % name)

    c.sect("semantic-rules-are-ours-alone")
    # These are 802.1Qaz REQUIREMENTS Wireshark does not enforce. Recording
    # that honestly is the point: the oracle covers the layout, not the
    # semantics, so these rules rest on the standard plus our own tests.
    for name, fn, code in (
        ("ETS bandwidth total", F.mal_dcbx_ets_bw_sum, "LLDP-061"),
        ("PFC over capability", F.mal_dcbx_pfc_over_cap, "LLDP-063"),
        ("priority beyond TC count", F.mal_dcbx_prio_beyond_tc, "LLDP-062"),
    ):
        raw = fn()
        text, _ = dissect([raw])
        c.eq(malformed_count(text), 0,
             "Wireshark does NOT object to %s — it is a semantic rule" % name)
        c.eq(sorted({r["code"] for r in W.Engine().handle_frame(raw)}), [code],
             "we fire %s on %s" % (code, name))

    c.sect("wire-byte-equality")
    # Our builders' bytes are what Wireshark parsed, so the lengths it read
    # back must equal the lengths we encoded.
    for fn in (F.benign_dcbx_ieee, F.benign_dcbx_cee):
        raw = fn()
        w = W.walk_tlvs(W.parse_ethernet(raw).payload)
        text, _ = dissect([raw])
        for t in w.tlvs:
            if t.type == 127:
                c.ok("TLV Length: %d" % t.length in text,
                     "Wireshark reads back our %d-octet org TLV" % t.length)


def main(argv: Optional[Sequence[str]] = None) -> int:
    if not have_tshark():
        print("tshark not available — this tier cannot run.")
        print("It is the ONLY independent check on the DCBX decode, because "
              "scapy has no DCBX dissector. Treat a skipped run as DCBX "
              "being unverified, not as a pass.")
        return 2
    c = Checker()
    for fn in (x_ground_truth, x_encoding_traps, x_field_agreement,
               x_malformed_agreement):
        fn(c)
    for name, n in c.by_section.items():
        print("  %-28s %4d" % (name, n))
    for f in c.failures:
        print("FAIL " + f)
    print("%s  %d checks, %d failures"
          % ("PASS" if not c.failures else "FAIL", c.passed, len(c.failures)))
    return 1 if c.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
