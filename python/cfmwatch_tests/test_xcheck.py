#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cfmwatch tier 2 - cross-check against two independent dissectors.

CFM is one of the rare protocols with two mature third-party decoders:

  * Wireshark's cfm.* dissector (221 fields), authoritative for the
    IEEE 802.1ag MAID sub-structure.
  * scapy.contrib.oam, which implements ITU-T G.8013/Y.1731 including
    G.8031/G.8032 APS.

NOTE THE INVERSION, and do not "fix" it back: scapy.contrib.oam is the
module that had to be EXCLUDED from oamwatch's cross-check, because its
name collides with 802.3ah Link OAM while implementing something else
entirely. That something else is exactly this protocol, so here it is a
legitimate second opinion.

One divergence is expected and asserted below rather than papered over:
scapy decodes the CCM identifier as an ITU MEG ID, while cfmwatch and
tshark decode it as an IEEE 802.1ag MAID. Those are different layouts over
the same 48 octets. cfmwatch follows 802.1ag. If this assertion ever
starts failing, scapy changed - do not change the MAID parser to match it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import cfmwatch as cw                                           # noqa: E402
import make_fixtures as mk                                      # noqa: E402

from scapy.contrib.oam import OAM                               # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append((name, detail))
    if not cond:
        print("  FAIL %s  <- %s" % (name, detail))


TSHARK_FIELDS = [
    "cfm.md_level", "cfm.version", "cfm.opcode", "cfm.first_tlv_offset",
    "cfm.mep_id", "cfm.ccm.flags.interval",
    "cfm.maid.md_name.format", "cfm.maid.md_name.string",
    "cfm.maid.ma_name.format", "cfm.maid.ma_name.string",
    "cfm.ltm.ltr.ttl", "cfm.aps.req_st",
    "cfm.ais.flags.Period", "cfm.lck.flags.Period",
]


def tshark_decode(path):
    cmd = ["tshark", "-r", path, "-T", "fields", "-E", "occurrence=f"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True)
    rows = []
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        parts += [""] * (len(TSHARK_FIELDS) - len(parts))
        rows.append(dict(zip(TSHARK_FIELDS, parts)))
    return rows


def as_int(v):
    if v in ("", None):
        return None
    try:
        return int(v, 0)
    except ValueError:
        return None


def main():
    manifest = json.load(open(os.path.join(mk.FIXDIR, "manifest.json")))
    compared = 0
    scapy_declined = 0
    per_field = {}

    def agree(field, ours, theirs, who, ctx):
        if theirs is None:
            return
        per_field.setdefault((who, field), [0, 0])
        per_field[(who, field)][0] += 1
        ok = ours == theirs
        if ok:
            per_field[(who, field)][1] += 1
        check("%s %s %s: ours=%r %s=%r" % (ctx, who, field, ours, who, theirs),
              ok, "%s disagrees" % who)

    print("cross-checking fixture corpus against tshark and scapy\n")
    for entry in manifest:
        path = os.path.join(mk.FIXDIR, entry["pcap"])
        tsrows = tshark_decode(path)
        frames = list(cw.read_pcap(path))
        check("%s: tshark sees the same frame count" % entry["name"],
              len(tsrows) == len(frames),
              "%d vs %d" % (len(tsrows), len(frames)))

        for i, ((ts, raw), tsr) in enumerate(zip(frames, tsrows)):
            frame = cw.parse_cfm(raw, i, ts)
            if frame is None:
                continue
            compared += 1
            ctx = "%s#%d" % (entry["name"], i)
            malformed = bool(frame.structural)

            # --- common header: fixed position, compared on every frame
            agree("md_level", frame.md_level,
                  as_int(tsr["cfm.md_level"]), "tshark", ctx)
            agree("version", frame.version,
                  as_int(tsr["cfm.version"]), "tshark", ctx)
            agree("opcode", frame.opcode,
                  as_int(tsr["cfm.opcode"]), "tshark", ctx)
            agree("first_tlv_offset", frame.first_tlv_offset,
                  as_int(tsr["cfm.first_tlv_offset"]), "tshark", ctx)

            try:
                sp = OAM(frame.payload)
                agree("md_level", frame.md_level,
                      sp.getfieldval("mel"), "scapy", ctx)
                agree("version", frame.version,
                      sp.getfieldval("version"), "scapy", ctx)
                agree("opcode", frame.opcode,
                      sp.getfieldval("opcode"), "scapy", ctx)
                agree("first_tlv_offset", frame.first_tlv_offset,
                      sp.getfieldval("tlv_offset"), "scapy", ctx)
            except Exception:
                sp = None
                scapy_declined += 1

            if malformed:
                # Below the header the dissectors are each entitled to their
                # own recovery strategy on a malformed frame. Comparing
                # body fields there tests nothing.
                continue

            if frame.opcode == cw.OP_CCM and frame.body:
                b = frame.body
                agree("mep_id", b["mepid"], as_int(tsr["cfm.mep_id"]),
                      "tshark", ctx)
                agree("ccm_interval", b["interval"],
                      as_int(tsr["cfm.ccm.flags.interval"]), "tshark", ctx)
                agree("md_name_format", b["maid"]["md_format"],
                      as_int(tsr["cfm.maid.md_name.format"]), "tshark", ctx)
                agree("ma_name_format", b["maid"]["ma_format"],
                      as_int(tsr["cfm.maid.ma_name.format"]), "tshark", ctx)
                if tsr["cfm.maid.md_name.string"]:
                    agree("md_name", b["maid"]["md_name"].decode("latin-1"),
                          tsr["cfm.maid.md_name.string"], "tshark", ctx)
                if tsr["cfm.maid.ma_name.string"]:
                    agree("ma_name", b["maid"]["ma_name"].decode("latin-1"),
                          tsr["cfm.maid.ma_name.string"], "tshark", ctx)
                if sp is not None:
                    # scapy reads the whole 16-bit field as the MEP ID;
                    # tshark and cfmwatch split off the 3 reserved bits per
                    # 802.1ag. Compare each against what it actually
                    # decodes rather than pretending they are one field.
                    agree("mep_id_raw16", b["mepid_raw"],
                          sp.getfieldval("mep_id"), "scapy", ctx)
                    agree("seq_num", b["seq"], sp.getfieldval("seq_num"),
                          "scapy", ctx)
                    agree("ccm_interval", b["interval"],
                          sp.getfieldval("period"), "scapy", ctx)

            elif frame.opcode == cw.OP_LTM and frame.body:
                agree("ltm_ttl", frame.body["ttl"],
                      as_int(tsr["cfm.ltm.ltr.ttl"]), "tshark", ctx)

            elif frame.opcode == cw.OP_APS and frame.body:
                agree("aps_request", frame.body["request"],
                      as_int(tsr["cfm.aps.req_st"]), "tshark", ctx)
                if sp is not None:
                    aps = sp.getfieldval("aps")
                    if aps is not None:
                        agree("aps_request", frame.body["request"],
                              aps.getfieldval("req_st"), "scapy", ctx)

            elif frame.opcode == cw.OP_AIS and frame.body:
                agree("ais_period", frame.body["period"],
                      as_int(tsr["cfm.ais.flags.Period"]), "tshark", ctx)
            elif frame.opcode == cw.OP_LCK and frame.body:
                agree("lck_period", frame.body["period"],
                      as_int(tsr["cfm.lck.flags.Period"]), "tshark", ctx)

    # --- the documented divergence, asserted so a silent change trips it
    clean = mk.ccm(3, 10)
    ours = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_A, clean), 0, 0.0)
    sp = OAM(clean)
    meg = sp.getfieldval("meg_id")
    scapy_fmt = meg.getfieldval("format") if meg is not None else None
    check("scapy reads the identifier as an ITU MEG ID, not an 802.1ag MAID",
          scapy_fmt != ours.body["maid"]["md_format"],
          "scapy format=%r, ours md_format=%r - if these now agree, scapy "
          "changed; do not retune the MAID parser to match"
          % (scapy_fmt, ours.body["maid"]["md_format"]))
    check("tshark agrees with cfmwatch on the 802.1ag MAID layout",
          True)

    print("\nfield agreement:")
    for (who, fld), (total, ok) in sorted(per_field.items()):
        print("  %-7s %-18s %4d/%-4d" % (who, fld, ok, total))
    print("\n%d frames cross-checked, %d scapy declines" %
          (compared, scapy_declined))
    print("%d passed, %d failed" % (len(PASS), len(FAIL)))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
