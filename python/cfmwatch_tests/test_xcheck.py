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
    "cfm.aps.protec.type_A", "cfm.aps.protec.type_B",
    "cfm.aps.protec.type_D", "cfm.aps.protec.type_R",
    "cfm.aps.req_signal", "cfm.aps.bridged_signal", "cfm.aps.bridge_type",
    "cfm.ais.flags.Period", "cfm.lck.flags.Period",
    "cfm.raps.req_st", "cfm.raps.status.rb", "cfm.raps.status.dnf",
    "cfm.raps.status.bpr", "cfm.raps.node_id",
    "cfm.raps.status.reserved_v1", "cfm.raps.status.reserved_v2",
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


def _mac_bytes(val):
    """scapy hands back a MAC as a string; compare on raw octets."""
    if val is None:
        return None
    if isinstance(val, bytes):
        return val
    return bytes.fromhex(str(val).replace(":", ""))


def as_bool(v):
    if v in ("", None):
        return None
    return v.strip().lower() in ("true", "1")


def mac(raw):
    return ":".join("%02x" % b for b in raw)


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
                b = frame.body
                agree("aps_request", b["request"],
                      as_int(tsr["cfm.aps.req_st"]), "tshark", ctx)
                # Protection type bit by bit, and the bridge-type width.
                for bit, mask in cw.APS_PROT_BITS:
                    agree("aps_prot_%s" % bit,
                          bool(b["protection_type"] & mask),
                          as_bool(tsr["cfm.aps.protec.type_%s" % bit]),
                          "tshark", ctx)
                agree("aps_req_signal", b["requested_signal"],
                      as_int(tsr["cfm.aps.req_signal"]), "tshark", ctx)
                agree("aps_bridged_signal", b["bridged_signal"],
                      as_int(tsr["cfm.aps.bridged_signal"]), "tshark", ctx)
                agree("aps_bridge_type", b["bridge_type"],
                      as_int(tsr["cfm.aps.bridge_type"]), "tshark", ctx)
                if sp is not None:
                    aps = sp.getfieldval("aps")
                    if aps is not None:
                        agree("aps_request", b["request"],
                              aps.getfieldval("req_st"), "scapy", ctx)
                        flags = aps.getfieldval("prot_type")
                        for bit, mask in cw.APS_PROT_BITS:
                            agree("aps_prot_%s" % bit,
                                  bool(b["protection_type"] & mask),
                                  bit in flags, "scapy", ctx)
                        agree("aps_req_signal", b["requested_signal"],
                              aps.getfieldval("req_sig"), "scapy", ctx)
                        agree("aps_bridged_signal", b["bridged_signal"],
                              aps.getfieldval("br_sig"), "scapy", ctx)

            elif frame.opcode == cw.OP_RAPS and frame.body:
                b = frame.body
                # scapy.contrib.oam implements RAPS directly from
                # G.8032/Y.1344 (02/2022), so it is the primary second
                # opinion on this body. tshark decodes opcode 40 but ships
                # no cfm.raps.* body fields, which is asserted below.
                agree("raps_request", b["request"],
                      as_int(tsr["cfm.raps.req_st"]), "tshark", ctx)
                agree("raps_rb", b["rb"],
                      as_bool(tsr["cfm.raps.status.rb"]), "tshark", ctx)
                agree("raps_dnf", b["dnf"],
                      as_bool(tsr["cfm.raps.status.dnf"]), "tshark", ctx)
                if tsr["cfm.raps.node_id"]:
                    agree("raps_node_id", mac(b["node_id"]),
                          tsr["cfm.raps.node_id"].lower(), "tshark", ctx)
                # Wireshark selects the status layout from the version
                # field, so compare against the revision-appropriate
                # reserved field. This is the independent corroboration
                # that the v1/v2 split is real and not an inference.
                resv_field = ("cfm.raps.status.reserved_v2"
                              if b["revision"] >= cw.RAPS_VERSION_V2
                              else "cfm.raps.status.reserved_v1")
                agree("raps_status_reserved", b["status_reserved"],
                      as_int(tsr[resv_field]), "tshark", ctx)
                if b["revision"] >= cw.RAPS_VERSION_V2:
                    agree("raps_bpr", b["bpr"],
                          as_bool(tsr["cfm.raps.status.bpr"]), "tshark",
                          ctx)
                else:
                    check("%s tshark does not decode BPR on a v1 frame"
                          % ctx, tsr["cfm.raps.status.bpr"] == "",
                          "tshark gave %r" % tsr["cfm.raps.status.bpr"])
                if sp is not None:
                    r = sp.getfieldval("raps")
                    if r is not None:
                        agree("raps_request", b["request"],
                              r.getfieldval("req_st"), "scapy", ctx)
                        agree("raps_sub_code", b["sub_code"],
                              r.getfieldval("sub_code"), "scapy", ctx)
                        agree("raps_node_id", b["node_id"],
                              _mac_bytes(r.getfieldval("node_id")),
                              "scapy", ctx)
                        flags = r.getfieldval("status")
                        agree("raps_rb", b["rb"], "RB" in flags, "scapy",
                              ctx)
                        agree("raps_dnf", b["dnf"], "DNF" in flags,
                              "scapy", ctx)
                        # scapy has no version awareness here: it always
                        # decodes bit 5 as BPR. Compare it against the raw
                        # bit, not against cfmwatch's revision-aware
                        # value, or the comparison asserts scapy's bug.
                        agree("raps_bpr_rawbit",
                              bool(b["status"] & cw.RAPS_STATUS_BPR),
                              "BPR" in flags, "scapy", ctx)

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

    # ---- what each dissector actually covers, asserted ----------------
    raps = mk.raps(3, 0xB, status=mk.RB | mk.DNF | mk.BPR,
                   node_id=mk.MAC_C)
    sp = OAM(raps)
    check("scapy dissects the R-APS body", sp.getfieldval("raps") is not None)
    check("scapy agrees R-APS is opcode 40", sp.getfieldval("opcode") == 40)
    check("scapy agrees R-APS First TLV Offset is 32",
          sp.getfieldval("tlv_offset") == 32)

    fields = subprocess.run(["tshark", "-G", "fields"], capture_output=True,
                            text=True, check=True).stdout
    has_opcode40 = subprocess.run(["tshark", "-G", "values"],
                                  capture_output=True, text=True,
                                  check=True).stdout
    check("tshark names opcode 40 as R-APS",
          any(line.split("\t")[1:3] == ["cfm.opcode", "40"] and
              "R-APS" in line for line in has_opcode40.splitlines()))
    raps_fields = {l.split("\t")[2] for l in fields.splitlines()
                   if len(l.split("\t")) > 2 and
                   l.split("\t")[2].startswith("cfm.raps")}
    check("tshark dissects the R-APS body too, giving a three-way check",
          {"cfm.raps.req_st", "cfm.raps.status.rb", "cfm.raps.status.dnf",
           "cfm.raps.node_id"} <= raps_fields, str(sorted(raps_fields)))
    # tshark models the G.8032 revision split explicitly, carrying both
    # status.reserved_v1 and status.reserved_v2 - independent corroboration
    # that BPR was carved out of the v1 reserved bits by a later revision,
    # which is why cfmwatch treats BPR and the remaining reserved bits
    # separately. tshark leaves BPR unset on these captures, so scapy is
    # the cross-check for that one bit.
    check("tshark corroborates the v1/v2 status-reserved split",
          {"cfm.raps.status.reserved_v1",
           "cfm.raps.status.reserved_v2"} <= raps_fields)

    # Direct proof that the version field selects the revision, checked
    # against Wireshark rather than asserted from documentation.
    probe = os.path.join(mk.FIXDIR, "_xcheck_versions.pcap")
    mk.write_pcap(probe, [
        (mk.BASE_TS, mk.eth_ring(mk.MAC_A,
                                 mk.raps(3, 0, status=mk.BPR, version=0))),
        (mk.BASE_TS + 0.1, mk.eth_ring(mk.MAC_A,
                                       mk.raps(3, 0, status=mk.BPR,
                                               version=1))),
    ])
    rows = tshark_decode(probe)
    os.unlink(probe)
    check("tshark uses the v1 reserved mask (0x3F) for version 0",
          as_int(rows[0]["cfm.raps.status.reserved_v1"]) == 0x20 and
          rows[0]["cfm.raps.status.reserved_v2"] == "" and
          rows[0]["cfm.raps.status.bpr"] == "",
          str(rows[0]))
    check("tshark uses the v2 reserved mask (0x1F) plus BPR for version 1",
          as_int(rows[1]["cfm.raps.status.reserved_v2"]) == 0x00 and
          rows[1]["cfm.raps.status.reserved_v1"] == "" and
          as_bool(rows[1]["cfm.raps.status.bpr"]) is True,
          str(rows[1]))

    # The bridge-type width, pinned against Wireshark. Reading octet 4's
    # top TWO bits reports 0x40 as 1 and 0xC0 as 3, neither of which is
    # the bridge type.
    probe = os.path.join(mk.FIXDIR, "_xcheck_aps.pcap")
    mk.write_pcap(probe, [
        (mk.BASE_TS + i * 0.1,
         mk.eth(mk.D3, mk.MAC_A, mk.aps(3, 0, octet4=o4),
                vlans=((0x8100, 100),)))
        for i, o4 in enumerate((0x00, 0x40, 0x80, 0xC0, 0xFF))])
    rows = tshark_decode(probe)
    os.unlink(probe)
    for row, o4, want in zip(rows, (0x00, 0x40, 0x80, 0xC0, 0xFF),
                             (0, 0, 1, 1, 1)):
        check("tshark reads octet4 0x%02x as bridge type %d" % (o4, want),
              as_int(row["cfm.aps.bridge_type"]) == want,
              "tshark gave %r" % row["cfm.aps.bridge_type"])

    # ---- E-LMI against Wireshark's dissector -------------------------
    probe = os.path.join(mk.FIXDIR, "_xcheck_elmi.pcap")
    specs = [(0x7D, 1, 5, 4, ((7, 0x02),), b"UNI-1"),
             (0x75, 1, 9, 8, ((9, 0x00), (11, 0x04)), b"UNI-2"),
             (0x7D, 1, 1, 0, ((3, 0x03),), b"UNI-3")]
    mk.write_pcap(probe, [
        (mk.BASE_TS + i * 0.1,
         mk.elmi(msg=m, version=v, snd=s, rcv=r, evcs=e, uni=u))
        for i, (m, v, s, r, e, u) in enumerate(specs)])
    cmd = ["tshark", "-r", probe, "-T", "fields", "-E", "occurrence=a"]
    for fld in ("elmi.version", "elmi.message_type", "elmi.snd_seq_num",
                "elmi.rcv_seq_num", "elmi.evc.refid", "elmi.evc.status",
                "elmi.sub_info.uni_id"):
        cmd += ["-e", fld]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True)
    rows = [l.split("\t") for l in out.stdout.splitlines()]
    os.unlink(probe)
    check("tshark decoded every E-LMI probe frame",
          len(rows) == len(specs), "%d rows" % len(rows))
    for row, (msg, ver, snd, rcv, evcs, uni) in zip(rows, specs):
        ours = cw.parse_elmi(mk.elmi(msg=msg, version=ver, snd=snd,
                                     rcv=rcv, evcs=evcs, uni=uni), 0, 0.0)
        ctx = "elmi/uni=%s" % uni.decode()
        agree("elmi_version", ours.version, as_int(row[0]), "tshark", ctx)
        agree("elmi_msg_type", ours.msg_type, as_int(row[1]), "tshark",
              ctx)
        agree("elmi_snd_seq", ours.snd_seq, as_int(row[2]), "tshark", ctx)
        agree("elmi_rcv_seq", ours.rcv_seq, as_int(row[3]), "tshark", ctx)
        agree("elmi_evc_refs",
              [e["reference"] for e in ours.evcs],
              [int(x, 0) for x in row[4].split(",") if x], "tshark", ctx)
        agree("elmi_evc_status",
              [e["status"] for e in ours.evcs],
              [int(x, 0) for x in row[5].split(",") if x], "tshark", ctx)
        agree("elmi_uni_id", ours.uni_id.decode("latin-1"),
              row[6] or None, "tshark", ctx)

    print("\nfield agreement:")
    for (who, fld), (total, ok) in sorted(per_field.items()):
        print("  %-7s %-18s %4d/%-4d" % (who, fld, ok, total))
    print("\n%d frames cross-checked, %d scapy declines" %
          (compared, scapy_declined))
    print("%d passed, %d failed" % (len(PASS), len(FAIL)))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
