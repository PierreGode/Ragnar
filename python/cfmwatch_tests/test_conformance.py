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

RING_ARGS = mk.RING_DECL

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
print("\n[2b] R-APS parser units and ring declaration")

# Body layout, asserted against the figures in the ITU-T G.8032 liaison
# overview and scapy's G.8032/Y.1344 (02/2022) implementation.
raw = mk.eth_ring(mk.MAC_A, mk.raps(3, 0xB, status=mk.RB | mk.DNF,
                                    node_id=mk.MAC_B))
frame = cw.parse_cfm(raw, 0, 0.0)
check("R-APS parses at opcode 40",
      frame is not None and frame.opcode == cw.OP_RAPS)
check("R-APS request/state decodes", frame.body["request"] == cw.RAPS_SF)
check("R-APS RB decodes", frame.body["rb"] is True)
check("R-APS DNF decodes", frame.body["dnf"] is True)
check("R-APS BPR decodes false when clear", frame.body["bpr"] is False)
check("R-APS Node ID decodes", frame.body["node_id"] == mk.MAC_B)
check("R-APS body is 32 octets per spec",
      cw.OPCODE_MIN_BODY[cw.OP_RAPS] == cw.RAPS_BODY_LEN == 32 and
      cw.OPCODE_FTO[cw.OP_RAPS] == 32)
check("conforming R-APS raises no structural defect",
      not cw.parse_cfm(mk.eth_ring(mk.MAC_A, mk.raps(3, 0)), 0,
                       0.0).structural)
check("R-APS First TLV Offset 32 agrees with the opcode table",
      not any(c == "CFM-010" for c, _ in frame.structural),
      str(frame.structural))
check("sub-code splits from request/state",
      cw.parse_cfm(mk.eth_ring(mk.MAC_A, mk.raps(3, 0xE, sub_code=0)), 0,
                   0.0).body["sub_code"] == 0)
check("reserved request/state values are the complement of the named set",
      cw.RAPS_RESERVED_REQUESTS ==
      frozenset(set(range(16)) - set(cw.RAPS_REQUEST_NAMES)))
check("G.8032 named requests are NR/MS/SF/FS/Event",
      sorted(cw.RAPS_REQUEST_NAMES.values()) ==
      ["Event", "FS", "MS", "NR", "SF"])
# Body truncation on R-APS is detectable only when the frame is NOT
# padded to the Ethernet minimum. CFM's common header carries no body
# length, and a 32-octet R-APS body fits inside a 60-octet frame, so a
# truncated R-APS padded with zeros is byte-identical to a conforming one
# whose fields are all zero. CCM escapes this because its 70-octet body
# exceeds the padded minimum. Asserted in both directions so the limit is
# pinned rather than discovered later as a surprise.
short = cw.struct.pack("!BBBB", 0x60, 40, 0, 32) + b"\x00" * 8
unpadded = cw.parse_cfm(mk.eth(mk.cfm_group(3), mk.MAC_A, short,
                               vlans=mk.RING_VLAN, minlen=0), 0, 0.0)
check("unpadded truncated R-APS raises CFM-006",
      not unpadded.body and
      any(c == "CFM-006" for c, _ in unpadded.structural),
      str(unpadded.structural))
padded = cw.parse_cfm(mk.eth_ring(mk.MAC_A, short), 0, 0.0)
check("padded truncated R-APS is indistinguishable from an all-zero body "
      "(documented limit, not a defect)",
      bool(padded.body) and not padded.structural,
      str(padded.structural))

# ---- Y.1731 measurement, maintenance, and the opcode table --------------
check("RFM, SFM and GNM are named, not reported as unassigned",
      all(o in cw.OPCODE_NAMES for o in (cw.OP_RFM, cw.OP_SFM, cw.OP_GNM)))
check("GNM is in the Y.1731 overlay set and RFM/SFM are not",
      cw.OP_GNM in cw.Y1731_OPCODES and
      cw.OP_RFM not in cw.Y1731_OPCODES and
      cw.OP_SFM not in cw.Y1731_OPCODES,
      "opcodes 0-31 are IEEE 802.1's range, 32-63 are ITU-T's")
for op, name in ((cw.OP_RFM, "RFM"), (cw.OP_SFM, "SFM"),
                 (cw.OP_GNM, "GNM")):
    fr = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_A,
                             mk.cfm(3, op, 0, 4, b"\x00\x00\x00\x01",
                                    mk.END), vlans=((0x8100, 100),)),
                      0, 0.0)
    check("%s raises no unassigned-opcode defect" % name,
          not any(c == "CFM-007" for c, _ in fr.structural),
          str(fr.structural))

# First TLV Offset is asserted only where the mandated value is
# established. Wireshark and scapy disagree for the OUI-bearing opcodes
# and GNM, so CFM-010 must stay silent there or it fires on every
# conforming frame.
for op in sorted(cw.OUI_OPCODES | {cw.OP_GNM}):
    check("no First TLV Offset is asserted for opcode %d" % op,
          op not in cw.OPCODE_FTO)
    body = (b"\x00\x11\x22\x07" if op in cw.OUI_OPCODES else b"\x01")
    for fto in (0, 4, 10, 13):
        fr = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_A,
                                 mk.cfm(3, op, 0, fto, body, mk.END),
                                 vlans=((0x8100, 100),)), 0, 0.0)
        check("opcode %d with offset %d raises no CFM-010" % (op, fto),
              not any(c == "CFM-010" for c, _ in fr.structural),
              str(fr.structural))
check("the established offsets are still enforced",
      any(c == "CFM-010" for c, _ in cw.parse_cfm(
          mk.eth(mk.D3, mk.MAC_A, mk.cfm(3, 43, 0, 99,
                                         b"\x00" * 12, mk.END),
                 vlans=((0x8100, 100),)), 0, 0.0).structural))
check("OUI-bearing opcodes require 4 body octets",
      all(cw.OPCODE_MIN_BODY[o] == 4 for o in cw.OUI_OPCODES))

# Delay timestamps: 4-octet seconds then 4-octet nanoseconds, stride 8.
# Four fill DMM/DMR's 32-octet body and two fill 1DM's 16, which is what
# fixes the stride at 8 rather than the 10 a 48-bit seconds field needs.
dmr = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_A,
                          mk.dm(3, 46, (0x11111110, 200000000),
                                (0x11111111, 200000001),
                                (0x11111112, 200000002),
                                (0x11111113, 200000003)),
                          vlans=((0x8100, 100),)), 0, 0.0)
st = dmr.body["timestamps"]
check("DMR carries four timestamps", len(st) == 4)
check("timestamp seconds and nanoseconds split at 4 octets each",
      st["TxTimeStampf"]["seconds"] == 0x11111110 and
      st["TxTimeStampf"]["nanos"] == 200000000 and
      st["RxTimeStampb"]["seconds"] == 0x11111113,
      str({k: (v["seconds"], v["nanos"]) for k, v in st.items()}))
odm = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_A,
                          mk.dm(3, 45, (5, 0), (6, 0)),
                          vlans=((0x8100, 100),)), 0, 0.0)
check("1DM carries two timestamps", len(odm.body["timestamps"]) == 2)

slm = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_A,
                          mk.sl(3, 55, 10, 0xDEADBEEF, 1000),
                          vlans=((0x8100, 100),)), 0, 0.0)
check("SLM decodes source MEP, test ID and TxFCf",
      slm.body["src_mep_id"] == 10 and
      slm.body["test_id"] == 0xDEADBEEF and
      slm.body["tx_fcf"] == 1000)
check("SLM leaves the SLR-only fields unread",
      slm.body["rsp_mep_id"] is None and slm.body["tx_fcb"] is None,
      "those octets are reserved in an SLM")
slr = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_A,
                          mk.sl(3, 54, 10, 0xDEADBEEF, 1000, rsp_mep=20,
                                txfcb=7), vlans=((0x8100, 100),)), 0, 0.0)
check("SLR decodes the responder MEP and TxFCb",
      slr.body["rsp_mep_id"] == 20 and slr.body["tx_fcb"] == 7)

# ---- E-LMI (MEF 16) ---------------------------------------------------
# Layout confirmed by probing Wireshark's E-LMI dissector: UNI Status
# carries a map-type octet then sub-IEs, and EVC Status carries a 2-octet
# reference, a status octet, then sub-IEs.
el = cw.parse_elmi(mk.elmi(snd=5, rcv=4, evcs=((7, 0x02), (9, 0x04))),
                   0, 0.0)
check("E-LMI parses at EtherType 0x88EE", el is not None)
check("E-LMI version and message type decode",
      el.version == 1 and el.msg_type == cw.ELMI_MSG_STATUS)
check("E-LMI sequence numbers decode",
      el.snd_seq == 5 and el.rcv_seq == 4)
check("E-LMI UNI identifier decodes from its sub-element",
      el.uni_id == b"UNI-1", str(el.uni_id))
check("E-LMI decodes both EVC status elements",
      [(e["reference"], e["status"]) for e in el.evcs] ==
      [(7, 0x02), (9, 0x04)], str(el.evcs))
check("E-LMI names the EVC status values",
      el.evcs[0]["status_name"] == "Active" and
      el.evcs[1]["status_name"] == "Partially Active")
check("a conforming E-LMI frame raises no structural defect",
      not el.structural, str(el.structural))
check("a CFM frame is not mistaken for E-LMI",
      cw.parse_elmi(mk.eth(mk.D3, mk.MAC_A, mk.ccm(3, 10)), 0, 0.0) is None)
check("an E-LMI frame is not mistaken for CFM",
      cw.parse_cfm(mk.elmi(), 0, 0.0) is None)
for label, frame in (
        ("a bad protocol version", mk.elmi(version=3)),
        ("an unknown message type", mk.elmi(msg=0x11)),
        ("an undefined EVC status", mk.elmi(evcs=((7, 0x09),))),
        ("a destination outside the E-LMI group",
         mk.elmi(dst=mk.MAC_B))):
    check("E-LMI rejects %s" % label,
          bool(cw.parse_elmi(frame, 0, 0.0).structural))
ev = cw.parse_evc("7,vlan=500,name=cust-A")
check("--evc parses reference, VLAN and label",
      ev.reference == 7 and ev.vlan == (500,) and ev.name() == "cust-A")
check("--evc accepts untagged", cw.parse_evc("7,vlan=untagged").vlan == ())
for bad_spec, why in (("7", "a missing vlan"),
                      ("abc,vlan=500", "a non-numeric reference"),
                      ("7,vlan=9999", "a VLAN out of range"),
                      ("7,bogus=1", "an unknown option"),
                      ("99999,vlan=1", "a reference out of range"),
                      ("", "an empty specification")):
    try:
        cw.parse_evc(bad_spec)
        check("--evc rejects %s" % why, False, bad_spec)
    except ValueError:
        check("--evc rejects %s" % why, True)

# ---- EVPN-VXLAN -------------------------------------------------------
native = mk.eth(mk.D3, mk.MAC_A, mk.ccm(3, 10), vlans=((0x8100, 500),))
tun = mk.vxlan(native, vni=1000)
check("CFM inside VXLAN is NOT seen without decapsulation",
      cw.parse_cfm(tun, 0, 0.0, vxlan=False) is None,
      "this is the blind spot the support closes")
fr = cw.parse_cfm(tun, 0, 0.0)
check("CFM inside VXLAN is parsed", fr is not None and
      fr.opcode == cw.OP_CCM)
check("the VNI is recovered", fr.vni == 1000)
check("the inner VLAN is the customer's", fr.vlan_key == (500,))
check("the service key separates VNI from VLAN",
      fr.service_key == (1000, 500))
check("native traffic uses the no-VNI marker",
      cw.parse_cfm(native, 0, 0.0).service_key == (cw.NO_VNI, 500))
check("split_service round-trips a service key",
      cw.split_service(fr.service_key) == (1000, (500,)) and
      cw.split_service((cw.NO_VNI, 500)) == (None, (500,)))
# Malformed or non-VXLAN encapsulation must not be mistaken for a tunnel.
for label, raw in (
        ("a plain IPv4 UDP frame to another port",
         mk.vxlan(native).replace(struct.pack("!H", 4789),
                                  struct.pack("!H", 4790), 1)),
        ("a truncated tunnel", mk.vxlan(native)[:30]),
        ("an ARP frame", bytes.fromhex("ffffffffffff")
         + mk.MAC_A + struct.pack("!H", 0x0806) + b"\x00" * 40)):
    check("%s is not decapsulated" % label,
          cw.parse_cfm(raw, 0, 0.0) is None)
# EVPN-MPLS is deliberately NOT decapsulated.
mpls = (bytes.fromhex("001122330044") + mk.MAC_A
        + struct.pack("!H", 0x8847)
        + struct.pack("!I", (16 << 12) | (1 << 8) | 64)
        + struct.pack("!I", 0) + native)
check("EVPN-MPLS is not decapsulated, by decision",
      cw.parse_cfm(mpls, 0, 0.0) is None,
      "a label stack carries no payload type; see the README boundary")

# ---- the capture filter ----------------------------------------------
# Every EtherType the module parses must be in the filter, or the kernel
# drops it before userspace and the plane is silently invisible. That is
# how E-LMI was first added: parser yes, filter no.
check("both parsed EtherTypes are in the filter's watch list",
      set(cw.WATCHED_ETHERTYPES) == {cw.ETHERTYPE_CFM, cw.ETHERTYPE_ELMI})
for vx in (False, True):
    blob, length = cw._bpf_blob(vxlan=vx)
    check("the capture filter is well-formed with vxlan=%s" % vx,
          len(blob) == length * 8 and length > 0)
    prog = [struct.unpack_from("HBBI", blob, i * 8) for i in range(length)]
    for etype in cw.WATCHED_ETHERTYPES:
        check("filter tests EtherType 0x%04x at all three tag depths "
              "(vxlan=%s)" % (etype, vx),
              sum(1 for ins in prog
                  if ins[0] == cw.BPF_JMP_JEQ and ins[3] == etype) == 3)
    check("no backward jumps with vxlan=%s" % vx,
          all(i[1] >= 0 and i[2] >= 0 for i in prog))
check("enabling VXLAN adds the clause rather than replacing the filter",
      cw._bpf_blob(vxlan=True)[1] > cw._bpf_blob(vxlan=False)[1])

# The assembler is what keeps those offsets right, so prove it resolves
# labels and refuses an undefined one.
asm = cw._bpf_assemble([(cw.BPF_JMP_JA, 0, 0, "end"),
                        (cw.BPF_RET_K, 0, 0, 0),
                        "end",
                        (cw.BPF_RET_K, 0, 0, cw.BPF_ACCEPT)])
check("the BPF assembler resolves a forward label",
      asm[0] == (cw.BPF_JMP_JA, 0, 0, 1), str(asm[0]))
try:
    cw._bpf_assemble([(cw.BPF_JMP_JA, 0, 0, "nowhere")])
    check("the BPF assembler rejects an undefined label", False)
except KeyError:
    check("the BPF assembler rejects an undefined label", True)

# ---- G.8031 / ELPS linear APS -------------------------------------------
# Field widths confirmed empirically against Wireshark: the protection
# type bits are A=0x08, B=0x04, D=0x02, R=0x01, and the bridge type is the
# single top bit of the body's last octet with the rest reserved.
a = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_A, mk.aps(3, 0xB, ptype=0xF),
                        vlans=((0x8100, 100),)), 0, 0.0)
check("APS protection type decodes all four bits",
      a.body["protection_bits"] == "ABDR", a.body["protection_bits"])
for bit, mask in (("A", 0x08), ("B", 0x04), ("D", 0x02), ("R", 0x01)):
    one = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_A, mk.aps(3, 0, ptype=mask),
                              vlans=((0x8100, 100),)), 0, 0.0)
    check("APS protection bit %s is 0x%02x" % (bit, mask),
          one.body["protection_bits"] == bit,
          one.body["protection_bits"])
# Bridge type is ONE bit. Reading two would report 0x40 as 1 and 0xC0 as 3.
for octet4, want_bt, want_resv in ((0x00, 0, 0x00), (0x40, 0, 0x40),
                                   (0x80, 1, 0x00), (0xC0, 1, 0x40),
                                   (0xFF, 1, 0x7F)):
    b = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_A,
                            mk.aps(3, 0, octet4=octet4),
                            vlans=((0x8100, 100),)), 0, 0.0)
    check("APS octet4 0x%02x -> bridge_type %d, reserved 0x%02x"
          % (octet4, want_bt, want_resv),
          b.body["bridge_type"] == want_bt and
          b.body["octet4_reserved"] == want_resv,
          "got bt=%s resv=0x%02x" % (b.body["bridge_type"],
                                     b.body["octet4_reserved"]))
check("APS signal octets name null and normal",
      cw.APS_SIGNAL_NAMES[0] == "null" and cw.APS_SIGNAL_NAMES[1] == "normal")
check("APS request table matches G.8031",
      cw.APS_REQUEST_NAMES == {0: "NR", 1: "DNR", 2: "RR", 4: "EXER",
                               5: "WTR", 7: "MS", 9: "SD", 11: "SF",
                               13: "FS", 14: "SF-P", 15: "LO"},
      str(cw.APS_REQUEST_NAMES))
check("APS code 6 is deprecated, not reserved",
      6 in cw.APS_DEPRECATED_REQUESTS and
      6 not in cw.APS_RESERVED_REQUESTS)
check("APS reserved codes are 3, 8, 10 and 12",
      cw.APS_RESERVED_REQUESTS == frozenset({3, 8, 10, 12}))
check("G.8031 APS is version 0, so version 1 is still a defect",
      any(c == "CFM-008" for c, _ in cw.parse_cfm(
          mk.eth(mk.D3, mk.MAC_A,
                 mk.cfm(3, 39, 0, 4, bytes([0xB0, 1, 1, 0]), mk.END,
                        version=1), vlans=((0x8100, 100),)),
          0, 0.0).structural),
      "the version exemption must stay scoped to R-APS only")

# ---- G.8032 revision handling -------------------------------------------
# The revision is carried in the CFM common-header Version field: 0 is
# G.8032v1, 1 is G.8032v2. Wireshark corroborates the split by selecting
# the status-octet layout from it - reserved_v1 masks 0x3F, reserved_v2
# masks 0x1F with bit 5 decoded as BPR.
v2 = cw.parse_cfm(mk.eth_ring(mk.MAC_A, mk.raps(3, 0xB, status=mk.RB,
                                                version=1)), 0, 0.0)
v1 = cw.parse_cfm(mk.eth_ring(mk.MAC_A, mk.raps(3, 0xB, status=mk.RB,
                                                version=0)), 0, 0.0)
check("version 1 is read as G.8032v2",
      v2.body["revision_name"] == "G.8032v2")
check("version 0 is read as G.8032v1",
      v1.body["revision_name"] == "G.8032v1")
check("a conforming G.8032v2 R-APS raises NO structural defect",
      not v2.structural,
      "CFM-008 here would fire on every frame of every modern ERPS "
      "deployment: " + str(v2.structural))
# The version exemption is scoped to R-APS only: a version-1 CCM is still
# a structural defect, because 802.1ag defines no version but 0.
ccm_v1 = cw.parse_cfm(mk.eth(mk.D3, mk.MAC_A,
                             mk.cfm(3, 1, 0x04, 70,
                                    mk.ccm_body(1, 10, mk.maid()),
                                    mk.END, version=1)), 0, 0.0)
check("version 1 on a non-R-APS opcode still raises CFM-008",
      any(c == "CFM-008" for c, _ in ccm_v1.structural),
      str(ccm_v1.structural))
check("version 2 on an R-APS still raises CFM-008 (no such revision)",
      any(c == "CFM-008" for c, _ in cw.parse_cfm(
          mk.eth_ring(mk.MAC_A, mk.raps(3, 0, version=2)), 0, 0.0
      ).structural))

# bit 5 of the status octet: BPR from v2, reserved in v1
bpr_v2 = cw.parse_cfm(mk.eth_ring(mk.MAC_A, mk.raps(3, 0, status=mk.BPR,
                                                    version=1)), 0, 0.0)
bpr_v1 = cw.parse_cfm(mk.eth_ring(mk.MAC_A, mk.raps(3, 0, status=mk.BPR,
                                                    version=0)), 0, 0.0)
check("bit 5 decodes as BPR on a v2 frame", bpr_v2.body["bpr"] is True)
check("bit 5 is NOT read as BPR on a v1 frame, where it is reserved",
      bpr_v1.body["bpr"] is False)
check("v1 reserved mask is 0x3F, so bit 5 counts as a reserved violation",
      bpr_v1.body["status_reserved"] == 0x20,
      str(bpr_v1.body["status_reserved"]))
check("v2 reserved mask is 0x1F, so bit 5 is not a reserved violation",
      bpr_v2.body["status_reserved"] == 0x00,
      str(bpr_v2.body["status_reserved"]))
check("reserved masks match the widths Wireshark uses per revision",
      cw.RAPS_STATUS_RESERVED_BY_VERSION == {0: 0x3F, 1: 0x1F})
check("v2-only requests are MS, FS and Event",
      cw.RAPS_V2_ONLY_REQUESTS == frozenset({cw.RAPS_MS, cw.RAPS_FS,
                                             cw.RAPS_EVENT}))

# Linux receive VLAN offload strips the outer 802.1Q tag out of the frame
# data and into socket aux data. The live path recovers it; these pin that
# behaviour, because a regression makes every VLAN-keyed rule in the
# module - the ring class and Class C's MA/MEP keying alike - silently
# report untagged. The offline pcap path cannot catch this.
tagged = mk.eth_ring(mk.MAC_A, mk.raps(3, 0, status=mk.RB))
stripped = tagged[:12] + tagged[16:]
check("a stripped tag loses the VLAN key",
      cw.parse_cfm(stripped, 0, 0.0).vlan_key == ())
check("reinsert_vlan restores the frame byte for byte",
      cw.reinsert_vlan(stripped, 500, 0x8100) == tagged)
check("reinsert_vlan restores the VLAN key",
      cw.parse_cfm(cw.reinsert_vlan(stripped, 500, 0x8100),
                   0, 0.0).vlan_key == (500,))
check("reinsert_vlan honours a QinQ service TPID",
      cw.parse_cfm(cw.reinsert_vlan(stripped, 300, 0x88A8),
                   0, 0.0).vlans[0].tpid == 0x88A8)
check("reinsert_vlan defaults a zero TPID to 0x8100",
      cw.parse_cfm(cw.reinsert_vlan(stripped, 500, 0),
                   0, 0.0).vlans[0].tpid == 0x8100)
check("reinsert_vlan leaves a runt frame alone",
      cw.reinsert_vlan(b"\x00" * 8, 500, 0x8100) == b"\x00" * 8)
check("aux-data struct is the kernel's 20-octet tpacket_auxdata",
      cw._AUXDATA_LEN == 20, str(cw._AUXDATA_LEN))

ring = cw.parse_ring("500,rpl=00:11:22:aa:00:01,"
                     "nodes=00:11:22:bb:00:02,name=r5")
check("--ring parses VLAN, RPL owner, nodes and label",
      ring.vlan == (500,) and ring.rpl_owner == mk.MAC_A and
      ring.label == "r5", str(ring))
check("declared RPL owner is added to the node set",
      mk.MAC_A in ring.nodes,
      "otherwise CFM-195 fires on the owner's own R-APS")
check("--ring accepts untagged", cw.parse_ring("untagged").vlan == ())
check("--ring accepts a QinQ outer/inner pair",
      cw.parse_ring("300/101").vlan == (300, 101))
for bad_spec, why in (("abc", "non-numeric VLAN"),
                      ("500,9999", "option without key=value"),
                      ("500,bogus=1", "unknown option"),
                      ("5000", "VLAN out of range"),
                      ("500,rpl=zz:zz", "malformed MAC")):
    try:
        cw.parse_ring(bad_spec)
        check("--ring rejects %s" % why, False, bad_spec)
    except ValueError:
        check("--ring rejects %s" % why, True)

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
print("\n[4] baseline quiet and negative controls")

eng = run_pcap(os.path.join(mk.FIXDIR, "baseline.pcap"))
noisy = [f.code for f in eng.results()
         if cw.REGISTRY[f.code].severity not in (cw.SEV_INFO, cw.SEV_LOW)]
check("healthy traffic raises nothing above LOW", not noisy, str(noisy))

# The ring negative control. raps_baseline carries a REAL protection
# switch: an AIS arrives first, then R-APS(SF). CFM-186 claims a forged
# switch and must stay silent when the fault is corroborated, or the whole
# rule is worthless on a live ring.
eng = run_pcap(os.path.join(mk.FIXDIR, "raps_baseline.pcap"), RING_ARGS)
fired = {f.code for f in eng.results()}
check("CFM-186 stays silent on an AIS-corroborated protection switch",
      "CFM-186" not in fired)
check("CFM-185 still records the SF itself", "CFM-185" in fired)
check("a declared ring does not raise the undeclared-ring finding",
      "CFM-200" not in fired)
check("a correctly declared RPL owner raises no impersonation finding",
      "CFM-192" not in fired)
check("declared ring nodes raise no off-ring finding",
      "CFM-195" not in fired)
noisy = [f.code for f in eng.results()
         if cw.REGISTRY[f.code].severity in (cw.SEV_CRITICAL, cw.SEV_HIGH)]
check("a healthy declared ring raises nothing at HIGH or above", not noisy,
      str(noisy))

# The ELPS negative control. SF-P reports that the PROTECTION path
# failed, so the working path keeps carrying traffic and its CCMs stay
# healthy. That is what SF-P implies, not evidence against it - running it
# through CFM-083's uncorroborated test raises a CRITICAL forged-switch
# alarm on every genuine protection-path failure.
eng = run_pcap(os.path.join(mk.FIXDIR, "elps.pcap"))
fired = {f.code for f in eng.results()}
check("CFM-083 stays silent on SF-P with a healthy working path",
      "CFM-083" not in fired)
check("CFM-088 reports the protection path failure instead",
      "CFM-088" in fired)
check("protection-type mismatch between ends is reported",
      "CFM-090" in fired)
check("requested/bridged signal disagreement is reported",
      "CFM-091" in fired)

# ---- G.8032v2 sub-rings: the negative control that closes the gap -------
# A legitimate topology-change propagation from an interconnection node is
# normal operation. Before sub-rings were modelled, cfmwatch reported it
# as a bare flush primitive (CFM-189/190) and so alarmed continuously on
# every interconnected topology.
eng = run_pcap(os.path.join(mk.FIXDIR, "subring.pcap"), mk.SUBRING_DECL)
fired = {f.code for f in eng.results()}
check("CFM-189 stays silent on legitimate interconnection-node propagation",
      "CFM-189" not in fired)
check("CFM-190 stays silent on legitimate propagation",
      "CFM-190" not in fired)
check("CFM-209 records the propagation instead", "CFM-209" in fired)
check("a flush from a non-interconnection node is still caught (CFM-205)",
      "CFM-205" in fired)
check("a flush INTO a sub-ring is caught (CFM-207)", "CFM-207" in fired)
check("a non-VC sub-ring node on the parent is caught (CFM-208)",
      "CFM-208" in fired)

# Without the declaration the same capture cannot be told apart, so the
# original behaviour must still stand - no silent regression into
# under-reporting.
eng = run_pcap(os.path.join(mk.FIXDIR, "subring.pcap"))
undeclared = {f.code for f in eng.results()}
check("without a declaration the flush still raises CFM-189",
      "CFM-189" in undeclared)
for code in ("CFM-205", "CFM-207", "CFM-208", "CFM-209"):
    check("%s stays inert without a declared topology" % code,
          code not in undeclared)

# Ring role parsing and its invariants.
sub = cw.parse_ring("600,role=sub,parent=major-500,vc=no,"
                    "interconnect=00:11:22:aa:00:01,nodes=00:11:22:cc:00:03")
check("role=sub parses with parent, vc and interconnect",
      sub.is_sub() and sub.parent == "major-500" and
      sub.virtual_channel is False and mk.MAC_A in sub.interconnect,
      str(sub))
check("interconnection nodes are added to the node set",
      mk.MAC_A in sub.nodes,
      "otherwise CFM-195 fires on an interconnection node's own R-APS")
check("revertive defaults to yes", cw.parse_ring("500").revertive is True)
check("revertive=no parses",
      cw.parse_ring("500,revertive=no").revertive is False)
for bad_spec, why in (("600,role=sub", "role=sub without a parent"),
                      ("500,parent=x", "parent without role=sub"),
                      ("500,role=bogus", "an unknown role"),
                      ("500,vc=maybe", "a non-boolean vc"),
                      ("500,revertive=sometimes", "a non-boolean revertive"),
                      ("500,interconnect=zz", "a malformed interconnect")):
    try:
        cw.parse_ring(bad_spec)
        check("--ring rejects %s" % why, False, bad_spec)
    except ValueError:
        check("--ring rejects %s" % why, True)

# Revertive operation is configuration only in G.8032, so a declared
# non-revertive ring must not raise the no-block findings at all.
eng = run_pcap(os.path.join(mk.FIXDIR, "raps_withdrawn.pcap"), mk.RING_DECL)
fired = {f.code for f in eng.results()}
check("an observed-then-vanished block raises CFM-206", "CFM-206" in fired)
check("CFM-194 yields to CFM-206 when the block was actually seen",
      "CFM-194" not in fired)
norev = list(mk.RING_DECL)
norev[-1] = norev[-1] + ",revertive=no"
eng = run_pcap(os.path.join(mk.FIXDIR, "raps_withdrawn.pcap"), norev)
fired = {f.code for f in eng.results()}
check("a declared non-revertive ring raises neither CFM-194 nor CFM-206",
      not ({"CFM-194", "CFM-206"} & fired), str(sorted(fired)))
check("the RB staleness window is tunable apart from the CFM-193 "
      "concurrency window",
      cw.Config().rb_stale is not None and
      "rb_stale" in cw.Config.__dataclass_fields__ and
      "rb_window" in cw.Config.__dataclass_fields__)

# The E-LMI cross-plane rule, both directions and the agreeing case.
eng = run_pcap(os.path.join(mk.FIXDIR, "elmi.pcap"), mk.EVC_DECL)
fired = {f.code for f in eng.results()}
check("a contradiction between E-LMI and CFM is reported",
      "CFM-251" in fired)
c251 = [f for f in eng.results() if f.code == "CFM-251"][0]
check("both directions of the contradiction are caught", c251.count >= 2,
      "got %d; expected the Not-Active-while-healthy and the "
      "Active-while-faulted cases" % c251.count)
check("a replayed E-LMI frame is caught", "CFM-253" in fired)
check("an E-LMI structural defect is caught", "CFM-252" in fired)
check("a declared mapping does not raise the undeclared finding",
      "CFM-254" not in fired)

# Agreement must stay silent, or the rule is worthless on a live UNI.
quiet = cw.Engine(cw.config_from_args(cw.build_parser().parse_args(
    ["--pcap", "x"] + mk.EVC_DECL)))
agree = [mk.eth(mk.D3, mk.MAC_A, mk.ccm(3, 10, seq=i + 1),
                vlans=((0x8100, 500),)) for i in range(3)]
agree.append(mk.elmi(snd=1, evcs=((7, 0x02),)))
for i, raw in enumerate(agree):
    quiet.feed_raw(raw, i, mk.BASE_TS + i * 0.3)
quiet.finalize()
agreed = {f.code for f in quiet.results()}
check("E-LMI reporting Active while CFM is healthy stays silent",
      "CFM-251" not in agreed, str(sorted(agreed)))
check("the E-LMI observation itself is still recorded",
      "CFM-250" in agreed)

# Undeclared E-LMI fails loud and leaves the cross-plane rule inert.
eng = run_pcap(os.path.join(mk.FIXDIR, "elmi_undeclared.pcap"))
fired = {f.code for f in eng.results()}
check("undeclared E-LMI raises CFM-254", "CFM-254" in fired)
check("CFM-251 is inert without an EVC mapping", "CFM-251" not in fired)
check("E-LMI structural rules stay armed without a mapping",
      "CFM-250" in fired)

# Two tenants behind different VNIs must not share per-service state.
eng = run_pcap(os.path.join(mk.FIXDIR, "vxlan.pcap"))
fired = {f.code for f in eng.results()}
check("two VNIs reusing one inner VLAN do not merge their associations",
      "CFM-040" not in fired,
      "CFM-040 here would mean tenant state collided in the state tables")
check("the VXLAN encapsulation is recorded", "CFM-240" in fired)

# Undeclared rings must fail loud rather than look clean.
eng = run_pcap(os.path.join(mk.FIXDIR, "raps_structural.pcap"))
fired = {f.code for f in eng.results()}
check("an undeclared ring fails loud with CFM-200", "CFM-200" in fired)
for code in ("CFM-192", "CFM-194", "CFM-195", "CFM-199"):
    check("%s stays inert without a ring declaration" % code,
          code not in fired)
check("structural R-APS rules stay armed without a declaration",
      {"CFM-181", "CFM-182", "CFM-183", "CFM-184"} <= fired,
      str(sorted(fired)))

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
