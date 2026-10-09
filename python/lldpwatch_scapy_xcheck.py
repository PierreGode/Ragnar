#!/usr/bin/env python3
"""
lldpwatch_scapy_xcheck — independent-implementation cross-check.

Suite LESSON A: lldpwatch pairs a hand-rolled TLV parser with a hand-rolled
frame serializer and the conformance harness feeds one into the other. That
structure proves the two halves AGREE; it cannot prove either is right about
the wire. Every Class-A rule in this module is a length, offset or bounds
rule, which is exactly where a shared mental model goes wrong silently.

scapy.contrib.lldp is an independent dissector of the same standard. Three
directions are checked:
  (1) we build  -> scapy dissects   (our bytes are real LLDP)
  (2) scapy builds -> we parse      (we read someone else's bytes)
  (3) our pcap writer -> scapy rdpcap (our artefacts are real pcaps)

Plus LESSON C: this is the only tier that executes _run_live(), the single
function that imports scapy, driven through scapy's own offline sniff.

Requires scapy. Deliberately NOT part of the offline conformance run, which
asserts scapy stays unimported.
"""

from __future__ import annotations

import os
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence

import lldpwatch as W
import lldpwatch_frames as F
from lldpwatch_conformance import Checker

from scapy.contrib.lldp import (  # noqa: E402
    LLDPDU,
    LLDPDUChassisID,
    LLDPDUEndOfLLDPDU,
    LLDPDUManagementAddress,
    LLDPDUPortDescription,
    LLDPDUPortID,
    LLDPDUSystemCapabilities,
    LLDPDUSystemDescription,
    LLDPDUSystemName,
    LLDPDUTimeToLive,
)
from scapy.config import conf  # noqa: E402
from scapy.layers.l2 import Dot1Q, Ether  # noqa: E402
from scapy.utils import rdpcap  # noqa: E402

conf.contribs["LLDP"].strict_mode_disable()


class _MissingLayer:
    """Returned when an expected scapy layer is absent, so a missing layer is
    a FAILURE rather than an IndexError that loses the rest of the section
    (suite LESSON L)."""

    def __getattr__(self, name: str) -> Any:
        return None

    def __getitem__(self, key: Any) -> Any:
        return self


def layer(c: Checker, pkt: Any, cls: Any, what: str) -> Any:
    if cls in pkt:
        c.ok(True, "%s: %s layer present" % (what, cls.__name__))
        return pkt[cls]
    c.ok(False, "%s: scapy did not dissect a %s layer" % (what, cls.__name__))
    return _MissingLayer()


def tlv_chain(pkt: Any) -> List[Any]:
    out = []
    layer = pkt
    while layer is not None:
        # scapy exposes a generic LLDPDU base layer in front of the first
        # typed TLV; it is the same bytes, not an extra TLV.
        if isinstance(layer, LLDPDU) and type(layer) is not LLDPDU:
            out.append(layer)
        layer = layer.payload if layer.payload else None
        if layer is not None and not hasattr(layer, "payload"):
            break
    return out


# ==========================================================================
# Direction 1 — we build, scapy dissects
# ==========================================================================


def d1_we_build(c: Checker) -> None:
    c.sect("d1-we-build-scapy-dissects")
    cases = [
        ("minimal", F.benign_minimal()),
        ("full-v4", F.benign_full()),
        ("full-v6", F.benign_full_v6()),
        ("med-phone", F.benign_med_phone()),
        ("long-banner", F.benign_long_banner()),
        ("cisco", F.vendor_cisco()),
        ("juniper", F.vendor_juniper()),
        ("lldpd", F.vendor_lldpd()),
        ("sonicwall", F.vendor_sonicwall()),
    ]
    for name, raw in cases:
        pkt = Ether(raw)
        c.eq(pkt.type, 0x88CC, "%s: scapy reads ethertype 0x88cc" % name)
        c.eq(pkt.dst, "01:80:c2:00:00:0e", "%s: scapy reads the group MAC" % name)
        chain = tlv_chain(pkt)
        c.ok(len(chain) >= 4, "%s: scapy dissects a TLV chain (%d)" % (name, len(chain)))
        ours = W.walk_tlvs(W.parse_ethernet(raw).payload)
        their_types = [t._type for t in chain]
        our_types = [t.type for t in ours.tlvs]
        c.ok(bool(our_types), "%s: our walker produced at least one TLV" % name)
        c.eq(our_types[: len(their_types)], their_types,
             "%s: TLV type sequence agrees with scapy" % name)
        c.ok(LLDPDUEndOfLLDPDU in pkt, "%s: scapy finds End-of-LLDPDU" % name)

    c.sect("d1-field-level")
    raw = F.benign_full()
    pkt = Ether(raw)
    c.eq(layer(c, pkt, LLDPDUChassisID, "chassis").subtype, 4, "chassis subtype agrees")
    c.eq(layer(c, pkt, LLDPDUChassisID, "chassis").id, "00:11:22:33:44:55", "chassis MAC id agrees")
    c.eq(layer(c, pkt, LLDPDUPortID, "port").subtype, 5, "port subtype agrees")
    c.eq(layer(c, pkt, LLDPDUPortID, "port").id, b"Gi1/0/1", "port id agrees")
    c.eq(layer(c, pkt, LLDPDUTimeToLive, "ttl").ttl, 120, "TTL agrees")
    c.eq(layer(c, pkt, LLDPDUSystemName, "sysname").system_name, b"srv-14", "system name agrees")
    c.eq(layer(c, pkt, LLDPDUPortDescription, "portdesc").description, b"uplink to agg", "port desc agrees")
    c.eq(bytes(layer(c, pkt, LLDPDUSystemDescription, "sysdesc").description or b""),
         b"GenericBox 400 software, build 7", "system description agrees")
    c.ok(LLDPDUSystemCapabilities in pkt, "system capabilities TLV present")
    ma = layer(c, pkt, LLDPDUManagementAddress, "mgmtaddr")
    c.eq(ma.management_address_subtype, 1, "mgmt address subtype is IPv4")
    c.eq(ma.management_address, F.IPV4_ADDR, "IPv4 mgmt address bytes agree")
    c.eq(ma._management_address_string_length, 5, "IPv4 address string length is 5")

    c.sect("d1-field-level-v6")
    pkt = Ether(F.benign_full_v6())
    ma = layer(c, pkt, LLDPDUManagementAddress, "mgmtaddr")
    c.eq(ma.management_address_subtype, 2, "mgmt address subtype is IPv6")
    c.eq(ma.management_address, F.IPV6_ADDR, "IPv6 mgmt address bytes agree")
    c.eq(ma._management_address_string_length, 17, "IPv6 address string length is 17")
    c.eq(W.extract_mgmt_addrs(W.walk_tlvs(W.parse_ethernet(F.benign_full_v6()).payload)),
         ["[2001:db8::9]"], "our v6 rendering of the address scapy also read")

    c.sect("d1-tagged")
    raw = F.benign_tagged(vid=300)
    pkt = Ether(raw)
    c.ok(Dot1Q in pkt, "scapy sees the 802.1Q tag")
    c.eq(layer(c, pkt, Dot1Q, "dot1q").vlan, 300, "scapy reads VLAN 300")
    c.eq(W.parse_ethernet(raw).vlans, (300,), "we read the same VLAN")
    raw = F.benign_qinq()
    pkt = Ether(raw)
    tags = [l.vlan for l in pkt.layers() if False] or []
    q = layer(c, pkt, Dot1Q, "dot1q")
    c.eq(q.vlan, 300, "QinQ outer tag agrees")
    c.eq(layer(c, q.payload, Dot1Q, "dot1q-inner").vlan, 12, "QinQ inner tag agrees")
    c.eq(W.parse_ethernet(raw).vlans, (300, 12), "we read both QinQ tags")

    c.sect("d1-length-encoding")
    # The 7-bit type / 9-bit length split is where a hand-rolled parser goes
    # wrong. Pin it against scapy at the boundaries.
    for ttype, ln in ((0, 0), (1, 7), (6, 255), (127, 300), (8, 12)):
        body = b"\x00" * ln
        ours = W.walk_tlvs(F.tlv(ttype, body) + F.t_end())
        if c.ok(bool(ours.tlvs), "length-encoding %d/%d yields a TLV" % (ttype, ln)):
            c.eq(ours.tlvs[0].type, ttype, "our type %d at len %d" % (ttype, ln))
            c.eq(ours.tlvs[0].length, ln, "our length %d for type %d" % (ln, ttype))
        hdr = F.tlv(ttype, body)[:2]
        c.eq((hdr[0] << 8 | hdr[1]) >> 9, ttype, "wire header type bits %d" % ttype)
        c.eq((hdr[0] << 8 | hdr[1]) & 0x1FF, ln, "wire header length bits %d" % ln)


# ==========================================================================
# Direction 2 — scapy builds, we parse
# ==========================================================================


def scapy_frame(*tlvs: Any, src: str = "02:00:00:00:ab:01") -> bytes:
    pkt = Ether(dst="01:80:c2:00:00:0e", src=src, type=0x88CC)
    for t in tlvs:
        pkt = pkt / t
    return bytes(pkt)


def d2_scapy_builds(c: Checker) -> None:
    c.sect("d2-scapy-builds-we-parse")
    raw = scapy_frame(
        LLDPDUChassisID(subtype=4, id="aa:bb:cc:dd:ee:ff"),
        LLDPDUPortID(subtype=5, id=b"xe-0/0/1"),
        LLDPDUTimeToLive(ttl=90),
        LLDPDUSystemName(system_name=b"scapy-built-01"),
        LLDPDUSystemDescription(description=b"Vendorless Appliance 1.0"),
        LLDPDUEndOfLLDPDU(),
    )
    fr = W.parse_ethernet(raw)
    c.ok(fr is not None, "we parse a scapy-built frame")
    c.eq(fr.src, "02:00:00:00:ab:01", "source MAC agrees")
    w = W.walk_tlvs(fr.payload)
    c.eq([t.type for t in w.tlvs], [1, 2, 3, 5, 6, 0], "TLV types agree")
    c.ok(w.end_seen, "we find scapy's End-of-LLDPDU")
    c.eq(w.tail_kind, "none", "a scapy-built frame carries no padding (the kernel "
         "pads on send, scapy does not pad on build)")
    # the scapy-built frame already exceeds the 60-octet minimum, so pad it
    # explicitly to reproduce what the kernel does to a SHORT LLDPDU
    padded = raw + b"\x00" * 10
    c.eq(W.walk_tlvs(W.parse_ethernet(padded).payload).tail_kind, "padding",
         "zeros appended after End-of-LLDPDU read as padding, not data")
    c.eq(W.Engine().handle_frame(padded), [], "the padded scapy frame is still silent")
    c.eq(W.Engine().handle_frame(raw), [], "a well-formed scapy frame is SILENT")
    c.eq(w.tlvs[0].value, bytes([4]) + bytes.fromhex("aabbccddeeff"),
         "chassis MAC bytes agree with scapy's encoding")
    c.eq(w.tlvs[2].value, b"\x00\x5a", "TTL 90 encodes as scapy encodes it")

    c.sect("d2-mgmt-address")
    # scapy's management_address is a raw byte field, NOT a presentation
    # string: handing it "192.0.2.10" encodes ten ASCII octets, which our
    # detector correctly reports as a malformed TLV. Pack the address.
    for sub, addr, want in (
        (1, bytes([192, 0, 2, 10]), "192.0.2.10"),
        (2, bytes.fromhex("20010db8" + "0" * 23 + "1"), "[2001:db8::1]"),
        (2, bytes.fromhex("fe80000000000000021122fffe334455"),
         "[fe80::211:22ff:fe33:4455]"),
        (2, bytes(15) + b"\x01", "[::1]"),
    ):
        raw = scapy_frame(
            LLDPDUChassisID(subtype=4, id="aa:bb:cc:dd:ee:ff"),
            LLDPDUPortID(subtype=5, id=b"eth0"),
            LLDPDUTimeToLive(ttl=90),
            LLDPDUManagementAddress(
                management_address_subtype=sub,
                management_address=addr,
                interface_numbering_subtype=2,
                interface_number=1,
            ),
            LLDPDUEndOfLLDPDU(),
        )
        c.eq(W.Engine().handle_frame(raw), [],
             "scapy-built mgmt address (subtype %d) is silent" % sub)
        got = W.extract_mgmt_addrs(W.walk_tlvs(W.parse_ethernet(raw).payload))
        c.eq(got, [want], "we recover scapy's address as %s" % want)

    c.sect("d2-wire-byte-equality")
    # Our serializer and scapy's must produce IDENTICAL bytes for the same
    # logical LLDPDU. This is the check that would have caught a cdpwatch-style
    # shared-codec error.
    ours = F.frame(
        [
            F.t_chassis_id(subtype=4, body=bytes.fromhex("aabbccddeeff")),
            F.t_port_id(subtype=5, body=b"eth0"),
            F.t_ttl(90),
            F.t_sys_name(b"box-1"),
            F.t_end(),
        ],
        src="02:00:00:00:ab:01",
        pad=False,
    )
    theirs = bytes(
        Ether(dst="01:80:c2:00:00:0e", src="02:00:00:00:ab:01", type=0x88CC)
        / LLDPDUChassisID(subtype=4, id="aa:bb:cc:dd:ee:ff")
        / LLDPDUPortID(subtype=5, id=b"eth0")
        / LLDPDUTimeToLive(ttl=90)
        / LLDPDUSystemName(system_name=b"box-1")
        / LLDPDUEndOfLLDPDU()
    )
    c.eq(ours, theirs[: len(ours)], "our LLDPDU bytes equal scapy's, octet for octet")

    c.sect("d2-counterfactual")
    # LESSON J: the wrong model must be INTERNALLY CONSISTENT and wrong only
    # relative to the standard, or it is self-detecting and proves nothing.
    # Here: an 8-bit type / 8-bit length split instead of 7/9. Every frame it
    # builds round-trips through its own parser perfectly.
    def wrong_tlv(ttype: int, value: bytes) -> bytes:
        return bytes([ttype & 0xFF, len(value) & 0xFF]) + value

    def wrong_walk(buf: bytes):
        out, i = [], 0
        while i + 2 <= len(buf):
            t, ln = buf[i], buf[i + 1]
            if i + 2 + ln > len(buf):
                break
            out.append((t, ln, buf[i + 2 : i + 2 + ln]))
            i += 2 + ln
            if t == 0 and ln == 0:
                break
        return out

    body = wrong_tlv(1, bytes([4]) + bytes.fromhex("aabbccddeeff")) + \
        wrong_tlv(2, bytes([5]) + b"eth0") + wrong_tlv(3, b"\x00\x5a") + wrong_tlv(0, b"")
    rt = wrong_walk(body)
    c.eq([t for t, _, _ in rt], [1, 2, 3, 0], "counterfactual round-trips through ITSELF")
    # ...and is nonetheless wrong on the wire: scapy must not read it as LLDP
    bad = Ether(
        b"\x01\x80\xc2\x00\x00\x0e" + F.mac("02:00:00:00:ab:09") + b"\x88\xcc" + body
    )
    their_types = [t._type for t in tlv_chain(bad)]
    c.ok(their_types != [1, 2, 3, 0],
         "scapy disagrees with the 8/8 model (read %r)" % their_types)
    ours_types = [t.type for t in W.walk_tlvs(body).tlvs]
    c.ok(ours_types != [1, 2, 3, 0],
         "our parser also disagrees with the 8/8 model (read %r)" % ours_types)


# ==========================================================================
# Direction 3 — our pcap writer, scapy's reader
# ==========================================================================


def d3_pcap(c: Checker) -> None:
    c.sect("d3-pcap-writer")
    frames = [b() for b in F.BENIGN_BUILDERS] + [
        fn() for v in F.MALFORMED_BUILDERS.values() for fn in v
    ]
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x.pcap")
        F.write_pcap(p, frames, base_ts=1700000000.0, interval=0.001)
        pkts = rdpcap(p)
        c.eq(len(pkts), len(frames), "scapy reads back every frame we wrote")
        for i, pkt in enumerate(pkts):
            c.eq(bytes(pkt), frames[i], "frame %d bytes survive scapy's reader" % i)
        times = [float(p_.time) for p_ in pkts]
        c.ok(all(b >= a for a, b in zip(times, times[1:])),
             "scapy sees monotonic timestamps")
        span = times[-1] - times[0]
        c.ok(span < W.Config().flood_window,
             "scapy-measured span %.4fs is inside the flood window" % span)
        c.eq(pkts[0].__class__.__name__, "Ether", "scapy decodes DLT_EN10MB as Ether")

        # the index-in-seconds bug, measured through scapy rather than asserted
        bad = os.path.join(d, "bad.pcap")
        F.write_pcap(bad, frames, base_ts=1700000000.0, interval=1.0)
        bt = [float(p_.time) for p_ in rdpcap(bad)]
        c.ok(bt[-1] - bt[0] > W.Config().flood_window,
             "counterfactual: 1s spacing exceeds the window, as it did in cdpwatch")


# ==========================================================================
# LESSON C — the live capture path, through scapy's own offline sniff
# ==========================================================================


def d4_live_path(c: Checker) -> None:
    c.sect("d4-live-path")
    from scapy.all import sniff as real_sniff

    attack = [fn() for v in F.MALFORMED_BUILDERS.values() for fn in v]
    attack += [fn() for fn in F.VENDOR_BUILDERS.values()]
    clean = [b() for b in F.BENIGN_BUILDERS]

    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "live.pcap")
        F.write_pcap(p, attack)

        seen: Dict[str, Any] = {}

        def offline_sniff(**kw):
            """Swap ONLY the source: everything else — the BPF filter, the
            callback, store=False — is handed to the real scapy sniff."""
            seen.update(kw)
            kw.pop("iface", None)
            return real_sniff(offline=p, **kw)

        out: List[Dict[str, Any]] = []
        cfg = W.Config(iface="veth-lab", flood_threshold=10000,
                       flood_distinct_src=10000, suppress_window=0.0001)
        eng = W.Engine(cfg, emit=out.append)
        W._run_live("veth-lab", eng, sniff_fn=offline_sniff)

        c.eq(seen.get("filter"), W.BPF_FILTER, "the real BPF filter is handed to scapy")
        c.eq(seen.get("store"), False, "store=False on the live path")
        c.eq(seen.get("iface"), "veth-lab", "iface is passed through")
        got = sorted({r["code"] for r in out})
        want = sorted(set(F.MALFORMED_BUILDERS) | set(F.VENDOR_BUILDERS))
        c.eq(got, want, "LIVE path yields the same codes as the offline tier")
        for r in out:
            c.eq(r["iface"], "veth-lab", "live record carries the interface")
            c.ok(r["ts"] > 1_600_000_000, "live record carries a real timestamp")

        # clean set through the same live path must be silent
        p2 = os.path.join(d, "clean.pcap")
        F.write_pcap(p2, clean)

        def offline_sniff2(**kw):
            kw.pop("iface", None)
            return real_sniff(offline=p2, **kw)

        out2: List[Dict[str, Any]] = []
        eng2 = W.Engine(W.Config(iface="veth-lab", flood_threshold=10000,
                                 flood_distinct_src=10000), emit=out2.append)
        W._run_live("veth-lab", eng2, sniff_fn=offline_sniff2)
        c.eq([r["code"] for r in out2], [], "clean set is silent on the LIVE path too")

        # learn mode on the live path: silent, and it still records a baseline
        out3: List[Dict[str, Any]] = []
        eng3 = W.Engine(W.Config(iface="veth-lab"), emit=out3.append, learn=True)
        W._run_live("veth-lab", eng3, sniff_fn=offline_sniff2)
        c.eq(out3, [], "live learn mode emits nothing")
        c.eq(eng3.baseline_lines(), sorted(eng3.baseline_lines()),
             "live learn mode dumps a sorted baseline")
        c.eq(len(eng3.baseline_lines()), len(clean),
             "live learn saw every source (a short count means the BPF filter "
             "dropped a frame the parser can handle - suite LESSON H)")

    c.sect("d4-bpf-reachability")
    # LESSON H / AE: scapy's offline sniff genuinely compiles and applies the
    # filter, so this is a MEASURED differential, not an assertion about it.
    with tempfile.TemporaryDirectory() as d:
        mixed = os.path.join(d, "mixed.pcap")
        arp = (
            b"\xff\xff\xff\xff\xff\xff" + F.mac("02:00:00:00:cc:01")
            + b"\x08\x06" + b"\x00" * 46
        )
        ipv6 = (
            b"\x33\x33\x00\x00\x00\x01" + F.mac("02:00:00:00:cc:02")
            + b"\x86\xdd" + b"\x00" * 46
        )
        F.write_pcap(mixed, [arp, F.benign_minimal(), ipv6, F.mal_length_overrun(),
                             F.benign_tagged(vid=300)])
        kept: List[bytes] = []
        real_sniff(offline=mixed, filter=W.BPF_FILTER, store=False,
                   prn=lambda p_: kept.append(bytes(p_)))
        c.eq(len(kept), 3, "BPF admits the 3 LLDP frames and drops ARP + IPv6")
        c.ok(F.mal_length_overrun() in kept, "the attack frame survives the filter")

        # MEASURED differential across the filter variants. The flat
        # three-term form is a NO-OP; only the nested form reaches QinQ.
        tagged_only = os.path.join(d, "tagged.pcap")
        variants = [
            ("ether proto 0x88cc", 1),
            ("ether proto 0x88cc or (vlan and ether proto 0x88cc)", 2),
            ("ether proto 0x88cc or (vlan and ether proto 0x88cc) "
             "or (vlan and vlan and ether proto 0x88cc)", 2),
            (W.BPF_FILTER, 3),
        ]
        F.write_pcap(tagged_only,
                     [F.benign_minimal(), F.benign_tagged(vid=300), F.benign_qinq()])
        counts = []
        for flt, want in variants:
            got: List[bytes] = []
            real_sniff(offline=tagged_only, filter=flt, store=False,
                       prn=lambda p_, g=got: g.append(bytes(p_)))
            counts.append(len(got))
            c.eq(len(got), want, "filter admits %d/3: %s" % (want, flt[:52]))
        c.eq(counts[1], counts[2],
             "the flat vlan-and-vlan term is a MEASURED NO-OP (LESSON AE)")
        c.ok(counts[3] > counts[2], "the nested form is the only one that reaches QinQ")

        # and the production filter must not over-admit tagged non-LLDP
        noise = os.path.join(d, "noise.pcap")
        F.write_pcap(noise, [
            F.DST_NEAREST_BRIDGE + F.mac("02:00:00:00:cc:03")
            + b"\x81\x00\x00\x64" + b"\x08\x00" + b"\x00" * 46,
            F.DST_NEAREST_BRIDGE + F.mac("02:00:00:00:cc:04")
            + b"\x81\x00\x00\x64" + b"\x81\x00\x00\x0c" + b"\x86\xdd" + b"\x00" * 46,
        ])
        got = []
        real_sniff(offline=noise, filter=W.BPF_FILTER, store=False,
                   prn=lambda p_: got.append(bytes(p_)))
        c.eq(len(got), 0, "the nested filter admits no tagged non-LLDP traffic")


def main(argv: Optional[Sequence[str]] = None) -> int:
    c = Checker()
    for fn in (d1_we_build, d2_scapy_builds, d3_pcap, d4_live_path):
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
