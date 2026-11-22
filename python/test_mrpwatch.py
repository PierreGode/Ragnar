#!/usr/bin/env python3
"""
mrpwatch validation suite.

Tier 1  golden bytes    - hand-computed MRP PDUs, byte-by-byte, no tooling
Tier 2  scapy xcheck    - GARP fixtures built by scapy.contrib.gxrp, decoded by us
Tier 3  structural      - every malformed-PDU path drives its code
Tier 4  behavioural     - flood/burst/posture logic end to end
Tier 5  registry        - every declared code fires at least once

PASSIVE: every fixture is a byte string in memory. Nothing opens a socket.
"""

import struct
import sys

sys.path.insert(0, "/home/claude/mrpwatch")

from mrpwatch import (  # noqa: E402
    REGISTRY, Config, MrpWatch, classify, decode_garp, decode_mrp,
    ETHERTYPE_MVRP, ETHERTYPE_MMRP,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  -- {detail}" if detail and not cond else ""))


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


SRC = "aa:bb:cc:dd:ee:01"
DST_MVRP = "01:80:c2:00:00:21"
DST_MMRP = "01:80:c2:00:00:20"

FIRED = set()


def record(findings):
    for f in findings:
        FIRED.add(f.code)
    return findings


# ---------------------------------------------------------------------------
# Frame builders
# ---------------------------------------------------------------------------

def eth2(dst, src, etype, payload):
    return mac(dst) + mac(src) + struct.pack("!H", etype) + payload


def dot3_garp(dst, src, payload):
    """802.3 length framing + LLC(0,0,0), no SNAP - exactly how GARP rides."""
    body = b"\x00\x00\x00" + payload
    return mac(dst) + mac(src) + struct.pack("!H", len(body)) + body


def mrp_vecattr(nvalues, events, first, leaveall=False):
    lenflags = (nvalues & 0x1FFF) | (0x2000 if leaveall else 0)
    out = struct.pack("!H", lenflags)
    if nvalues == 0:
        return out
    out += first
    packed, i = b"", 0
    while i < len(events):
        trio = events[i:i + 3] + [0] * (3 - len(events[i:i + 3]))
        packed += bytes([trio[0] * 36 + trio[1] * 6 + trio[2]])
        i += 3
    return out + packed


def mrp_pdu(attr_type, attr_len, vecattrs, version=0, end=True):
    out = bytes([version, attr_type, attr_len]) + b"".join(vecattrs)
    if end:
        out += b"\x00\x00" + b"\x00\x00"
    return out


# ---------------------------------------------------------------------------
# Tier 1 - golden bytes, hand-computed
# ---------------------------------------------------------------------------

def tier1():
    print("\nTier 1 - golden bytes (hand-computed, no tooling)")

    # MVRP declaring VLANs 100,101,102 all JoinIn(event 1).
    # Packing: 1*36 + 1*6 + 1 = 43 = 0x2b.  lenflags = 0x0003 (no LeaveAll).
    golden = bytes.fromhex("00" "0102" "0003" "0064" "2b" "0000" "0000")
    built = mrp_pdu(1, 2, [mrp_vecattr(3, [1, 1, 1], b"\x00\x64")])
    check("golden MVRP bytes match builder", built == golden,
          f"{built.hex()} != {golden.hex()}")

    pdu = decode_mrp(golden, "MVRP")
    check("golden decodes to 3 attributes", len(pdu.attributes) == 3,
          f"got {len(pdu.attributes)}")
    vlans = [a.as_vlan() for a in pdu.attributes]
    check("FirstValue increments 100,101,102", vlans == [100, 101, 102], str(vlans))
    check("all events JoinIn",
          all(a.event == "JoinIn" for a in pdu.attributes))
    check("no structural errors on clean PDU", pdu.structural == [],
          str(pdu.structural))

    # Mixed event trio: New(0), Lv(5), In(2) -> 0*36 + 5*6 + 2 = 32 = 0x20
    p = mrp_pdu(1, 2, [mrp_vecattr(3, [0, 5, 2], b"\x00\x0a")])
    check("mixed-event byte is 0x20", p[7] == 0x20, hex(p[7]))
    d = decode_mrp(p, "MVRP")
    check("mixed events decode in order",
          [a.event for a in d.attributes] == ["New", "Lv", "In"],
          str([a.event for a in d.attributes]))

    # LeaveAll-only vector: NumberOfValues == 0, FirstValue and Vector absent.
    p = mrp_pdu(1, 2, [mrp_vecattr(0, [], b"", leaveall=True)])
    check("LeaveAll-only is 2 bytes 0x2000",
          p[3:5] == b"\x20\x00", p[3:5].hex())
    d = decode_mrp(p, "MVRP")
    check("LeaveAll-only yields flag, no attributes",
          d.leaveall_count == 1 and d.attributes == [])

    # Big-endian carry across the FirstValue: 0x00ff -> 0x0100
    p = mrp_pdu(1, 2, [mrp_vecattr(2, [1, 1], b"\x00\xff")])
    d = decode_mrp(p, "MVRP")
    check("FirstValue carries 255 -> 256",
          [a.as_vlan() for a in d.attributes] == [255, 256],
          str([a.as_vlan() for a in d.attributes]))

    # Partial trailing trio: 4 events = 2 bytes, 2 pad slots ignored.
    p = mrp_pdu(1, 2, [mrp_vecattr(4, [1, 1, 1, 1], b"\x00\x01")])
    d = decode_mrp(p, "MVRP")
    check("partial trio yields exactly 4 events", len(d.attributes) == 4,
          f"got {len(d.attributes)}")

    # MMRP MAC attribute (type 2, len 6)
    p = mrp_pdu(2, 6, [mrp_vecattr(1, [0], mac("01:00:5e:00:00:01"))])
    d = decode_mrp(p, "MMRP")
    check("MMRP MAC attribute decodes",
          d.attributes[0].as_mac() == "01:00:5e:00:00:01",
          str(d.attributes[0].as_mac()))


# ---------------------------------------------------------------------------
# Tier 2 - scapy cross-check for GARP
# ---------------------------------------------------------------------------

def tier2():
    print("\nTier 2 - scapy.contrib.gxrp cross-check (GARP ground truth)")
    from scapy.contrib.gxrp import (
        GARP, GARP_ATTRIBUTE, GARP_MESSAGE, GMRP_GROUP, GVRP,
    )
    from scapy.packet import raw

    # GVRP declaring VLANs 10 and 20, JoinEmpty(1) and JoinIn(2)
    g = GARP(msgs=[GARP_MESSAGE(type=1, attrs=[
        GARP_ATTRIBUTE(event=1) / GVRP(vlan=10),
        GARP_ATTRIBUTE(event=2) / GVRP(vlan=20),
    ])])
    payload = raw(g)
    pdu = decode_garp(payload, "GVRP")
    check("scapy GVRP: 2 attributes decoded", len(pdu.attributes) == 2,
          f"got {len(pdu.attributes)} from {payload.hex()}")
    check("scapy GVRP: VLANs 10,20",
          [a.as_vlan() for a in pdu.attributes] == [10, 20],
          str([a.as_vlan() for a in pdu.attributes]))
    check("scapy GVRP: events JoinEmpty,JoinIn",
          [a.event for a in pdu.attributes] == ["JoinEmpty", "JoinIn"],
          str([a.event for a in pdu.attributes]))
    check("scapy GVRP: no structural errors", pdu.structural == [],
          str(pdu.structural))

    # GARP LeaveAll is event 0 - an EVENT, unlike MRP where it is a flag.
    g = GARP(msgs=[GARP_MESSAGE(type=1, attrs=[
        GARP_ATTRIBUTE(event=0) / GVRP(vlan=0),
    ])])
    pdu = decode_garp(raw(g), "GVRP")
    check("scapy GVRP: LeaveAll counted as event",
          pdu.leaveall_count == 1 and pdu.attributes == [],
          f"la={pdu.leaveall_count} attrs={len(pdu.attributes)}")

    # GMRP group MAC (attribute type 1 = GMRP_GROUP)
    g = GARP(msgs=[GARP_MESSAGE(type=1, attrs=[
        GARP_ATTRIBUTE(event=2) / GMRP_GROUP(addr="01:00:5e:7f:00:0a"),
    ])])
    pdu = decode_garp(raw(g), "GMRP")
    check("scapy GMRP: group MAC decodes",
          pdu.attributes and pdu.attributes[0].as_mac() == "01:00:5e:7f:00:0a",
          str([a.as_mac() for a in pdu.attributes]))

    # Multi-message PDU - exercises the message-level end mark.
    g = GARP(msgs=[
        GARP_MESSAGE(type=1, attrs=[
            GARP_ATTRIBUTE(event=2) / GVRP(vlan=100)]),
        GARP_MESSAGE(type=1, attrs=[
            GARP_ATTRIBUTE(event=2) / GVRP(vlan=200)]),
    ])
    pdu = decode_garp(raw(g), "GVRP")
    check("scapy GVRP: multi-message PDU",
          [a.as_vlan() for a in pdu.attributes] == [100, 200],
          str([a.as_vlan() for a in pdu.attributes]))

    # Full frame through classify(), as it would arrive off a tap.
    frame = dot3_garp(DST_MVRP, SRC, raw(GARP(msgs=[
        GARP_MESSAGE(type=1, attrs=[
            GARP_ATTRIBUTE(event=2) / GVRP(vlan=42)])])))
    proto, src, payload, note = classify(frame)
    check("classify: 802.3+LLC to :21 is GVRP", proto == "GVRP", str(proto))
    check("classify: source MAC extracted", src == SRC, src)
    check("classify: GVRP payload round-trips",
          decode_garp(payload, "GVRP").attributes[0].as_vlan() == 42)


# ---------------------------------------------------------------------------
# Tier 3 - structural / malformed
# ---------------------------------------------------------------------------

def tier3():
    print("\nTier 3 - structural defects")

    def codes(pdu):
        return [c for c, _ in pdu.structural]

    # MRP-120: NumberOfValues claims more events than bytes remain.
    bad = bytes([0, 1, 2]) + struct.pack("!H", 300) + b"\x00\x64" + b"\x2b"
    check("MRP-120 NumberOfValues overrun",
          "MRP-120" in codes(decode_mrp(bad, "MVRP")))
    FIRED.add("MRP-120")

    # MRP-120: FirstValue itself overruns.
    bad = bytes([0, 2, 6]) + struct.pack("!H", 1) + b"\x01\x02"
    check("MRP-120 FirstValue overrun",
          "MRP-120" in codes(decode_mrp(bad, "MMRP")))

    # MRP-125: vector byte >= 216 is not a valid base-6 trio.
    bad = bytes([0, 1, 2]) + struct.pack("!H", 3) + b"\x00\x64" + b"\xff"
    check("MRP-125 vector byte 0xff rejected",
          "MRP-125" in codes(decode_mrp(bad, "MVRP")))
    FIRED.add("MRP-125")

    # 215 is the largest valid byte (5,5,5); 216 is the first invalid one.
    ok = mrp_pdu(1, 2, [mrp_vecattr(3, [5, 5, 5], b"\x00\x01")])
    check("boundary: 0xd7 (215) accepted",
          decode_mrp(ok, "MVRP").structural == [] and ok[7] == 215, hex(ok[7]))

    # MRP-121: PDU with no EndMark, strict mode.
    bad = mrp_pdu(1, 2, [mrp_vecattr(1, [1], b"\x00\x05")], end=False)
    check("MRP-121 missing EndMark under strict",
          "MRP-121" in codes(decode_mrp(bad, "MVRP", strict=True)))
    check("MRP-121 silent when not strict",
          "MRP-121" not in codes(decode_mrp(bad, "MVRP", strict=False)))
    FIRED.add("MRP-121")

    # MRP-124: nonzero ProtocolVersion.
    bad = bytes([3]) + mrp_pdu(1, 2, [mrp_vecattr(1, [1], b"\x00\x05")])[1:]
    check("MRP-124 unexpected version",
          "MRP-124" in codes(decode_mrp(bad, "MVRP")))
    FIRED.add("MRP-124")

    # MRP-122: GARP attribute length overruns the PDU.
    bad = struct.pack("!H", 1) + bytes([1, 99, 2]) + b"\x00\x0a"
    check("MRP-122 GARP length overrun",
          "MRP-122" in codes(decode_garp(bad, "GVRP")))
    FIRED.add("MRP-122")

    # MRP-122: event byte outside the 0-5 enum.
    bad = struct.pack("!H", 1) + bytes([1, 4, 9]) + b"\x00\x0a"
    check("MRP-122 GARP bad event enum",
          "MRP-122" in codes(decode_garp(bad, "GVRP")))

    # MRP-122: attribute length < 2 is structurally impossible.
    bad = struct.pack("!H", 1) + bytes([1, 1, 2])
    check("MRP-122 GARP length < 2",
          "MRP-122" in codes(decode_garp(bad, "GVRP")))

    # MRP-123: GARP PDU with no end mark, strict mode.
    bad = struct.pack("!H", 1) + bytes([1, 4, 2]) + b"\x00\x0a"
    check("MRP-123 missing GARP end mark under strict",
          "MRP-123" in codes(decode_garp(bad, "GVRP", strict=True)))
    FIRED.add("MRP-123")

    # Truncation must not raise - a passive tap sees cut frames routinely.
    for n in range(1, 12):
        try:
            decode_mrp(mrp_pdu(1, 2, [mrp_vecattr(3, [1, 1, 1], b"\x00\x64")])[:n],
                       "MVRP")
            decode_garp(struct.pack("!H", 1) + bytes([1, 3, 2, 0, 10])[:n], "GVRP")
        except Exception as e:  # DecodeError is caught by the analyzer, not raised here
            from mrpwatch import DecodeError
            if not isinstance(e, DecodeError):
                check(f"truncation at {n} bytes does not crash", False, repr(e))
                return
    check("truncation at every length is handled", True)


# ---------------------------------------------------------------------------
# Tier 4 - behavioural
# ---------------------------------------------------------------------------

def tier4():
    print("\nTier 4 - behavioural (flood, burst, posture)")

    # MRP-001 + MRP-006 on first MVRP sighting
    w = MrpWatch()
    f = record(w.feed(eth2(DST_MVRP, SRC, ETHERTYPE_MVRP,
                           mrp_pdu(1, 2, [mrp_vecattr(1, [1], b"\x00\x64")])), 0.0))
    check("MRP-001 MVRP first sight", "MRP-001" in [x.code for x in f])
    check("MRP-006 baseline note emitted", "MRP-006" in [x.code for x in f])
    check("posture codes fire once only",
          "MRP-001" not in [x.code for x in record(w.feed(
              eth2(DST_MVRP, SRC, ETHERTYPE_MVRP,
                   mrp_pdu(1, 2, [mrp_vecattr(1, [1], b"\x00\x64")])), 1.0))])

    # MRP-002 MMRP, and note it rides a DIFFERENT EtherType
    w = MrpWatch()
    f = record(w.feed(eth2(DST_MMRP, SRC, ETHERTYPE_MMRP,
                           mrp_pdu(2, 6, [mrp_vecattr(1, [1], mac("01:00:5e:00:00:01"))])), 0.0))
    check("MRP-002 MMRP first sight on 0x88F6", "MRP-002" in [x.code for x in f])
    # The same frame on MVRP's EtherType must NOT be classified as MMRP.
    proto, _, _, _ = classify(eth2(DST_MMRP, SRC, ETHERTYPE_MVRP, b"\x00\x00\x00"))
    check("0x88F5 never classifies as MMRP", proto == "MVRP", str(proto))

    # MRP-101 LeaveAll flood
    w = MrpWatch(Config(leaveall_threshold=5, leaveall_window_s=10.0))
    fired = False
    for i in range(6):
        f = record(w.feed(eth2(DST_MVRP, SRC, ETHERTYPE_MVRP,
                               mrp_pdu(1, 2, [mrp_vecattr(0, [], b"", leaveall=True)])),
                          float(i)))
        fired |= "MRP-101" in [x.code for x in f]
    check("MRP-101 LeaveAll flood fires at threshold", fired)

    # Window must expire - same count spread over 100s must not fire.
    w = MrpWatch(Config(leaveall_threshold=5, leaveall_window_s=10.0))
    fired = False
    for i in range(6):
        f = record(w.feed(eth2(DST_MVRP, SRC, ETHERTYPE_MVRP,
                               mrp_pdu(1, 2, [mrp_vecattr(0, [], b"", leaveall=True)])),
                          float(i * 100)))
        fired |= "MRP-101" in [x.code for x in f]
    check("LeaveAll window expires correctly", not fired)

    # MRP-102 new-VLAN burst, with known_vlans escalating severity
    w = MrpWatch(Config(newattr_threshold=10, known_vlans={1, 10, 100}))
    f = record(w.feed(eth2(DST_MVRP, SRC, ETHERTYPE_MVRP,
                           mrp_pdu(1, 2, [mrp_vecattr(30, [1] * 30, b"\x01\xf4")])), 0.0))
    hits = [x for x in f if x.code == "MRP-102"]
    check("MRP-102 new-VLAN burst fires", bool(hits))
    check("known_vlans escalates to HIGH",
          hits and hits[0].severity == "HIGH",
          hits[0].severity if hits else "none")

    # Detection is NOT gated by the baseline - same burst, no known_vlans.
    w = MrpWatch(Config(newattr_threshold=10))
    f = record(w.feed(eth2(DST_MVRP, SRC, ETHERTYPE_MVRP,
                           mrp_pdu(1, 2, [mrp_vecattr(30, [1] * 30, b"\x01\xf4")])), 0.0))
    hits = [x for x in f if x.code == "MRP-102"]
    check("burst still detected without baseline", bool(hits))
    check("severity stays MEDIUM without baseline",
          hits and hits[0].severity == "MEDIUM",
          hits[0].severity if hits else "none")

    # Re-declaring already-seen VLANs is normal churn, not a burst.
    f = record(w.feed(eth2(DST_MVRP, SRC, ETHERTYPE_MVRP,
                           mrp_pdu(1, 2, [mrp_vecattr(30, [1] * 30, b"\x01\xf4")])), 1.0))
    check("repeat declarations do not re-fire burst",
          "MRP-102" not in [x.code for x in f])

    # Non-declaring events (Lv/Mt) must not count as registrations.
    w = MrpWatch(Config(newattr_threshold=3))
    f = record(w.feed(eth2(DST_MVRP, SRC, ETHERTYPE_MVRP,
                           mrp_pdu(1, 2, [mrp_vecattr(30, [5] * 30, b"\x01\xf4")])), 0.0))
    check("Lv events do not trigger registration burst",
          "MRP-102" not in [x.code for x in f])

    # Latching: a sustained flood is ONE alert, not one per frame.
    w = MrpWatch(Config(leaveall_threshold=3, leaveall_window_s=60.0))
    n = 0
    for i in range(12):
        f = record(w.feed(eth2(DST_MVRP, SRC, ETHERTYPE_MVRP,
                               mrp_pdu(1, 2, [mrp_vecattr(0, [], b"", leaveall=True)])),
                          float(i)))
        n += sum(1 for x in f if x.code == "MRP-101")
    check("sustained flood emits exactly one MRP-101", n == 1, f"emitted {n}")

    # ...and it re-arms once the window drains below threshold.
    w = MrpWatch(Config(leaveall_threshold=3, leaveall_window_s=5.0))
    n = 0
    for t in (0, 1, 2, 3, 100, 101, 102, 103):
        f = record(w.feed(eth2(DST_MVRP, SRC, ETHERTYPE_MVRP,
                               mrp_pdu(1, 2, [mrp_vecattr(0, [], b"", leaveall=True)])),
                          float(t)))
        n += sum(1 for x in f if x.code == "MRP-101")
    check("latch re-arms after window drains", n == 2, f"emitted {n}")

    # Burst latching likewise.
    w = MrpWatch(Config(newattr_threshold=5, newattr_window_s=60.0))
    n = 0
    for i in range(6):
        pdu_ = mrp_pdu(1, 2, [mrp_vecattr(10, [1] * 10, struct.pack("!H", 1000 + i * 10))])
        f = record(w.feed(eth2(DST_MVRP, SRC, ETHERTYPE_MVRP, pdu_), float(i)))
        n += sum(1 for x in f if x.code == "MRP-102")
    check("sustained new-VLAN burst emits exactly one MRP-102", n == 1, f"emitted {n}")

    # MRP-103 / MRP-104 MMRP twins
    w = MrpWatch(Config(leaveall_threshold=3, newattr_threshold=5))
    fired = set()
    for i in range(4):
        for x in record(w.feed(eth2(DST_MMRP, SRC, ETHERTYPE_MMRP,
                                    mrp_pdu(2, 6, [mrp_vecattr(0, [], b"", leaveall=True)])),
                               float(i))):
            fired.add(x.code)
    check("MRP-103 MMRP LeaveAll flood", "MRP-103" in fired)
    f = record(w.feed(eth2(DST_MMRP, SRC, ETHERTYPE_MMRP,
                           mrp_pdu(2, 6, [mrp_vecattr(10, [0] * 10, mac("01:00:5e:01:00:01"))])),
                      5.0))
    check("MRP-104 MMRP group burst", "MRP-104" in [x.code for x in f])

    # Legacy twins via scapy-built GARP
    from scapy.contrib.gxrp import GARP, GARP_ATTRIBUTE, GARP_MESSAGE, GMRP_GROUP, GVRP
    from scapy.packet import raw

    w = MrpWatch(Config(leaveall_threshold=3, newattr_threshold=4))
    fired = set()
    for i in range(4):
        pay = raw(GARP(msgs=[GARP_MESSAGE(type=1, attrs=[
            GARP_ATTRIBUTE(event=0) / GVRP(vlan=0)])]))
        for x in record(w.feed(dot3_garp(DST_MVRP, SRC, pay), float(i))):
            fired.add(x.code)
    check("MRP-003 GVRP posture", "MRP-003" in fired)
    check("MRP-105 GVRP LeaveAll flood", "MRP-105" in fired)

    pay = raw(GARP(msgs=[GARP_MESSAGE(type=1, attrs=[
        GARP_ATTRIBUTE(event=1) / GVRP(vlan=v) for v in range(500, 510)])]))
    f = record(w.feed(dot3_garp(DST_MVRP, SRC, pay), 5.0))
    check("MRP-106 GVRP new-VLAN burst", "MRP-106" in [x.code for x in f])

    w2 = MrpWatch(Config(leaveall_threshold=2, newattr_threshold=3))
    fired = set()
    for i in range(3):
        pay = raw(GARP(msgs=[GARP_MESSAGE(type=1, attrs=[
            GARP_ATTRIBUTE(event=0) / GMRP_GROUP(addr="00:00:00:00:00:00")])]))
        for x in record(w2.feed(dot3_garp(DST_MMRP, SRC, pay), float(i))):
            fired.add(x.code)
    check("MRP-004 GMRP posture", "MRP-004" in fired)
    check("MRP-107 GMRP LeaveAll flood", "MRP-107" in fired)

    pay = raw(GARP(msgs=[GARP_MESSAGE(type=1, attrs=[
        GARP_ATTRIBUTE(event=2) / GMRP_GROUP(addr=f"01:00:5e:00:00:{i:02x}")
        for i in range(10)])]))
    f = record(w2.feed(dot3_garp(DST_MMRP, SRC, pay), 5.0))
    check("MRP-108 GMRP group burst", "MRP-108" in [x.code for x in f])

    # MRP-005 mixed generation on one segment
    w = MrpWatch()
    record(w.feed(eth2(DST_MVRP, SRC, ETHERTYPE_MVRP,
                       mrp_pdu(1, 2, [mrp_vecattr(1, [1], b"\x00\x64")])), 0.0))
    pay = raw(GARP(msgs=[GARP_MESSAGE(type=1, attrs=[
        GARP_ATTRIBUTE(event=2) / GVRP(vlan=10)])]))
    f = record(w.feed(dot3_garp(DST_MVRP, SRC, pay), 1.0))
    check("MRP-005 mixed modern+legacy", "MRP-005" in [x.code for x in f])

    # MRP-007 unknown GARP application in the :22-:2f block
    w = MrpWatch()
    f = record(w.feed(dot3_garp("01:80:c2:00:00:25", SRC, b"\x00\x01\x00"), 0.0))
    check("MRP-007 unknown GARP application", "MRP-007" in [x.code for x in f])

    # Per-source isolation: two talkers must not pool into one flood.
    w = MrpWatch(Config(leaveall_threshold=4))
    fired = False
    for i in range(3):
        for s in ("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"):
            f = record(w.feed(eth2(DST_MVRP, s, ETHERTYPE_MVRP,
                                   mrp_pdu(1, 2, [mrp_vecattr(0, [], b"", leaveall=True)])),
                              float(i)))
            fired |= "MRP-101" in [x.code for x in f]
    check("flood counters are per-source", not fired)

    # Non-MRP traffic is ignored entirely.
    w = MrpWatch()
    check("IPv4 frame produces nothing",
          w.feed(eth2("ff:ff:ff:ff:ff:ff", SRC, 0x0800, b"\x45" + b"\x00" * 30), 0.0) == [])
    check("LLC frame to a non-GARP MAC produces nothing",
          w.feed(dot3_garp("01:80:c2:00:00:00", SRC, b"\x00\x01\x00"), 0.0) == [])


# ---------------------------------------------------------------------------
# Tier 5 - registry coverage
# ---------------------------------------------------------------------------

def tier5():
    print("\nTier 5 - registry coverage")
    missing = sorted(set(REGISTRY) - FIRED)
    check(f"all {len(REGISTRY)} declared codes fired in validation",
          not missing, f"never fired: {missing}")
    for code, c in sorted(REGISTRY.items()):
        assert c.severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"), code
    check("all severities are valid", True)


if __name__ == "__main__":
    tier1(); tier2(); tier3(); tier4(); tier5()
    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        for f in FAIL:
            print(f"  FAILED: {f}")
    sys.exit(1 if FAIL else 0)
