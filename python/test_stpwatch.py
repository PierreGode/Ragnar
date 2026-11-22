#!/usr/bin/env python3
"""stpwatch self-test harness.

Pure offline: crafts BPDUs, feeds the parser and analyzer directly, and
cross-validates the decoder against Scapy's STP dissector. No NIC, no root,
no frame ever leaves the process.

    python3 test_stpwatch.py           # run all
    python3 test_stpwatch.py -v        # show every check
"""
from __future__ import annotations

import io
import json
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import stpwatch as S
from stpwatch import Analyzer, BPDU, ParseError, parse_frame, pcap_frames

from scapy.layers.l2 import Dot3, LLC, STP  # noqa: E402
from scapy.packet import Raw  # noqa: E402

VERBOSE = "-v" in sys.argv

IEEE_DST = b"\x01\x80\xc2\x00\x00\x00"
PVST_DST = b"\x01\x00\x0c\xcc\xcc\xcd"
SNAP_HDR = b"\xaa\xaa\x03\x00\x00\x0c\x01\x0b"
LLC_HDR = b"\x42\x42\x03"

DEF_ROOT = (32768, "00:11:22:33:44:55")
DEF_BRIDGE = (32768, "00:aa:bb:cc:dd:ee")


# --------------------------------------------------------------------------
# frame construction
# --------------------------------------------------------------------------

def macb(m: str) -> bytes:
    return bytes.fromhex(m.replace(":", ""))


def bid(prio: int, mac: str) -> bytes:
    return struct.pack("!H", prio) + macb(mac)


def config_body(version=0, btype=0, flags=0, root=DEF_ROOT, cost=4,
                bridge=DEF_BRIDGE, portid=0x8001, age=1.0, maxage=20.0,
                hello=2.0, fwd=15.0, proto=0) -> bytes:
    b = struct.pack("!HBBB", proto, version, btype, flags)
    b += bid(*root) + struct.pack("!I", cost) + bid(*bridge) + struct.pack("!H", portid)
    b += struct.pack("!HHHH", int(age * 256), int(maxage * 256),
                     int(hello * 256), int(fwd * 256))
    assert len(b) == 35, len(b)
    return b


def rstp_body(**kw) -> bytes:
    kw.setdefault("version", 2)
    kw.setdefault("btype", 2)
    return config_body(**kw) + b"\x00"


def msti_record(mstid=1, prio=32768, mac="00:11:22:33:44:55", cost=20000,
                flags=0x3C, bridge_prio=0x80, port_prio=0x80, hops=20) -> bytes:
    """One 16-octet MSTI Configuration Message (802.1Q-2018 Table 14-1).

    The instance number lives in the low 12 bits of the Regional Root
    Identifier, so `prio` is the 4-bit priority and `mstid` the sysid-ext.
    """
    r = struct.pack("!B", flags)
    r += struct.pack("!H", (prio & 0xF000) | (mstid & 0x0FFF)) + macb(mac)
    r += struct.pack("!I", cost)
    r += struct.pack("!BBB", bridge_prio, port_prio, hops)
    assert len(r) == 16, len(r)
    return r


def mst_body(region="CORE", revision=1, digest=b"\xaa" * 16, msti=0,
             records=None, v3len=None, trailer=b"", **kw) -> bytes:
    """MSTP BPDU. `records` takes real MSTI records; `msti` is a count shortcut."""
    kw.setdefault("version", 3)
    kw.setdefault("btype", 2)
    base = config_body(**kw) + b"\x00"                 # + version-1 length
    if records is None:
        records = [msti_record(mstid=i + 1) for i in range(msti)]
    blob = b"".join(records)
    if v3len is None:
        v3len = 64 + 16 * len(records)
    cfg = b"\x00" + region.encode().ljust(32, b"\x00") + struct.pack("!H", revision) + digest
    assert len(cfg) == 51, len(cfg)
    cist = struct.pack("!I", 0) + bid(*DEF_BRIDGE) + b"\x14"
    return base + struct.pack("!H", v3len) + cfg + cist + blob + trailer


def frame(body: bytes, dst=IEEE_DST, src="00:aa:bb:cc:dd:ee", tags=(),
          snap=False, pad=True) -> bytes:
    payload = (SNAP_HDR if snap else LLC_HDR) + body
    t = b"".join(struct.pack("!HH", tpid, vid) for tpid, vid in tags)
    f = dst + macb(src) + t + struct.pack("!H", len(payload)) + payload
    if pad and len(f) < 60:
        f += b"\x00" * (60 - len(f))
    return f


def pvst_frame(vlan=100, body=None, tags=None, **kw) -> bytes:
    body = body if body is not None else config_body()
    body += struct.pack("!HHH", 0x0000, 0x0002, vlan)
    tags = tags if tags is not None else ((0x8100, vlan),)
    return frame(body, dst=PVST_DST, tags=tags, snap=True, **kw)


def tcn_frame(**kw) -> bytes:
    return frame(struct.pack("!HBB", 0, 0, 0x80), **kw)


# --------------------------------------------------------------------------
# harness
# --------------------------------------------------------------------------

class T:
    def __init__(self):
        self.n = 0
        self.fails = []

    def check(self, name, cond, detail=""):
        self.n += 1
        ok = bool(cond)
        if not ok:
            self.fails.append((name, detail))
        if VERBOSE or not ok:
            print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  <- {detail}" if detail and not ok else ""))

    def report(self):
        passed = self.n - len(self.fails)
        print(f"\n{passed}/{self.n} self-tests passed")
        for name, d in self.fails:
            print(f"  FAILED: {name} {d}")
        return 0 if not self.fails else 1


t = T()


def ids(findings):
    return [f.id for f in findings]


def an(**kw) -> Analyzer:
    kw.setdefault("start_ts", 0.0)
    return Analyzer(**kw)


def feed(a: Analyzer, raw: bytes, ts: float, iface="eth0"):
    p = parse_frame(raw, iface, ts)
    assert p is not None
    return a.process(p)


# --------------------------------------------------------------------------
# 1. Parsing
# --------------------------------------------------------------------------
print("-- parser --")

p = parse_frame(frame(config_body()), "eth0", 1.0)
t.check("parse: IEEE config BPDU decodes", p is not None and p.encap == "ieee")
t.check("parse: root bridge id", str(p.root) == "32768/0/00:11:22:33:44:55", str(p.root))
t.check("parse: path cost", p.path_cost == 4)
t.check("parse: timers in seconds", (p.hello_time, p.max_age, p.forward_delay) == (2.0, 20.0, 15.0))
t.check("parse: port id decomposition", (p.port_priority, p.port_number) == (8, 1))
t.check("parse: not a TCN", not p.is_tcn and not p.tc)

p = parse_frame(frame(rstp_body(flags=0x3E)), "eth0", 1.0)
t.check("parse: RSTP version/type", p.version == 2 and p.bpdu_type == 2)
t.check("parse: RSTP port role decode", p.port_role == "designated", p.port_role)
t.check("parse: RSTP proposal flag", p.proposal and not p.agreement)
t.check("parse: RSTP learning/forwarding flags", p.flags & S.FLAG_LEARNING and p.flags & S.FLAG_FORWARDING)
t.check("parse: RSTP reserved-bit rule not applied to v2", not p.parse_anomalies, p.parse_anomalies)
t.check("parse: RSTP agreement flag",
        parse_frame(frame(rstp_body(flags=0x40)), "eth0", 1.0).agreement)

p = parse_frame(frame(mst_body(region="CORE", revision=7, digest=b"\x11" * 16, msti=3)), "eth0", 1.0)
t.check("parse: MSTP region name", p.mst and p.mst["region_name"] == "CORE")
t.check("parse: MSTP revision", p.mst["revision"] == 7)
t.check("parse: MSTP digest", p.mst["digest"] == "11" * 16)
t.check("parse: MSTP MSTI record count", p.mst["msti_count"] == 3, p.mst["msti_count"])
t.check("parse: MSTP remaining hops", p.mst["remaining_hops"] == 20)

# --- MSTI record deserialization (the gap this build closes) --------------
recs = [
    msti_record(mstid=10, prio=32768, mac="00:11:22:33:44:55", cost=20000,
                flags=0x3C, bridge_prio=0x80, port_prio=0x70, hops=19),
    msti_record(mstid=20, prio=4096, mac="aa:bb:cc:dd:ee:ff", cost=0,
                flags=0x01, bridge_prio=0x10, port_prio=0x80, hops=20),
]
p = parse_frame(frame(mst_body(region="CORE", records=recs)), "eth0", 1.0)
m = p.mst["mstis"]
t.check("msti: both records deserialized", len(m) == 2, len(m))
t.check("msti: MSTID read from regional-root sysid-ext",
        [r["mstid"] for r in m] == [10, 20], [r["mstid"] for r in m])
t.check("msti: regional root MAC", m[0]["regional_root_mac"] == "00:11:22:33:44:55")
t.check("msti: regional root priority", m[0]["regional_root"]["priority"] == 32768)
t.check("msti: internal root path cost", m[0]["internal_root_path_cost"] == 20000)
t.check("msti: bridge priority from top nibble", m[0]["bridge_priority"] == 32768,
        m[0]["bridge_priority"])
t.check("msti: port priority from top nibble", m[0]["port_priority"] == 28672,
        m[0]["port_priority"])
t.check("msti: remaining hops per record",
        [r["remaining_hops"] for r in m] == [19, 20])
t.check("msti: port role decoded from record flags",
        m[0]["port_role"] == "designated", m[0]["port_role"])
t.check("msti: learning/forwarding flags", m[0]["learning"] and m[0]["forwarding"])
t.check("msti: TC flag on second record", m[1]["tc"] and not m[0]["tc"])
t.check("msti: bit 7 decoded as Master, not TCA",
        not m[0]["master"] and parse_frame(
            frame(mst_body(records=[msti_record(mstid=5, flags=0x80)])),
            "eth0", 1.0).mst["mstis"][0]["master"])
t.check("msti: second record keeps its own low priority",
        m[1]["regional_root"]["raw_priority"] == 4096 + 20,
        m[1]["regional_root"]["raw_priority"])
t.check("msti: clean records produce no record anomalies",
        p.mst["msti_anomalies"] == [], p.mst["msti_anomalies"])
t.check("msti: declared count recorded", p.mst["msti_declared"] == 2)

# structural faults the parser must notice
p = parse_frame(frame(mst_body(records=[msti_record(mstid=0)])), "eth0", 1.0)
t.check("msti: MSTID 0 flagged (CIST is not an MSTI)",
        any("outside" in a for a in p.mst["msti_anomalies"]), p.mst["msti_anomalies"])
p = parse_frame(frame(mst_body(records=[msti_record(mstid=7), msti_record(mstid=7)])), "eth0", 1.0)
t.check("msti: duplicate MSTID flagged",
        any("duplicates" in a for a in p.mst["msti_anomalies"]), p.mst["msti_anomalies"])
p = parse_frame(frame(mst_body(records=[msti_record(mstid=1)], v3len=64 + 32)), "eth0", 1.0)
t.check("msti: declared-vs-present mismatch flagged",
        any("only 1 present" in a for a in p.mst["msti_anomalies"]), p.mst["msti_anomalies"])
p = parse_frame(frame(mst_body(records=[msti_record(mstid=1)], trailer=b"\x00" * 5)), "eth0", 1.0)
t.check("msti: trailing octets flagged",
        any("trailing" in a for a in p.mst["msti_anomalies"]), p.mst["msti_anomalies"])
p = parse_frame(frame(mst_body(records=[msti_record(mstid=1, bridge_prio=0x85)])), "eth0", 1.0)
t.check("msti: non-zero priority low nibble flagged",
        any("low nibble" in a for a in p.mst["msti_anomalies"]), p.mst["msti_anomalies"])
p = parse_frame(frame(mst_body(msti=0)), "eth0", 1.0)
t.check("msti: zero-instance MSTP BPDU parses clean",
        p.mst["mstis"] == [] and p.mst["msti_anomalies"] == [])

p = parse_frame(pvst_frame(vlan=100), "eth0", 1.0)
t.check("parse: PVST+ SNAP encap", p.encap == "pvst")
t.check("parse: PVST+ VLAN from TLV", p.vlan == 100)

p = parse_frame(tcn_frame(), "eth0", 1.0)
t.check("parse: TCN decodes and stops", p.is_tcn and p.root is None)

p = parse_frame(frame(config_body(), tags=((0x88A8, 10), (0x8100, 20))), "eth0", 1.0)
t.check("parse: QinQ tag stack", p.tags == [(0x88A8, 10), (0x8100, 20)] and p.vlan == 20)

t.check("parse: non-BPDU destination ignored",
        parse_frame(b"\xff" * 6 + macb("00:11:22:33:44:55") + b"\x08\x06" + b"\x00" * 40, "eth0", 1.0) is None)
t.check("parse: EtherType frame to bridge group ignored",
        parse_frame(IEEE_DST + macb("00:11:22:33:44:55") + b"\x08\x00" + b"\x00" * 40, "eth0", 1.0) is None)

try:
    parse_frame(frame(b"\x00\x00\x00", pad=False), "eth0", 1.0)
    t.check("parse: truncated BPDU raises", False)
except ParseError:
    t.check("parse: truncated BPDU raises", True)

try:
    parse_frame(frame(config_body(), tags=((0x8100, 1), (0x8100, 2), (0x8100, 3))), "eth0", 1.0)
    t.check("parse: excessive tag stack raises", False)
except ParseError:
    t.check("parse: excessive tag stack raises", True)

# Cross-validate against Scapy's dissector.
raw = frame(config_body(root=(4096, "de:ad:be:ef:00:01"), cost=19,
                        bridge=(32768, "00:aa:bb:cc:dd:ee")))
sp = Dot3(raw)
mine = parse_frame(raw, "eth0", 1.0)
t.check("scapy: layer chain Dot3/LLC/STP", sp.haslayer(STP))
t.check("scapy: root mac agrees", sp[STP].rootmac == S.mac_str(mine.root.mac), sp[STP].rootmac)
t.check("scapy: root priority agrees", sp[STP].rootid == mine.root.raw_priority)
t.check("scapy: path cost agrees", sp[STP].pathcost == mine.path_cost)
t.check("scapy: bridge mac agrees", sp[STP].bridgemac == S.mac_str(mine.bridge.mac))
t.check("scapy: hello time agrees", abs(sp[STP].hellotime - mine.hello_time) < 1e-6)


# --------------------------------------------------------------------------
# 2. Detections
# --------------------------------------------------------------------------
print("\n-- detections --")

# STP-001 / STP-002 / STP-003 / STP-019
a = an()
feed(a, frame(config_body(root=DEF_ROOT)), 100.0)
f = feed(a, frame(config_body(root=(36864, "00:99:88:77:66:55"))), 101.0)
t.check("STP-001 root change", "STP-001" in ids(f), ids(f))
t.check("STP-019 two roots inside window", "STP-019" in ids(f), ids(f))

a = an(baseline={"roots": {"eth0|0": {"raw_priority": 32768, "mac": "00:11:22:33:44:55"}}})
f = feed(a, frame(config_body(root=(8192, "00:00:00:00:00:01"),
                              bridge=(8192, "00:00:00:00:00:01"), cost=0)), 100.0)
t.check("STP-002 superior BPDU vs baseline root", "STP-002" in ids(f), ids(f))
t.check("STP-002 is CRITICAL", any(x.severity == "CRITICAL" for x in f if x.id == "STP-002"))
t.check("STP-002 no false ZERO_PATH_COST when sender is the claimed root", "STP-015" not in ids(f))

a = an(thresholds={"cooldown": 0.0})
feed(a, frame(config_body(root=(32768, "00:00:00:00:00:01"))), 100.0)
got = []
for i, mac in enumerate(["00:00:00:00:00:02", "00:00:00:00:00:03", "00:00:00:00:00:04"]):
    got += feed(a, frame(config_body(root=(32768, mac))), 101.0 + i)
t.check("STP-003 root flap", "STP-003" in ids(got), ids(got))

# STP-004
a = an(baseline={"roots": {"eth0|0": {"raw_priority": 32768, "mac": "00:11:22:33:44:55"}},
                 "bridges": {"32768/0/00:aa:bb:cc:dd:ee": {}}})
f = feed(a, frame(config_body(bridge=(32768, "00:aa:bb:cc:dd:ee"))), 100.0)
t.check("STP-004 quiet for baselined bridge", "STP-004" not in ids(f), ids(f))
f = feed(a, frame(config_body(bridge=(32768, "de:ad:be:ef:ca:fe")), src="de:ad:be:ef:ca:fe"), 101.0)
t.check("STP-004 new bridge", "STP-004" in ids(f), ids(f))

# STP-005
a = an(edge_ifaces=["eth9"])
f = feed(a, frame(config_body()), 100.0, iface="eth9")
t.check("STP-005 BPDU on declared edge port", "STP-005" in ids(f), ids(f))
t.check("STP-005 is CRITICAL", [x.severity for x in f if x.id == "STP-005"] == ["CRITICAL"])
f = feed(a, frame(config_body()), 100.0, iface="eth0")
t.check("STP-005 quiet on trunk port", "STP-005" not in ids(f))

# STP-006
a = an()
got = []
for i in range(6):
    got += feed(a, tcn_frame(), 100.0 + i)
t.check("STP-006 TCN flood", "STP-006" in ids(got), ids(got))

# STP-007
a = an()
got = []
for i in range(4):
    got += feed(a, frame(config_body(flags=0x01)), 100.0 + i * 11.0)
t.check("STP-007 topology-change episode flood", "STP-007" in ids(got), ids(got))

# STP-008
a = an()
got = []
for i in range(110):
    got += feed(a, frame(config_body()), 100.0 + i * 0.01)
t.check("STP-008 BPDU storm", "STP-008" in ids(got), ids(got))

# STP-009
a = an()
f = feed(a, frame(config_body(root=(0, "00:00:00:00:00:01"), bridge=(0, "00:00:00:00:00:01"), cost=0)), 100.0)
t.check("STP-009 priority-zero root claim", "STP-009" in ids(f), ids(f))

# STP-010
a = an()
f = feed(a, pvst_frame(vlan=100, body=config_body(bridge=(32775, "00:aa:bb:cc:dd:ee"))), 100.0)
t.check("STP-010 sysid-ext does not match VLAN", "STP-010" in ids(f), ids(f))
a = an()
f = feed(a, pvst_frame(vlan=100, body=config_body(bridge=(32768 + 100, "00:aa:bb:cc:dd:ee"))), 100.0)
t.check("STP-010 quiet when sysid-ext == VLAN", "STP-010" not in ids(f), ids(f))
a = an()
f = feed(a, frame(config_body(bridge=(32769, "00:aa:bb:cc:dd:ee"))), 100.0)
t.check("STP-010 quiet on untagged native VLAN (unverifiable)", "STP-010" not in ids(f), ids(f))

# STP-011
a = an()
f = feed(a, frame(config_body(), src="02:11:22:33:44:55"), 100.0)
t.check("STP-011 locally administered source MAC", "STP-011" in ids(f), ids(f))
a = an()
f = feed(a, frame(config_body(), src="01:11:22:33:44:55"), 100.0)
t.check("STP-011 multicast source MAC", "STP-011" in ids(f), ids(f))
a = an()
f = feed(a, frame(config_body(), src="00:aa:bb:cc:dd:ee"), 100.0)
t.check("STP-011 quiet on a normal UAA source", "STP-011" not in ids(f))

# STP-012
a = an()
f = feed(a, frame(config_body(hello=0.0)), 100.0)
t.check("STP-012 hello below legal range", "STP-012" in ids(f), ids(f))
a = an()
f = feed(a, frame(config_body(maxage=39.0, fwd=15.0)), 100.0)
t.check("STP-012 2*(fwd_delay-1) < max_age", "STP-012" in ids(f), ids(f))
a = an()
f = feed(a, frame(config_body()), 100.0)
t.check("STP-012 quiet on default 2/20/15 timers", "STP-012" not in ids(f), ids(f))

# STP-013
a = an()
f = feed(a, frame(config_body(proto=0x0001)), 100.0)
t.check("STP-013 bad protocol identifier", "STP-013" in ids(f), ids(f))
a = an()
f = feed(a, frame(config_body(version=0, flags=0x40)), 100.0)
t.check("STP-013 reserved flag bits set in 802.1D BPDU", "STP-013" in ids(f), ids(f))

# STP-014
a = an()
f = feed(a, frame(config_body(age=25.0, maxage=20.0)), 100.0)
t.check("STP-014 message_age >= max_age", "STP-014" in ids(f), ids(f))
a = an()
f = feed(a, frame(config_body(age=0.0)), 100.0)
t.check("STP-014 zero message_age from non-root", "STP-014" in ids(f), ids(f))

# STP-015
a = an()
f = feed(a, frame(config_body(cost=0)), 100.0)
t.check("STP-015 zero path cost from non-root", "STP-015" in ids(f), ids(f))

# STP-016
a = an()
got = []
for i in range(31):
    got += feed(a, frame(rstp_body(flags=0x02)), 100.0 + i * 0.1)
t.check("STP-016 RSTP proposal flood", "STP-016" in ids(got), ids(got))

# STP-017
a = an()
feed(a, frame(config_body()), 100.0)
f = feed(a, pvst_frame(vlan=100), 100.5)
t.check("STP-017 IEEE and PVST+ on the same interface", "STP-017" in ids(f), ids(f))

# STP-018
a = an()
f = feed(a, frame(config_body(), tags=((0x8100, 100),)), 100.0)
t.check("STP-018 tagged IEEE BPDU", "STP-018" in ids(f), ids(f))
a = an()
f = feed(a, pvst_frame(vlan=100), 100.0)
t.check("STP-018 quiet for tagged PVST+ (expected)", "STP-018" not in ids(f), ids(f))

# STP-020
a = an()
feed(a, frame(config_body()), 100.0)
f = a.tick(200.0)
t.check("STP-020 BPDU silence", "STP-020" in ids(f), ids(f))
t.check("STP-020 fires once, not per tick", "STP-020" not in ids(a.tick(201.0)))

# STP-021 / STP-022
bl = {"roots": {}, "bridges": {}, "mst_regions": {"CORE": {"revision": 1, "digest": "aa" * 16}}}
a = an(baseline=bl)
f = feed(a, frame(mst_body(region="CORE", digest=b"\xbb" * 16)), 100.0)
t.check("STP-021 MST digest mismatch", "STP-021" in ids(f), ids(f))
a = an(baseline=bl)
f = feed(a, frame(mst_body(region="EVIL", digest=b"\xcc" * 16)), 100.0)
t.check("STP-022 unknown MST region", "STP-022" in ids(f), ids(f))
a = an(baseline=bl)
f = feed(a, frame(mst_body(region="CORE", digest=b"\xaa" * 16)), 100.0)
t.check("STP-021/022 quiet for a matching region", not ({"STP-021", "STP-022"} & set(ids(f))), ids(f))


# --- per-MSTI tier (STP-023..031) ----------------------------------------
GOOD = dict(region="CORE", digest=b"\xaa" * 16)


def mstframe(records, **kw):
    kw.setdefault("region", "CORE")
    kw.setdefault("digest", b"\xaa" * 16)
    return frame(mst_body(records=records, **kw))


# a baseline where the region digest MATCHES, so STP-021/022 stay silent and
# only the per-MSTI tier can possibly fire -- this is the whole point.
BL_MST = {"roots": {}, "bridges": {"32768/0/00:aa:bb:cc:dd:ee": {}},
          "mst_regions": {"CORE": {"revision": 1, "digest": "aa" * 16}}}

a = an(baseline=BL_MST)
feed(a, mstframe([msti_record(mstid=10, prio=32768, mac="00:11:22:33:44:55")]), 100.0)
f = feed(a, mstframe([msti_record(mstid=10, prio=32768, mac="00:00:00:00:00:01")]), 101.0)
t.check("STP-023 regional root change", "STP-023" in ids(f), ids(f))
t.check("STP-021/022 stay silent on a correctly-digested region",
        not ({"STP-021", "STP-022"} & set(ids(f))), ids(f))

a = an(baseline=BL_MST)
feed(a, mstframe([msti_record(mstid=10, prio=32768, mac="00:11:22:33:44:55")]), 100.0)
f = feed(a, mstframe([msti_record(mstid=10, prio=8192, mac="00:00:00:00:00:01")]), 131.0)
t.check("STP-024 superior regional root inside an MSTI", "STP-024" in ids(f), ids(f))
t.check("STP-024 is CRITICAL", [x.severity for x in f if x.id == "STP-024"] == ["CRITICAL"])
t.check("STP-024 scoped to the instance",
        [x.vlan for x in f if x.id == "STP-024"] == ["MSTI:10"],
        [x.vlan for x in f if x.id == "STP-024"])

# the CIST fields are untouched throughout, so no CIST-level finding may fire
t.check("per-MSTI forgery leaves the CIST checks silent (the gap this closes)",
        not ({"STP-001", "STP-002", "STP-003", "STP-009", "STP-015"} & set(ids(f))), ids(f))

a = an(baseline=BL_MST, thresholds={"cooldown": 0.0})
feed(a, mstframe([msti_record(mstid=5, mac="00:00:00:00:00:01")]), 100.0)
got = []
for i, mac in enumerate(["00:00:00:00:00:02", "00:00:00:00:00:03", "00:00:00:00:00:04"]):
    got += feed(a, mstframe([msti_record(mstid=5, mac=mac)]), 101.0 + i)
t.check("STP-025 regional root flap", "STP-025" in ids(got), ids(got))

a = an(baseline=BL_MST)
f = feed(a, mstframe([msti_record(mstid=10, prio=0, mac="de:ad:be:ef:00:01")]), 100.0)
t.check("STP-026 priority-zero regional root claim", "STP-026" in ids(f), ids(f))
a = an(baseline=BL_MST)
f = feed(a, mstframe([msti_record(mstid=10, bridge_prio=0x00)]), 100.0)
t.check("STP-026 sub-floor MSTI bridge priority", "STP-026" in ids(f), ids(f))
a = an(baseline=BL_MST)
f = feed(a, mstframe([msti_record(mstid=10)]), 100.0)
t.check("STP-026 quiet at default 32768 priority", "STP-026" not in ids(f), ids(f))

a = an(baseline=BL_MST)
f = feed(a, mstframe([msti_record(mstid=10, cost=0, mac="00:11:22:33:44:55")]), 100.0)
t.check("STP-027 zero internal path cost from a non-root", "STP-027" in ids(f), ids(f))
a = an(baseline=BL_MST)
f = feed(a, mstframe([msti_record(mstid=10, cost=0, mac="00:aa:bb:cc:dd:ee")]), 100.0)
t.check("STP-027 quiet when the sender IS the regional root", "STP-027" not in ids(f), ids(f))

a = an(baseline=BL_MST, thresholds={"cooldown": 0.0})
feed(a, mstframe([msti_record(mstid=10, mac="00:00:00:00:00:01")]), 100.0)
f = feed(a, mstframe([msti_record(mstid=10, mac="00:00:00:00:00:02")]), 101.0)
t.check("STP-028 two regional roots for one MSTI inside the window",
        "STP-028" in ids(f), ids(f))

a = an(baseline=BL_MST)
f = feed(a, mstframe([msti_record(mstid=0)]), 100.0)
t.check("STP-029 malformed MSTI record surfaces as a finding", "STP-029" in ids(f), ids(f))

a = an(baseline=BL_MST)
feed(a, mstframe([msti_record(mstid=10), msti_record(mstid=20)]), 100.0)
f = feed(a, mstframe([msti_record(mstid=10), msti_record(mstid=30)]), 101.0)
t.check("STP-030 instance set changed", "STP-030" in ids(f), ids(f))
ev = [x.evidence for x in f if x.id == "STP-030"][0]
t.check("STP-030 names what was added and removed",
        ev["added"] == [30] and ev["removed"] == [20], ev)
a = an(baseline=BL_MST)
feed(a, mstframe([msti_record(mstid=10), msti_record(mstid=20)]), 100.0)
f = feed(a, mstframe([msti_record(mstid=10), msti_record(mstid=20)]), 101.0)
t.check("STP-030 quiet on a stable instance set", "STP-030" not in ids(f), ids(f))

a = an(baseline=BL_MST)
f = feed(a, mstframe([msti_record(mstid=10, hops=0)]), 100.0)
t.check("STP-031 exhausted hop count", "STP-031" in ids(f), ids(f))
a = an(baseline=BL_MST)
f = feed(a, mstframe([msti_record(mstid=10, hops=40)]), 100.0)
t.check("STP-031 hop count above region maximum", "STP-031" in ids(f), ids(f))
a = an(baseline=BL_MST)
f = feed(a, mstframe([msti_record(mstid=10, hops=20)]), 100.0)
t.check("STP-031 quiet at the default 20 hops", "STP-031" not in ids(f), ids(f))

# instances must not bleed into one another
a = an(baseline=BL_MST)
feed(a, mstframe([msti_record(mstid=10, mac="00:00:00:00:00:01"),
                  msti_record(mstid=20, mac="00:00:00:00:00:02")]), 100.0)
f = feed(a, mstframe([msti_record(mstid=10, mac="00:00:00:00:00:01"),
                      msti_record(mstid=20, mac="00:00:00:00:00:09")]), 101.0)
chg = [x for x in f if x.id == "STP-023"]
t.check("MSTI state is per-instance, not shared",
        len(chg) == 1 and chg[0].vlan == "MSTI:20",
        [(x.id, x.vlan) for x in f])

# a clean multi-instance region must be completely silent
a = an(baseline=BL_MST)
clean = [msti_record(mstid=i, mac=f"00:11:22:33:44:{i:02x}") for i in (1, 2, 3, 10, 20)]
f1 = feed(a, mstframe(clean), 100.0)
f2 = feed(a, mstframe(clean), 102.0)
t.check("clean 5-instance region produces no findings at all",
        not f1 and not f2, ids(f1) + ids(f2))


# --------------------------------------------------------------------------
# 3. Machinery
# --------------------------------------------------------------------------
print("\n-- machinery --")

a = an()
f1 = feed(a, frame(config_body(cost=0)), 100.0)
f2 = feed(a, frame(config_body(cost=0)), 110.0)
t.check("cooldown suppresses duplicate findings", "STP-015" in ids(f1) and "STP-015" not in ids(f2))
f3 = feed(a, frame(config_body(cost=0)), 200.0)
sup = [x for x in f3 if x.id == "STP-015"]
t.check("cooldown re-fires and reports suppression count",
        sup and sup[0].evidence.get("suppressed_since_last") == 1,
        sup[0].evidence if sup else None)

t.check("bridge id ordering: lower priority is superior",
        S.BridgeID(4096, b"\xff" * 6).key() < S.BridgeID(32768, b"\x00" * 6).key())
t.check("bridge id ordering: equal priority breaks on MAC",
        S.BridgeID(32768, b"\x00" * 6).key() < S.BridgeID(32768, b"\x00" * 5 + b"\x01").key())

a = an(learning=True)
feed(a, frame(config_body()), 100.0)
feed(a, frame(mst_body(region="CORE", digest=b"\xaa" * 16)), 101.0)
a._seen_regions = {"CORE": {"revision": 1, "digest": "aa" * 16}}
bl = a.build_baseline()
bl2 = json.loads(json.dumps(bl))
t.check("baseline roundtrips through JSON", bl2["roots"] and bl2["bridges"])
a2 = an(baseline=bl2)
t.check("baseline root reloads as a BridgeID",
        isinstance(next(iter(a2._bl_roots.values())), S.BridgeID))
t.check("baselined analyzer skips the grace period", a2._past_grace(0.0))

rows = a.health()
t.check("health table has one row per segment", len(rows) == 2, rows)
t.check("health table reports the root", rows[0]["root"] != "-")

# --- per-MSTI baseline + health ------------------------------------------
a = an(learning=True)
feed(a, mstframe([msti_record(mstid=10, mac="00:11:22:33:44:55"),
                  msti_record(mstid=20, mac="00:11:22:33:44:66")]), 100.0)
a._seen_regions = {"CORE": {"revision": 1, "digest": "aa" * 16}}
bl = json.loads(json.dumps(a.build_baseline()))
t.check("baseline carries per-MSTI regional roots", len(bl["msti_roots"]) == 2, bl["msti_roots"])
t.check("baseline MSTI key is iface|region|mstid",
        "eth0|CORE|10" in bl["msti_roots"], list(bl["msti_roots"]))

a2 = an(baseline=bl)
t.check("baselined MSTI roots reload as BridgeIDs",
        isinstance(next(iter(a2._bl_msti_roots.values())), S.BridgeID))
t.check("MSTI baseline alone skips the grace period", a2._past_grace(0.0))
f = feed(a2, mstframe([msti_record(mstid=10, prio=0, mac="00:00:00:00:00:01")]), 0.0)
t.check("STP-024 fires against a baselined MSTI root with no warm-up",
        "STP-024" in ids(f), ids(f))
t.check("STP-024 evidence marks the baseline source",
        [x.evidence["from_baseline"] for x in f if x.id == "STP-024"] == [True])

mrows = a.msti_health()
t.check("MSTI health table has one row per instance", len(mrows) == 2, mrows)
t.check("MSTI health reports the regional root", mrows[0]["regional_root"] != "-")
t.check("MSTI health is sorted by instance", [r["mstid"] for r in mrows] == [10, 20])

# one frame carrying N records is still ONE BPDU for rate purposes
a = an(baseline=BL_MST)
many = [msti_record(mstid=i, mac=f"00:11:22:33:44:{i:02x}") for i in range(1, 13)]
for i in range(10):
    feed(a, mstframe(many), 100.0 + i * 2.0)
t.check("multi-record frames do not inflate the BPDU rate",
        a.stats["bpdu_total"] == 10 and "finding:STP-008" not in a.stats,
        dict(a.stats))


# --- classic BPF program: interpret it, don't just eyeball it ---------------
def bpf_run(prog, pkt):
    A = 0
    i = 0
    for _ in range(64):
        code, jt, jf, k = prog[i]
        if code == 0x28:                      # ldh [k]
            A = struct.unpack_from("!H", pkt, k)[0]
        elif code == 0x20:                    # ld [k]
            A = struct.unpack_from("!I", pkt, k)[0]
        elif code == 0x15:                    # jeq #k
            i += 1 + (jt if A == k else jf)
            continue
        elif code == 0x06:                    # ret #k
            return k
        else:
            raise AssertionError(f"unknown opcode 0x{code:02x}")
        i += 1
    raise AssertionError("no terminating ret")


P = S.BPF_PROGRAM
t.check("bpf: program terminates in two rets", P[-1][0] == 0x06 and P[-2][0] == 0x06)
t.check("bpf: accepts 01:80:c2:00:00:00", bpf_run(P, IEEE_DST + b"\x00" * 54) == 0x40000)
t.check("bpf: accepts 01:00:0c:cc:cc:cd", bpf_run(P, PVST_DST + b"\x00" * 54) == 0x40000)
t.check("bpf: rejects broadcast", bpf_run(P, b"\xff" * 6 + b"\x00" * 54) == 0)
t.check("bpf: rejects 01:80:c2:00:00:0e (LLDP)",
        bpf_run(P, b"\x01\x80\xc2\x00\x00\x0e" + b"\x00" * 54) == 0)
t.check("bpf: rejects 01:00:0c:cc:cc:cc (CDP)",
        bpf_run(P, b"\x01\x00\x0c\xcc\xcc\xcc" + b"\x00" * 54) == 0)
t.check("bpf: blob is 8 bytes per instruction", len(S._bpf_blob()) == 8 * len(P))


# --- pcap replay ------------------------------------------------------------
def write_pcap(path, frames):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            fh.write(struct.pack("<IIII", 1000 + i, 0, len(fr), len(fr)))
            fh.write(fr)


with tempfile.TemporaryDirectory() as td:
    pc = os.path.join(td, "stp.pcap")
    write_pcap(pc, [frame(config_body()), tcn_frame(), pvst_frame(vlan=100)])
    got = list(pcap_frames(pc))
    t.check("pcap: three frames replayed", len(got) == 3, len(got))
    t.check("pcap: timestamps monotonic", got[0][0] < got[2][0])
    parsed = [parse_frame(d, "pcap", ts) for ts, d in got]
    t.check("pcap: all frames parse as BPDUs", all(x is not None for x in parsed))

    # End-to-end regression: the stealth in-region MSTI forgery. Correct region
    # name and digest, a plausible burned-in source MAC, CIST fields untouched.
    # Before the per-MSTI tier existed this capture produced ZERO findings.
    pc2 = os.path.join(td, "stealth.pcap")
    clean = [msti_record(mstid=10, mac="00:11:22:33:44:55"),
             msti_record(mstid=20, mac="00:11:22:33:44:66")]
    forged = [msti_record(mstid=10, mac="00:11:22:33:44:55"),
              msti_record(mstid=20, prio=0, mac="00:1b:90:7a:2b:34",
                          cost=0, bridge_prio=0x00)]
    fs = [frame(mst_body(records=clean)) for _ in range(20)]
    fs += [frame(mst_body(records=forged), src="00:1b:90:7a:2b:34") for _ in range(5)]
    write_pcap(pc2, fs)

    az = Analyzer(baseline=BL_MST, start_ts=0.0)
    seen = []
    for ts, d in pcap_frames(pc2):
        seen += az.process(parse_frame(d, "eth0", ts))
    sids = set(ids(seen))
    t.check("pcap/e2e: stealth MSTI forgery raises the per-MSTI tier",
            {"STP-023", "STP-024", "STP-026", "STP-027", "STP-028"} <= sids, sorted(sids))
    t.check("pcap/e2e: no CIST-level finding fires (CIST fields untouched)",
            not ({"STP-001", "STP-002", "STP-003", "STP-009", "STP-015"} & sids), sorted(sids))
    t.check("pcap/e2e: region digest matches so STP-021/022 stay silent",
            not ({"STP-021", "STP-022"} & sids), sorted(sids))
    t.check("pcap/e2e: no bogus-MAC finding (attacker used a burned-in OUI)",
            "STP-011" not in sids, sorted(sids))
    t.check("pcap/e2e: MSTI 10 stays clean while 20 is attacked",
            {x.vlan for x in seen} == {"MSTI:20"}, {x.vlan for x in seen})
    t.check("pcap/e2e: a CRITICAL is raised",
            any(x.severity == "CRITICAL" for x in seen))
    mh = {r["mstid"]: r for r in az.msti_health()}
    t.check("pcap/e2e: MSTI health shows the hijacked root only on instance 20",
            mh[10]["root_changes"] == 0 and mh[20]["root_changes"] == 1, mh)


# --- passivity contract -----------------------------------------------------
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "stpwatch.py")).read()
banned = [".send(", ".sendto(", ".sendall(", "sendp(", "srp(", "sr1("]
t.check("passivity: no transmit call anywhere in stpwatch.py",
        not any(b in src for b in banned),
        [b for b in banned if b in src])
t.check("passivity: Sniffer exposes no send method", not hasattr(S.Sniffer, "send"))
t.check("detection catalogue has no gaps",
        sorted(S.DETECTIONS) == [f"STP-{i:03d}" for i in range(1, 32)])

sys.exit(t.report())
