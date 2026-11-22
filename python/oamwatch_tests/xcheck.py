#!/usr/bin/env python3
"""oamwatch cross-check tier: an INDEPENDENT dissector on the other side of
every length and bounds rule.

Why this tier is not optional
-----------------------------
A hand-rolled parser and a hand-rolled frame builder can agree with each other
and both be wrong - that is the cdpwatch checksum-quirk lesson. Everything in
oamwatch Class A is length and bounds arithmetic, so a second implementation
has to sit on the other side of it.

Primary independent dissector: WIRESHARK's `oampdu` dissector via tshark. It is
third-party, written from the same IEEE clause by other people, and it decodes
Flags, Code, Information TLV state/config/OUI, event sequence, variable
branch/leaf/width and the loopback command byte.

Secondary: SCAPY, for framing and pcap round-trip (`scapy.contrib.slowprot`
gives an independent SlowProtocol/subtype demux, and rdpcap is an independent
pcap reader for the timestamp contract).

AGGREGATOR HYGIENE - READ BEFORE "IMPROVING" THIS FILE
------------------------------------------------------
`scapy.contrib.oam` is NOT 802.3ah Link OAM. It implements ITU-T G.8013/Y.1731
and 802.1ag CFM, which ride EtherType 0x8902 and are a different protocol at a
different layer - the "bigger carrier cousin" named in the oamwatch preflight.
Wiring it in here would be the same class of error as treating CVE-2019-14810
(LDP) as an LLDP bug. Do not use it.

This tier is kept OUT of the offline conformance run, which asserts scapy is
never imported there.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import frames as F                                      # noqa: E402
from oamwatch.parser import parse_frame                 # noqa: E402
from oamwatch.sensor import write_pcap, read_pcap       # noqa: E402

_checks = 0
_failures = []


def check(cond, what):
    global _checks
    _checks += 1
    if not cond:
        _failures.append(what)


def tshark_json(pcap, fields):
    args = ["tshark", "-r", pcap, "-T", "json", "-x"]
    out = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError("tshark failed: %s" % out.stderr[:400])
    return json.loads(out.stdout)


def tshark_fields(pcap, fields):
    """Return a list of per-frame dicts for the requested display fields."""
    args = ["tshark", "-r", pcap, "-T", "fields", "-E", "separator=|",
            "-E", "occurrence=a"]
    for f in fields:
        args += ["-e", f]
    out = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError("tshark failed: %s" % out.stderr[:400])
    rows = []
    for line in out.stdout.splitlines():
        parts = line.split("|")
        parts += [""] * (len(fields) - len(parts))
        rows.append(dict(zip(fields, parts)))
    return rows


def _as_int(s):
    s = s.strip()
    if not s:
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Direction 1: we build -> Wireshark dissects -> fields must agree
# --------------------------------------------------------------------------
def direction1(tmp):
    specs = [
        # (frame, expected code, expected flags, note)
        (F.information([F.info_tlv(1), F.info_tlv(2)]), 0x00, 0x0050),
        (F.information([F.info_tlv(1, state=0x01, config=0x1F)]), 0x00, 0x0050),
        (F.information(flags=F.FLAGS_OPERATIONAL | F.F_DYING_GASP), 0x00, 0x0052),
        (F.information(flags=F.FLAGS_OPERATIONAL | F.F_CRITICAL), 0x00, 0x0054),
        (F.information(flags=F.FLAGS_OPERATIONAL | F.F_LINK_FAULT), 0x00, 0x0051),
        (F.event_notification(seq=0x1234), 0x01, 0x0050),
        (F.variable_request(descriptors=((0x07, 0x0042),)), 0x02, 0x0050),
        (F.variable_response(), 0x03, 0x0050),
        (F.loopback_control(command=0x01), 0x04, 0x0050),
        (F.loopback_control(command=0x02), 0x04, 0x0050),
    ]
    pcap = os.path.join(tmp, "d1.pcap")
    write_pcap(pcap, [s[0] for s in specs])

    fields = ["oampdu.code", "oampdu.flags", "oampdu.flags.dyingGasp",
              "oampdu.flags.criticalEvent", "oampdu.flags.linkFault",
              "oampdu.info.state", "oampdu.info.oamConfig",
              "oampdu.info.oampduConfig", "oampdu.info.oui",
              "oampdu.event.sequence", "oampdu.variable.branch",
              "oampdu.lpbk.commands", "slow.subtype"]
    rows = tshark_fields(pcap, fields)
    check(len(rows) == len(specs),
          "tshark dissected %d frames, built %d" % (len(rows), len(specs)))

    for i, (raw, want_code, want_flags) in enumerate(specs):
        if i >= len(rows):
            break
        row = rows[i]
        ours = parse_frame(raw, ts=1.0 + i)
        check(ours is not None, "frame %d: our parser rejected our own frame" % i)
        if ours is None:
            continue
        ws_code = _as_int(row["oampdu.code"].split(",")[0])
        ws_flags = _as_int(row["oampdu.flags"].split(",")[0])
        check(ws_code == ours.code == want_code,
              "frame %d code: wireshark=%r ours=%r expected=%r"
              % (i, ws_code, ours.code, want_code))
        check(ws_flags == ours.flags == want_flags,
              "frame %d flags: wireshark=%r ours=%r expected=%r"
              % (i, ws_flags, ours.flags, want_flags))

        # failure flags, independently decoded
        for fld, attr in (("oampdu.flags.dyingGasp", "dying_gasp"),
                          ("oampdu.flags.criticalEvent", "critical_event"),
                          ("oampdu.flags.linkFault", "link_fault")):
            v = row[fld].split(",")[0].strip()
            if v in ("0", "1", "True", "False"):
                ws = v in ("1", "True")
                check(ws == bool(getattr(ours, attr)),
                      "frame %d %s: wireshark=%s ours=%s"
                      % (i, fld, ws, getattr(ours, attr)))

        if ours.local_info is not None:
            ws_state = _as_int(row["oampdu.info.state"].split(",")[0])
            ws_cfg = _as_int(row["oampdu.info.oamConfig"].split(",")[0])
            ws_max = _as_int(row["oampdu.info.oampduConfig"].split(",")[0])
            check(ws_state == ours.local_info.state,
                  "frame %d info state: wireshark=%r ours=%r"
                  % (i, ws_state, ours.local_info.state))
            check(ws_cfg == ours.local_info.config,
                  "frame %d oam config: wireshark=%r ours=%r"
                  % (i, ws_cfg, ours.local_info.config))
            check(ws_max == ours.local_info.max_pdu_size,
                  "frame %d max pdu: wireshark=%r ours=%r"
                  % (i, ws_max, ours.local_info.max_pdu_size))

        if ours.event_seq is not None:
            ws_seq = _as_int(row["oampdu.event.sequence"].split(",")[0])
            check(ws_seq == ours.event_seq,
                  "frame %d event seq: wireshark=%r ours=%r"
                  % (i, ws_seq, ours.event_seq))

        if ours.loopback_cmd is not None:
            ws_cmd = _as_int(row["oampdu.lpbk.commands"].split(",")[0])
            check(ws_cmd == ours.loopback_cmd,
                  "frame %d loopback command: wireshark=%r ours=%r"
                  % (i, ws_cmd, ours.loopback_cmd))

        ws_sub = _as_int(row["slow.subtype"].split(",")[0])
        check(ws_sub == 3, "frame %d subtype: wireshark=%r, expected 3"
              % (i, ws_sub))


# --------------------------------------------------------------------------
# Direction 2: Wireshark must also see the malformation we flag
# --------------------------------------------------------------------------
def direction2(tmp):
    """Frames our parser calls structurally broken must not dissect cleanly in
    Wireshark either. A frame we flag that Wireshark reads as well-formed is a
    false positive worth knowing about."""
    malformed = [
        ("OAM-040", F.information([F.info_tlv(length=0x40)])),
        ("OAM-042", F.information([F.info_tlv(length=0x0E)])),
        ("OAM-046", F.event_notification(tlvs=[F.event_tlv(0x02, length=24)])),
        ("OAM-051", F.loopback_control(command=0x03)),
        ("OAM-053", F.variable_response(width_override=0x7F)),
    ]
    pcap = os.path.join(tmp, "d2.pcap")
    write_pcap(pcap, [m[1] for m in malformed])
    rows = tshark_fields(pcap, ["_ws.expert", "_ws.malformed",
                                "oampdu.code", "oampdu.info.length",
                                "oampdu.event.length", "oampdu.variable.width",
                                "oampdu.lpbk.commands"])
    check(len(rows) == len(malformed),
          "tshark read %d of %d malformed frames" % (len(rows), len(malformed)))
    for i, (code, raw) in enumerate(malformed):
        if i >= len(rows):
            break
        ours = parse_frame(raw, ts=1.0)
        check(code in ours.defect_codes(),
              "%s: our parser did not flag its own malformed fixture (%s)"
              % (code, ours.defect_codes()))
        # Wireshark must at least agree on the raw field we based the call on.
        row = rows[i]
        if code == "OAM-040" or code == "OAM-042":
            ws_len = _as_int(row["oampdu.info.length"].split(",")[0])
            check(ws_len is not None and ws_len != 0x10,
                  "%s: wireshark read Information TLV length %r, expected the "
                  "non-standard value we flagged" % (code, ws_len))
        if code == "OAM-046":
            ws_len = _as_int(row["oampdu.event.length"].split(",")[0])
            check(ws_len == 24,
                  "%s: wireshark read event length %r, expected 24"
                  % (code, ws_len))
        if code == "OAM-051":
            ws_cmd = _as_int(row["oampdu.lpbk.commands"].split(",")[0])
            check(ws_cmd == 0x03,
                  "%s: wireshark read loopback command %r, expected 0x03"
                  % (code, ws_cmd))
        if code == "OAM-053":
            ws_w = _as_int(row["oampdu.variable.width"].split(",")[0])
            check(ws_w == 0x7F,
                  "%s: wireshark read variable width %r, expected 0x7f"
                  % (code, ws_w))


# --------------------------------------------------------------------------
# Direction 3: scapy builds -> we parse
# --------------------------------------------------------------------------
def direction3():
    from scapy.contrib.slowprot import SlowProtocol
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
    import struct

    body = (struct.pack("!H", 0x0050) + bytes([0x00])
            + F.info_tlv(1) + b"\x00")
    pkt = (Ether(dst="01:80:c2:00:00:02", src="00:11:22:33:44:55",
                 type=0x8809) / SlowProtocol(subtype=3) / Raw(load=body))
    raw = bytes(pkt)
    ours = parse_frame(raw, ts=1.0)
    check(ours is not None, "our parser rejected a scapy-built OAM frame")
    if ours is not None:
        check(ours.subtype == 3, "scapy-built: subtype %r" % ours.subtype)
        check(ours.flags == 0x0050, "scapy-built: flags %r" % ours.flags)
        check(ours.code == 0x00, "scapy-built: code %r" % ours.code)
        check(ours.local_info is not None,
              "scapy-built: Local Information TLV not parsed")
        check(not ours.defect_codes(),
              "scapy-built clean frame produced defects: %s"
              % ours.defect_codes())

    # scapy's own demux must agree the frame is slow-protocol subtype 3
    back = Ether(raw)
    check(back.type == 0x8809, "scapy re-dissect ethertype %r" % back.type)
    check(back[SlowProtocol].subtype == 3,
          "scapy re-dissect subtype %r" % back[SlowProtocol].subtype)


# --------------------------------------------------------------------------
# Direction 4: our pcap writer -> scapy rdpcap (timestamp contract)
# --------------------------------------------------------------------------
def direction4(tmp):
    from scapy.utils import rdpcap

    batch = [F.keepalive() for _ in range(25)]
    pcap = os.path.join(tmp, "d4.pcap")
    write_pcap(pcap, batch, base_ts=1000.0, interval=0.001)

    pkts = rdpcap(pcap)
    check(len(pkts) == len(batch),
          "scapy read %d frames, wrote %d" % (len(pkts), len(batch)))
    times = [float(p.time) for p in pkts]
    check(all(b > a for a, b in zip(times, times[1:])),
          "pcap timestamps are not strictly increasing")
    span = times[-1] - times[0]
    check(abs(span - 0.024) < 1e-3,
          "25 frames at 1ms should span 24ms, spans %.6fs. A pcap whose "
          "timestamps advance by the FRAME INDEX IN SECONDS replays at one "
          "frame per second and silently disarms OAM-070." % span)

    # our own reader must agree with scapy's, byte for byte
    mine = list(read_pcap(pcap))
    check(len(mine) == len(pkts), "our reader got %d, scapy %d"
          % (len(mine), len(pkts)))
    for i, ((ts, data), p) in enumerate(zip(mine, pkts)):
        check(data == bytes(p), "frame %d bytes differ between readers" % i)
        check(abs(ts - float(p.time)) < 1e-6,
              "frame %d timestamp differs: ours=%r scapy=%r"
              % (i, ts, float(p.time)))

    # and the rate code must actually fire on this pcap
    from oamwatch.engine import Engine
    from oamwatch.config import Config
    eng = Engine(Config())
    got = []
    for ts, data in read_pcap(pcap):
        pdu = parse_frame(data, ts=ts)
        got.extend(f.code for f in eng.observe(pdu))
    check("OAM-070" in got,
          "25 frames inside 25ms did not trigger OAM-070 (got %s)"
          % sorted(set(got)))


# --------------------------------------------------------------------------
# Direction 5: event TLV field values, read independently by Wireshark
# --------------------------------------------------------------------------
# Wireshark exposes named fields for 18 of the 20 link-monitoring values.
# It has NO field for the ErroredFramePeriod or ErroredFrameSecondsSummary
# error counts - but those two are still pinned, because a wrong width for
# either one visibly shifts the running totals that follow it, and those
# ARE oracled. direction5_counterfactual proves that sandwich has teeth.
EV_PREFIX = {0x01: "espe", 0x02: "efe", 0x03: "efpe", 0x04: "efsse"}
EV_ORACLED = {
    0x01: ("Window", "Threshold", "Errors", "TotalErrors", "TotalEvents"),
    0x02: ("Window", "Threshold", "Errors", "TotalErrors", "TotalEvents"),
    0x03: ("Window", "Threshold", "TotalErrors", "TotalEvents"),
    0x04: ("Window", "Threshold", "TotalErrors", "TotalEvents"),
}
_ATTR = {"Window": "window", "Threshold": "threshold", "Errors": "errors",
         "TotalErrors": "error_total", "TotalEvents": "event_total"}


def direction5(tmp):
    specs = [
        (0x01, dict(timestamp=0x1234, window=1 << 40, threshold=1 << 33,
                    errors=1 << 35, error_total=1 << 36, event_total=70000)),
        (0x02, dict(timestamp=7, window=10, threshold=999,
                    errors=1000, error_total=1 << 33, event_total=12)),
        (0x03, dict(timestamp=65535, window=4000000000, threshold=3,
                    errors=9, error_total=1 << 40, event_total=1)),
        (0x04, dict(timestamp=1, window=60000, threshold=2,
                    errors=5000, error_total=4000000000, event_total=9)),
    ]
    pcap = os.path.join(tmp, "d5.pcap")
    write_pcap(pcap, [F.event_notification(seq=100 + i, tlvs=[F.event_tlv(k, **kw)])
                      for i, (k, kw) in enumerate(specs)])

    fields = ["oampdu.event.sequence", "oampdu.event.timestamp"]
    for pre in EV_PREFIX.values():
        for suf in ("Window", "Threshold", "Errors", "TotalErrors",
                    "TotalEvents"):
            name = "oampdu.event.%s%s" % (pre, suf)
            if name in ("oampdu.event.efpeErrors", "oampdu.event.efsseErrors"):
                continue      # Wireshark has no such field
            fields.append(name)
    rows = tshark_fields(pcap, fields)
    check(len(rows) == len(specs),
          "tshark read %d event frames, built %d" % (len(rows), len(specs)))

    for i, (kind, kw) in enumerate(specs):
        if i >= len(rows):
            break
        row = rows[i]
        raw = F.event_notification(seq=100 + i, tlvs=[F.event_tlv(kind, **kw)])
        ours = parse_frame(raw, ts=1.0 + i)
        check(ours is not None and not ours.defect_codes(),
              "event frame %d: our parser reported defects %s"
              % (i, ours.defect_codes() if ours else "parse failed"))
        if ours is None or not ours.events:
            _failures.append("event frame %d: no event TLV decoded" % i)
            continue
        ev = ours.events[0]

        ws_seq = _as_int(row["oampdu.event.sequence"].split(",")[0])
        check(ws_seq == ours.event_seq == 100 + i,
              "event frame %d sequence: wireshark=%r ours=%r"
              % (i, ws_seq, ours.event_seq))
        ws_ts = _as_int(row["oampdu.event.timestamp"].split(",")[0])
        check(ws_ts == ev.timestamp == kw["timestamp"],
              "event frame %d timestamp: wireshark=%r ours=%r expected=%r"
              % (i, ws_ts, ev.timestamp, kw["timestamp"]))

        for suf in EV_ORACLED[kind]:
            fld = "oampdu.event.%s%s" % (EV_PREFIX[kind], suf)
            ws = _as_int(row[fld].split(",")[0])
            mine = getattr(ev, _ATTR[suf])
            want = kw[_ATTR[suf]]
            check(ws == mine == want,
                  "event frame %d %s: wireshark=%r ours=%r expected=%r"
                  % (i, fld, ws, mine, want))

        # the two un-oracled counts still have to round-trip through OUR
        # decoder at the offsets the oracled neighbours pin
        if kind in (0x03, 0x04):
            check(ev.errors == kw["errors"],
                  "event frame %d un-oracled error count: ours=%r expected=%r"
                  % (i, ev.errors, kw["errors"]))


def direction5_counterfactual(tmp):
    """LESSON J: prove the sandwich argument for the two fields Wireshark
    cannot read. If a WRONG width for the error count left the oracled
    running totals unchanged, their agreement would prove nothing about the
    count's offset."""
    import struct

    def efpe_with_error_width(w):
        lay = [(2, 0x1111), (4, 0x22222222), (4, 0x33333333),
               (w, 0x44444444), (8, 0x55555555), (4, 0x66666666)]
        body = b"".join((v & ((1 << (wd * 8)) - 1)).to_bytes(wd, "big")
                        for wd, v in lay)
        tlv = bytes([0x03, 2 + len(body)]) + body
        return F.eth(0x01, struct.pack("!H", 0x9999) + tlv + b"\x00")

    pcap = os.path.join(tmp, "d5cf.pcap")
    write_pcap(pcap, [efpe_with_error_width(w) for w in (4, 2, 6)])
    rows = tshark_fields(pcap, ["oampdu.event.efpeTotalErrors",
                                "oampdu.event.efpeTotalEvents"])
    check(len(rows) == 3, "counterfactual: tshark read %d of 3" % len(rows))
    if len(rows) < 3:
        return
    right = (_as_int(rows[0]["oampdu.event.efpeTotalErrors"].split(",")[0]),
             _as_int(rows[0]["oampdu.event.efpeTotalEvents"].split(",")[0]))
    check(right == (0x55555555, 0x66666666),
          "counterfactual: correct width should read the planted totals, got %r"
          % (right,))
    for idx, w in ((1, 2), (2, 6)):
        wrong = (_as_int(rows[idx]["oampdu.event.efpeTotalErrors"].split(",")[0]),
                 _as_int(rows[idx]["oampdu.event.efpeTotalEvents"].split(",")[0]))
        check(wrong != right,
              "counterfactual VACUOUS: a %d-octet error count left the oracled "
              "running totals reading %r, identical to the correct model - so "
              "Wireshark's agreement proves nothing about that offset"
              % (w, wrong))


def main():
    if not shutil.which("tshark"):
        print("xcheck: tshark not available - the independent dissector is "
              "REQUIRED for this tier. Install wireshark-common.")
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        direction1(tmp)
        direction2(tmp)
        direction3()
        direction4(tmp)
        direction5(tmp)
        direction5_counterfactual(tmp)
    print("oamwatch xcheck: %d checks, %d failure(s)" % (_checks, len(_failures)))
    for f in _failures:
        print("  FAIL: %s" % f)
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
