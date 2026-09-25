"""
Hand-rolled dual-stack DNS parser for DNS Doctor's passive tier.

No regex, no dnspython on the hot path -- per the Pi Zero 2W budget.
Pure bytes in, structured records out. Every function is total: it
returns a MalformedDNS marker rather than raising, because a passive
sensor that crashes on hostile input is worse than one that misses a
packet, and malformed packets are themselves a finding (DNSD-007).

THREE THINGS THIS FILE GETS RIGHT ON PURPOSE, each a known trap:

1. COMPRESSION POINTER LOOPS. A name can point backwards to another
   name. Two pointers aimed at each other hang a naive parser forever
   -- a one-packet CPU denial of service against the sensor itself.
   Guarded two ways: pointers must strictly DECREASE (a pointer may
   only ever point earlier in the message), and a hard jump budget.
   The strictly-decreasing rule is the stronger of the two and is what
   makes a loop structurally impossible rather than merely bounded.

2. FORWARD POINTERS ARE REJECTED. RFC 1035 s4.1.4 defines compression
   as a pointer to a PRIOR occurrence. Forward pointers are a classic
   parser-differential evasion: some stacks follow them, some don't,
   so an attacker can make one name mean two things to two readers.

3. OFFSET ARITHMETIC IS DUAL-STACK BUT NOT DUPLICATED. The IPv4 and
   IPv6 paths differ only in where the L4 header starts; everything
   above that is one code path, because DNS records are byte-identical
   over either. The version nibble decides the offset and nothing else
   branches -- so there is no second implementation to drift.
"""

MAX_NAME_LEN = 255
MAX_LABEL_LEN = 63
MAX_POINTER_JUMPS = 32

ETH_HDR = 14
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_VLAN = 0x8100

# DNS rdata type numbers we care about.
T_A, T_NS, T_CNAME, T_SOA, T_AAAA = 1, 2, 5, 6, 28
T_DS, T_RRSIG, T_NSEC, T_DNSKEY, T_NSEC3 = 43, 46, 47, 48, 50
T_OPT, T_DNAME, T_SVCB, T_HTTPS, T_TKEY, T_TSIG = 41, 39, 64, 65, 249, 250
QT_IXFR, QT_AXFR, QT_TKEY = 251, 252, 249

# EDNS0 option codes that RFC permits AT MOST ONCE in one OPT record.
# Repeating one is CVE-2026-42944's denial-of-service primitive.
EDNS_SINGLETON_OPTIONS = {
    3: "NSID", 8: "ECS", 9: "DAU", 10: "DHU", 11: "N3U",
    10500: "PADDING", 12: "PADDING", 10: "DHU", 11: "N3U",
}
EDNS_OPTION_NAMES = {3: "NSID", 8: "ECS", 9: "DAU", 10: "DHU", 11: "N3U",
                     12: "PADDING", 13: "CHAIN", 14: "KEY-TAG",
                     15: "EXTENDED-ERROR", 10: "DHU", 10500: "PADDING"}
# DNS COOKIE is option 10 in some drafts and 10 (COOKIE) in RFC 7873 == 10.
EDNS_COOKIE = 10

# DNSSEC algorithms a modern validator can actually verify. Anything
# outside this set and not in DEPRECATED_ALGOS is simply unknown to us.
SUPPORTED_ALGOS = {5, 7, 8, 10, 13, 14, 15, 16}
DEPRECATED_ALGOS = {1, 3, 6, 12}


class MalformedDNS(Exception):
    """Carried as a value, not raised past parse_dns()."""


class PointerAnomaly(MalformedDNS):
    """
    A compression-pointer failure specifically, as opposed to any other
    malformation.

    Kept as its own type because the two get very different findings.
    A truncated record is DNSD-007 (notice/low, malformed packets are
    ordinary on real networks). A pointer loop, a forward pointer, or a
    pointer into RDATA is DNSD-008 (critical/high) -- that is the shape
    behind an Unbound RCE and two dnsmasq memory-safety bugs, and
    collapsing it into the generic malformed bucket would bury a
    critical finding under an informational one.
    """


class Name:
    __slots__ = ("labels", "truncated")

    def __init__(self, labels, truncated=False):
        self.labels = labels
        self.truncated = truncated

    def text(self):
        if not self.labels:
            return "."
        return ".".join(l.decode("ascii", "replace") for l in self.labels) + "."

    def lower_labels(self):
        return [l.lower() for l in self.labels]

    def __repr__(self):
        return f"Name({self.text()!r})"


class RR:
    __slots__ = ("name", "rtype", "rclass", "ttl", "rdata", "rdlength", "section", "parsed")

    def __init__(self, name, rtype, rclass, ttl, rdata, rdlength, section):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata
        self.rdlength = rdlength
        self.section = section
        self.parsed = {}


class DNSMessage:
    __slots__ = ("txid", "flags", "qr", "opcode", "aa", "tc", "rd", "ra", "ad", "cd",
                 "rcode", "questions", "answers", "authority", "additional",
                 "malformed", "malformed_reason", "pointer_anomaly",
                 "pointer_targets", "rdata_spans", "counts")

    def __init__(self):
        self.questions = []
        self.answers = []
        self.authority = []
        self.additional = []
        self.malformed = False
        self.malformed_reason = None
        self.pointer_anomaly = None
        self.pointer_targets = []
        self.rdata_spans = []
        self.counts = (0, 0, 0, 0)

    def all_rrs(self):
        return self.answers + self.authority + self.additional


def parse_l3_l4(frame):
    """
    Dual-stack. Returns (src_ip, dst_ip, sport, dport, proto, payload)
    or None if this frame isn't DNS-shaped. src/dst are returned as
    raw bytes -- formatting them costs CPU on the hot path and only
    matters when a finding actually fires.
    """
    if len(frame) < ETH_HDR:
        return None
    ethertype = int.from_bytes(frame[12:14], "big")
    off = ETH_HDR

    # One level of VLAN tag. On Linux AF_PACKET the OUTER tag is
    # usually stripped into auxdata before BPF runs and re-inserted by
    # libpcap for the reader (LESSON F), so a tag being visible here
    # is normal and must not be treated as an anomaly.
    if ethertype == ETH_P_VLAN:
        if len(frame) < off + 4:
            return None
        ethertype = int.from_bytes(frame[off + 2:off + 4], "big")
        off += 4

    if ethertype == ETH_P_IP:
        if len(frame) < off + 20:
            return None
        vihl = frame[off]
        if (vihl >> 4) != 4:
            return None
        ihl = (vihl & 0x0F) * 4
        if ihl < 20 or len(frame) < off + ihl:
            return None
        proto = frame[off + 9]
        # A fragmented datagram cannot be parsed as DNS from one frame.
        frag = int.from_bytes(frame[off + 6:off + 8], "big")
        if frag & 0x1FFF:
            return None
        src, dst = frame[off + 12:off + 16], frame[off + 16:off + 20]
        l4 = off + ihl
    elif ethertype == ETH_P_IPV6:
        if len(frame) < off + 40:
            return None
        if (frame[off] >> 4) != 6:
            return None
        proto = frame[off + 6]
        src, dst = frame[off + 8:off + 24], frame[off + 24:off + 40]
        l4 = off + 40
        # Walk extension headers. DNS itself is identical over v6, but
        # the L4 OFFSET is not fixed when EHs are present -- the exact
        # blind spot that bit juniperwatch and sshwatch. Hop-by-hop(0),
        # routing(43), destination(60) share the TLV shape.
        hops = 0
        while proto in (0, 43, 60) and hops < 8:
            if len(frame) < l4 + 2:
                return None
            nxt = frame[l4]
            ehlen = (frame[l4 + 1] + 1) * 8
            l4 += ehlen
            proto = nxt
            hops += 1
        if proto == 44:  # fragment header -- same reasoning as IPv4
            return None
    else:
        return None

    if proto == 17:  # UDP
        if len(frame) < l4 + 8:
            return None
        sport = int.from_bytes(frame[l4:l4 + 2], "big")
        dport = int.from_bytes(frame[l4 + 2:l4 + 4], "big")
        return (src, dst, sport, dport, "udp", frame[l4 + 8:])
    if proto == 6:  # TCP
        if len(frame) < l4 + 20:
            return None
        sport = int.from_bytes(frame[l4:l4 + 2], "big")
        dport = int.from_bytes(frame[l4 + 2:l4 + 4], "big")
        doff = (frame[l4 + 12] >> 4) * 4
        if doff < 20 or len(frame) < l4 + doff:
            return None
        payload = frame[l4 + doff:]
        # DNS over TCP prefixes a 2-byte length.
        if len(payload) < 2:
            return None
        return (src, dst, sport, dport, "tcp", payload[2:])
    return None


def parse_name(buf, offset, _jumps=0, _min_ptr=None, ptr_sink=None):
    """
    Returns (Name, next_offset). next_offset is the offset AFTER the
    name in the ORIGINAL stream (pointer jumps don't advance it).

    Raises MalformedDNS on: label overrun, oversized name, forward or
    equal pointer, jump budget exhaustion, or a truncated buffer.
    """
    labels = []
    total = 0
    next_offset = None
    cur = offset
    jumps = _jumps
    min_ptr = _min_ptr

    while True:
        if cur >= len(buf):
            raise MalformedDNS("name runs past end of message")
        ln = buf[cur]

        if ln == 0:
            cur += 1
            if next_offset is None:
                next_offset = cur
            return Name(labels), next_offset

        if (ln & 0xC0) == 0xC0:
            if cur + 1 >= len(buf):
                raise PointerAnomaly("compression pointer truncated")
            ptr = ((ln & 0x3F) << 8) | buf[cur + 1]
            if next_offset is None:
                next_offset = cur + 2
            jumps += 1
            if ptr_sink is not None:
                ptr_sink.append(ptr)
            if jumps > MAX_POINTER_JUMPS:
                raise PointerAnomaly("compression pointer jump budget exhausted")
            # STRICTLY DECREASING: a pointer must point earlier than
            # the pointer itself, and earlier than any pointer already
            # followed. This makes loops structurally impossible, and
            # rejects the forward-pointer parser-differential evasion.
            limit = cur if min_ptr is None else min(cur, min_ptr)
            if ptr >= limit:
                raise PointerAnomaly(
                    f"compression pointer must point strictly backwards "
                    f"(ptr={ptr}, limit={limit})")
            min_ptr = ptr
            cur = ptr
            continue

        if (ln & 0xC0) != 0:
            raise MalformedDNS(f"reserved label length bits set (0x{ln:02x})")
        if ln > MAX_LABEL_LEN:
            raise MalformedDNS(f"label longer than {MAX_LABEL_LEN}")
        if cur + 1 + ln > len(buf):
            raise MalformedDNS("label runs past end of message")

        total += ln + 1
        if total > MAX_NAME_LEN:
            raise MalformedDNS(f"name longer than {MAX_NAME_LEN}")
        labels.append(buf[cur + 1:cur + 1 + ln])
        cur += 1 + ln


def _u16(buf, off):
    if off + 2 > len(buf):
        raise MalformedDNS("truncated u16")
    return int.from_bytes(buf[off:off + 2], "big")


def _u32(buf, off):
    if off + 4 > len(buf):
        raise MalformedDNS("truncated u32")
    return int.from_bytes(buf[off:off + 4], "big")


def parse_rr(buf, off, section, ptr_sink=None, rdata_spans=None):
    name, off = parse_name(buf, off, ptr_sink=ptr_sink)
    rtype = _u16(buf, off)
    rclass = _u16(buf, off + 2)
    ttl = _u32(buf, off + 4)
    rdlength = _u16(buf, off + 8)
    off += 10
    if off + rdlength > len(buf):
        raise MalformedDNS("rdlength runs past end of message")
    rr = RR(name, rtype, rclass, ttl, buf[off:off + rdlength], rdlength, section)
    if rdata_spans is not None and rdlength:
        rdata_spans.append((off, off + rdlength, rtype))
    _parse_rdata(rr, buf, off, ptr_sink=ptr_sink)
    return rr, off + rdlength


def _parse_rdata(rr, buf, rdoff, ptr_sink=None):
    """
    Decode the rdata fields the detectors actually read. Anything we
    don't decode stays available as raw bytes. Failures here are
    recorded on the RR rather than propagated -- a single unparseable
    rdata shouldn't discard an otherwise readable message.
    """
    try:
        if rr.rtype == T_DNSKEY and rr.rdlength >= 4:
            flags = _u16(buf, rdoff)
            proto = buf[rdoff + 2]
            algo = buf[rdoff + 3]
            key = rr.rdata[4:]
            rr.parsed = {"flags": flags, "protocol": proto, "algorithm": algo,
                         "key_tag": dnskey_key_tag(rr.rdata),
                         "zone_key": bool(flags & 0x0100),
                         "sep": bool(flags & 0x0001), "keylen": len(key)}
        elif rr.rtype == T_RRSIG and rr.rdlength >= 18:
            rr.parsed = {
                "type_covered": _u16(buf, rdoff),
                "algorithm": buf[rdoff + 2],
                "labels": buf[rdoff + 3],
                "original_ttl": _u32(buf, rdoff + 4),
                "expiration": _u32(buf, rdoff + 8),
                "inception": _u32(buf, rdoff + 12),
                "key_tag": _u16(buf, rdoff + 16),
            }
            # signer's name is NOT compressible inside RRSIG rdata per
            # RFC 4034 s3.1.7, so parse it standalone.
            try:
                signer, _ = parse_name(buf, rdoff + 18)
                rr.parsed["signer"] = signer
            except MalformedDNS:
                rr.parsed["signer"] = None
        elif rr.rtype == T_NSEC3 and rr.rdlength >= 5:
            salt_len = buf[rdoff + 4]
            rr.parsed = {
                "hash_algorithm": buf[rdoff],
                "flags": buf[rdoff + 1],
                "iterations": _u16(buf, rdoff + 2),
                "salt_length": salt_len,
                "opt_out": bool(buf[rdoff + 1] & 0x01),
            }
        elif rr.rtype == T_NS:
            target, _ = parse_name(buf, rdoff, ptr_sink=ptr_sink)
            rr.parsed = {"target": target}
        elif rr.rtype in (T_CNAME, T_DNAME):
            target, _ = parse_name(buf, rdoff, ptr_sink=ptr_sink)
            rr.parsed = {"target": target}
        elif rr.rtype == T_NSEC and rr.rdlength >= 1:
            # RFC 4034 s4.1.1: next-domain is NOT compressible.
            nxt, after = parse_name(buf, rdoff)
            rr.parsed = {"next": nxt, "bitmap_len": rr.rdlength - (after - rdoff)}
        elif rr.rtype in (T_SVCB, T_HTTPS) and rr.rdlength >= 3:
            prio = _u16(buf, rdoff)
            target, _ = parse_name(buf, rdoff + 2)
            rr.parsed = {"priority": prio, "target": target,
                         "alias_mode": prio == 0, "service_mode": prio != 0}
        elif rr.rtype == T_OPT:
            opts, p, end = [], rdoff, rdoff + rr.rdlength
            while p + 4 <= end:
                ocode = _u16(buf, p)
                olen = _u16(buf, p + 2)
                if p + 4 + olen > end:
                    opts.append(("truncated", ocode))
                    break
                opts.append((ocode, olen))
                p += 4 + olen
            rr.parsed = {"options": opts}
        elif rr.rtype == T_SOA:
            mname, o2 = parse_name(buf, rdoff)
            rname, _ = parse_name(buf, o2)
            rr.parsed = {"mname": mname, "rname": rname}
    except MalformedDNS as e:
        rr.parsed = {"rdata_error": str(e)}


def dnskey_key_tag(rdata):
    """
    RFC 4034 Appendix B key-tag computation. This is a CHECKSUM RULE,
    which per LESSON A is precisely the kind of thing a hand-rolled
    implementation and its hand-rolled test can agree on while both
    being wrong -- so xcheck.py verifies it against an independent
    implementation (dnspython) rather than against our own fixtures.

    Algorithm 1 (RSA/MD5) uses a completely different rule and is
    handled separately; it is deprecated but still appears in the wild.
    """
    if len(rdata) < 4:
        return None
    algorithm = rdata[3]
    if algorithm == 1:
        if len(rdata) < 7:
            return None
        return (rdata[-3] << 8) | rdata[-2]
    total = 0
    for i, b in enumerate(rdata):
        total += b if (i & 1) else (b << 8)
    total += (total >> 16) & 0xFFFF
    return total & 0xFFFF


def parse_dns(payload):
    """
    Total function: always returns a DNSMessage. On a structural
    failure it returns one with .malformed set and whatever sections
    were readable before the failure -- partial data is still useful
    to the posture detectors, and the malformation itself is DNSD-007.
    """
    msg = DNSMessage()
    if len(payload) < 12:
        msg.malformed = True
        msg.malformed_reason = "shorter than a DNS header"
        msg.pointer_anomaly = None
        msg.txid = None
        msg.qr = msg.opcode = msg.rcode = None
        msg.flags = 0
        msg.aa = msg.tc = msg.rd = msg.ra = msg.ad = msg.cd = False
        return msg

    msg.txid = int.from_bytes(payload[0:2], "big")
    flags = int.from_bytes(payload[2:4], "big")
    msg.flags = flags
    msg.qr = bool(flags & 0x8000)
    msg.opcode = (flags >> 11) & 0x0F
    msg.aa = bool(flags & 0x0400)
    msg.tc = bool(flags & 0x0200)
    msg.rd = bool(flags & 0x0100)
    msg.ra = bool(flags & 0x0080)
    msg.ad = bool(flags & 0x0020)
    msg.cd = bool(flags & 0x0010)
    msg.rcode = flags & 0x000F

    qd, an, ns, ar = (int.from_bytes(payload[i:i + 2], "big") for i in (4, 6, 8, 10))
    msg.counts = (qd, an, ns, ar)
    off = 12
    ptr_sink, rdata_spans = [], []
    msg.pointer_targets = ptr_sink
    msg.rdata_spans = rdata_spans
    try:
        for _ in range(qd):
            name, off = parse_name(payload, off, ptr_sink=ptr_sink)
            qtype = _u16(payload, off)
            qclass = _u16(payload, off + 2)
            off += 4
            msg.questions.append({"name": name, "qtype": qtype, "qclass": qclass})
        for count, section, bucket in ((an, "answer", msg.answers),
                                       (ns, "authority", msg.authority),
                                       (ar, "additional", msg.additional)):
            for _ in range(count):
                rr, off = parse_rr(payload, off, section,
                                   ptr_sink=ptr_sink, rdata_spans=rdata_spans)
                bucket.append(rr)
    except PointerAnomaly as e:
        msg.malformed = True
        msg.malformed_reason = str(e)
        msg.pointer_anomaly = str(e)
    except MalformedDNS as e:
        msg.malformed = True
        msg.malformed_reason = str(e)

    # A pointer that resolves INTO a resource record's RDATA is the
    # CVE-2026-81642 shape. It is not caught by the strictly-backward
    # rule, because a pointer into an EARLIER record's rdata points
    # backwards quite legally as far as that rule is concerned.
    if msg.pointer_anomaly is None:
        for ptr in ptr_sink:
            for start, end, rtype in rdata_spans:
                if start <= ptr < end:
                    msg.pointer_anomaly = (
                        f"compression pointer {ptr} resolves into the RDATA of a "
                        f"type-{rtype} record (bytes {start}..{end})")
                    break
            if msg.pointer_anomaly:
                break
    return msg
