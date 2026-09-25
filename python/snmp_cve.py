"""Vendored SNMP CVE detectors (from Solarflere's "SNMP Watch v4").

A dependency-free BER decoder plus the four passive SNMP CVE detectors, extracted
from the standalone snmpwatch.py so the in-app do_snmp_watch can run them over raw
captured frames. The in-app text parser (tcpdump -v) cannot see the raw BER these
CVEs key on — the SNMPv3 USM HMAC length, OID sub-identifier bytes, and varbind
value lengths — so this module reads the SNMP message bytes straight off the wire.

Covered CVEs (all wire-signature; confirmed/attempt/exposure confidence):
  * CVE-2008-0960            SNMPv3 USM HMAC truncation / absence (auth bypass)
  * CVE-2017-6736..6744      Cisco IOS/IOS XE SNMP subsystem RCE (CISA KEV)
  * CVE-2025-68615           net-snmp snmptrapd oversize-field stack overflow
  * CVE-2022-24805/07/09/10  net-snmp malformed-OID VACM out-of-bounds

Detection-only: it parses bytes already captured; it never transmits.
Credit: Solarflere (github.com/Solarflere) — original snmpwatch.py detectors.
"""

# --- SNMP / BER constants ---------------------------------------------------
VERSION_LABELS = {0: "v1", 1: "v2c", 3: "v3"}
TAG_SEQUENCE = 0x30
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
WRITE_PDUS = {0xA3}          # SetRequest == cleartext write access
V3_FLAG_AUTH = 0x01
PDU_NAMES = {
    0xA0: "GetRequest", 0xA1: "GetNextRequest", 0xA2: "Response",
    0xA3: "SetRequest", 0xA4: "Trap-v1", 0xA5: "GetBulkRequest",
    0xA6: "InformRequest", 0xA7: "Trap-v2", 0xA8: "Report",
}


class BERError(ValueError):
    """Raised when a byte string does not decode as a plausible SNMP message."""


# --- BER helpers ------------------------------------------------------------
def _read_tlv(data, offset=0):
    """Read one BER TLV at `offset`; return (tag, length, value, next_offset).
    Supports short- and long-form definite lengths; rejects indefinite length."""
    if offset >= len(data):
        raise BERError("truncated: expected tag")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise BERError("truncated: expected length")
    length_byte = data[offset]
    offset += 1
    if length_byte & 0x80:
        num = length_byte & 0x7F
        if num == 0:
            raise BERError("indefinite length unsupported")
        if offset + num > len(data):
            raise BERError("truncated: long-form length header")
        length = int.from_bytes(data[offset:offset + num], "big")
        offset += num
    else:
        length = length_byte
    if offset + length > len(data):
        raise BERError("truncated: value shorter than declared length")
    return tag, length, data[offset:offset + length], offset + length


def _decode_int(value):
    if not value:
        return 0
    return int.from_bytes(value, "big", signed=True)


def _decode_oid(value):
    """Decode a BER OBJECT IDENTIFIER value (sans tag/len) to dotted form."""
    if not value:
        return ""
    subids, cur = [], 0
    for b in value:
        cur = (cur << 7) | (b & 0x7F)
        if not (b & 0x80):
            subids.append(cur)
            cur = 0
    if not subids:
        return ""
    first = subids[0]
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    arcs.extend(subids[1:])
    return ".".join(str(a) for a in arcs)


def parse_usm(sec_params):
    """Decode RFC 3414 USM msgSecurityParameters → {engine_id, user_name, auth_len,
    priv_len, ...}. Returns {} when it does not decode (non-USM model, or garbage)."""
    out = {}
    try:
        tag, _, inner, _ = _read_tlv(sec_params, 0)
        if tag != TAG_SEQUENCE:
            return out
        _, _, eid, o = _read_tlv(inner, 0)
        _, _, boots, o = _read_tlv(inner, o)
        _, _, etime, o = _read_tlv(inner, o)
        _, _, user, o = _read_tlv(inner, o)
        atag, _, auth, o = _read_tlv(inner, o)
        ptag, _, priv, _ = _read_tlv(inner, o)
        out["engine_id"] = eid
        out["engine_boots"] = _decode_int(boots)
        out["engine_time"] = _decode_int(etime)
        out["user_name"] = user.decode("latin-1", "replace")
        if atag == TAG_OCTET_STRING:
            out["auth_len"] = len(auth)
        if ptag == TAG_OCTET_STRING:
            out["priv_len"] = len(priv)
    except BERError:
        pass
    return out


def parse_snmp(payload):
    """Decode the leading header fields of an SNMP message.

    Returns {'version': int}, plus for v1/v2c {'community', 'pdu_tag', 'pdu_value'}
    and for v3 {'msg_flags', 'usm', 'msg_data_tag'} and (when msgData is a plaintext
    ScopedPDU) {'engine_id', 'context_name', 'pdu_tag', 'pdu_value'}. Raises BERError
    for anything that is not a plausible SNMP message."""
    tag, _, seq_val, _ = _read_tlv(payload, 0)
    if tag != TAG_SEQUENCE:
        raise BERError("outer object is not a SEQUENCE")
    tag, _, ver_val, off = _read_tlv(seq_val, 0)
    if tag != TAG_INTEGER:
        raise BERError("first field is not the version INTEGER")
    version = _decode_int(ver_val)
    if version not in VERSION_LABELS:
        raise BERError("unknown SNMP version %r" % version)

    result = {"version": version}
    if version in (0, 1):                                   # v1 / v2c
        tag, _, comm_val, off = _read_tlv(seq_val, off)
        if tag != TAG_OCTET_STRING:
            raise BERError("expected community OCTET STRING")
        result["community"] = comm_val
        tag, _, pdu_val, _ = _read_tlv(seq_val, off)
        result["pdu_tag"] = tag
        result["pdu_value"] = pdu_val
    elif version == 3:
        tag, _, gd_val, off = _read_tlv(seq_val, off)       # msgGlobalData
        if tag == TAG_SEQUENCE:
            try:
                _, _, _, o = _read_tlv(gd_val, 0)           # msgID
                _, _, _, o = _read_tlv(gd_val, o)           # msgMaxSize
                ftag, _, flags_val, _ = _read_tlv(gd_val, o)   # msgFlags
                if ftag == TAG_OCTET_STRING and flags_val:
                    result["msg_flags"] = flags_val[0]
            except BERError:
                pass
        try:
            _, _, sec_params, off = _read_tlv(seq_val, off)     # msgSecurityParameters
            usm = parse_usm(sec_params)
            if usm:
                result["usm"] = usm
            mtag, _, md_val, _ = _read_tlv(seq_val, off)        # msgData
            result["msg_data_tag"] = mtag
            if mtag == TAG_SEQUENCE:                             # plaintext ScopedPDU
                _, _, eid, o = _read_tlv(md_val, 0)
                _, _, cname, o = _read_tlv(md_val, o)
                result["engine_id"] = eid
                result["context_name"] = cname
                ptag, _, pval, _ = _read_tlv(md_val, o)
                result["pdu_tag"] = ptag
                result["pdu_value"] = pval
        except BERError:
            pass
    return result


def _extract_varbinds(pdu_tag, pdu_value, limit=64):
    """Walk a PDU's variable-bindings → [{oid, value_tag, value_len}]. Handles the
    standard PDU shape and the SNMPv1 Trap-PDU (0xA4). Best-effort: any decode error
    truncates the list."""
    out = []
    try:
        off = 0
        for _ in range(5 if pdu_tag == 0xA4 else 3):
            _, _, _, off = _read_tlv(pdu_value, off)
        _, _, vb_seq, _ = _read_tlv(pdu_value, off)
    except BERError:
        return out
    o = 0
    while o < len(vb_seq) and len(out) < limit:
        try:
            tag, _, vb, o = _read_tlv(vb_seq, o)
        except BERError:
            break
        if tag != TAG_SEQUENCE:
            continue
        try:
            t2, _, oid_bytes, off2 = _read_tlv(vb, 0)
        except BERError:
            continue
        if t2 != 0x06:
            continue
        entry = {"oid": _decode_oid(oid_bytes), "value_tag": None, "value_len": 0}
        try:
            vtag, vlen, _, _ = _read_tlv(vb, off2)
            entry["value_tag"] = vtag
            entry["value_len"] = vlen
        except BERError:
            pass
        out.append(entry)
    return out


# --- CVE detectors ----------------------------------------------------------
# CVE-2008-0960: RFC 3414 fixes msgAuthenticationParameters at 12 bytes (HMAC-96);
# RFC 7860 adds SHA-2 lengths. Shorter than 12 with authFlag set is the bypass.
USM_VALID_AUTH_LENS = {12, 16, 24, 32, 48}
USM_MIN_AUTH_LEN = 12

# CVE-2017-6736..6744: Cisco published the vulnerable MIB list; these prefixes are
# the independently verified ones. ALPS-MIB is the public-PoC branch.
CISCO_SNMP_RCE_MIBS = [
    ("1.3.6.1.4.1.9.9.95",  "ALPS-MIB"),
    ("1.3.6.1.2.1.10.94",   "ADSL-LINE-MIB (transmission.94)"),
    ("1.3.6.1.4.1.9.9.654", "CISCO-MAC-AUTH-BYPASS-MIB"),
    ("1.3.6.1.4.1.9.9.254", "CISCO-SLB-EXT-MIB"),
    ("1.3.6.1.4.1.9.9.252", "ciscoMgmt.252 (Cisco workaround exclusion)"),
]
# The PoC smuggles shellcode as OID arcs (~60+); legitimate table OIDs run ~14-20.
CISCO_RCE_ARC_THRESHOLD = 25

# CVE-2025-68615: net-snmp snmptrapd copies unvalidated user data into a fixed
# stack buffer. The overflowing field is not public, so flag any oversize field.
TRAPD_FIELD_LIMIT = 512

# CVE-2022-24805/07/09/10: a malformed OID that names a VACM column then supplies a
# short INDEX walks off the end. index_count = INDEX elements the entry requires.
NETSNMP_VACM_TABLES = [
    ("1.3.6.1.4.1.8072.1.9.1.1", "NET-SNMP-VACM-MIB::nsVacmAccessEntry", 5,
     "CVE-2022-24805/24809/24810"),
    ("1.3.6.1.6.3.16.1.4.1", "SNMP-VIEW-BASED-ACM-MIB::vacmAccessEntry", 4,
     "CVE-2022-24807"),
]


def detect_usm_hmac_truncation(info):
    """CVE-2008-0960 — SNMPv3 HMAC truncation authentication bypass (confirmed)."""
    if info.get("version") != 3:
        return []
    flags = info.get("msg_flags")
    if flags is None or not (flags & V3_FLAG_AUTH):
        return []          # no authentication asserted -> nothing to truncate
    usm = info.get("usm") or {}
    if "auth_len" not in usm:
        return []
    alen = usm["auth_len"]
    user = usm.get("user_name", "")
    who = " (user '%s')" % user if user else ""
    if alen == 0:
        return [{"cve": "CVE-2008-0960", "code": "SW-USM-HMAC-ABSENT",
                 "severity": "CRITICAL", "confidence": "confirmed",
                 "detail": ("SNMPv3 authFlag is set but msgAuthenticationParameters "
                            "is empty%s — the message asserts authentication while "
                            "carrying no HMAC at all." % who)}]
    if alen < USM_MIN_AUTH_LEN:
        return [{"cve": "CVE-2008-0960", "code": "SW-USM-HMAC-TRUNCATED",
                 "severity": "CRITICAL", "confidence": "confirmed",
                 "detail": ("SNMPv3 HMAC truncated to %d byte(s)%s; RFC 3414 requires "
                            "12. A vulnerable agent verifies only the bytes supplied, "
                            "cutting the forgery search space — the CVE-2008-0960 auth "
                            "bypass on the wire." % (alen, who))}]
    if alen not in USM_VALID_AUTH_LENS:
        return [{"cve": "CVE-2008-0960", "code": "SW-USM-HMAC-ODDLEN",
                 "severity": "LOW", "confidence": "attempt",
                 "detail": ("SNMPv3 HMAC length %d%s matches no standard algorithm "
                            "(12/16/24/32/48). Non-conforming agent or probing."
                            % (alen, who))}]
    return []


def detect_cisco_snmp_rce(varbinds, pdu):
    """CVE-2017-6736..6744 — Cisco IOS/IOS XE SNMP subsystem RCE (CISA KEV)."""
    out = []
    for vb in varbinds:
        oid = vb["oid"]
        for prefix, label in CISCO_SNMP_RCE_MIBS:
            if oid == prefix or oid.startswith(prefix + "."):
                arcs = oid.count(".") + 1
                if arcs > CISCO_RCE_ARC_THRESHOLD:
                    out.append({"cve": "CVE-2017-6736..6744",
                                "code": "SW-CISCO-SNMP-RCE-ATTEMPT",
                                "severity": "CRITICAL", "confidence": "attempt",
                                "detail": ("%s to %s with a %d-arc OID (%s...). "
                                           "Legitimate OIDs run ~14-20 arcs; the "
                                           "published PoC smuggles shellcode as OID "
                                           "sub-identifiers exactly this way. CISA "
                                           "KEV, exploited in the wild."
                                           % (pdu or "request", label, arcs, oid[:60]))})
                else:
                    out.append({"cve": "CVE-2017-6736..6744",
                                "code": "SW-CISCO-SNMP-RCE-EXPOSURE",
                                "severity": "MEDIUM", "confidence": "exposure",
                                "detail": ("%s touches %s, one of the MIBs Cisco "
                                           "named vulnerable. Patch level is not "
                                           "passively visible; confirm the target is "
                                           "fixed or exclude the MIB via snmp-server "
                                           "view." % (pdu or "request", label))})
                break
    return out


def detect_trapd_oversize(varbinds, community, usm, dport, pdu):
    """CVE-2025-68615 — net-snmp snmptrapd oversize-field stack overflow (attempt)."""
    if dport != 162:
        return []
    offenders = []
    if len(community) > TRAPD_FIELD_LIMIT:
        offenders.append("community string (%d bytes)" % len(community))
    val = usm.get("user_name") or ""
    if len(val) > TRAPD_FIELD_LIMIT:
        offenders.append("msgUserName (%d bytes)" % len(val))
    for vb in varbinds:
        if vb["value_tag"] == TAG_OCTET_STRING and vb["value_len"] > TRAPD_FIELD_LIMIT:
            offenders.append("varbind value for %s (%d bytes)"
                             % (vb["oid"], vb["value_len"]))
    if not offenders:
        return []
    return [{"cve": "CVE-2025-68615", "code": "SW-TRAPD-OVERSIZE-FIELD",
             "severity": "HIGH", "confidence": "attempt",
             "detail": ("Oversized field(s) in a %s to UDP/162: %s. net-snmp "
                        "snmptrapd copies user-supplied data into a fixed-length "
                        "stack buffer without validating length (unauthenticated "
                        "RCE). The overflowing field is not public, so treat this as "
                        "an anomaly rather than attribution."
                        % (pdu or "trap", "; ".join(offenders)))}]


def detect_netsnmp_vacm_malformed(varbinds, pdu_tag, pdu):
    """CVE-2022-24805/07/09/10 — malformed OID into net-snmp VACM tables (attempt)."""
    out = []
    is_set = pdu_tag in WRITE_PDUS
    is_getnext = pdu_tag in (0xA1, 0xA5)
    if not (is_set or is_getnext):
        return []
    for vb in varbinds:
        oid = vb["oid"]
        for entry, label, idx_count, cves in NETSNMP_VACM_TABLES:
            if not oid.startswith(entry + "."):
                continue
            tail = oid[len(entry) + 1:].split(".")
            if len(tail) < 2:
                continue          # bare column -- a normal walk position
            index_arcs = len(tail) - 1
            if index_arcs < idx_count:
                out.append({"cve": cves, "code": "SW-NETSNMP-VACM-MALFORMED-OID",
                            "severity": "HIGH" if is_set else "MEDIUM",
                            "confidence": "attempt",
                            "detail": ("%s to %s with a truncated INDEX: %d index "
                                       "arc(s) supplied, %d required (%s). The "
                                       "malformed-OID shape behind %s (out-of-bounds "
                                       "read / NULL deref in net-snmp < 5.9.2). "
                                       "Requires valid credentials, so treat a hit as "
                                       "post-compromise."
                                       % (pdu or "request", label, index_arcs,
                                          idx_count, oid, cves))})
            break
    return out


def run_cve_detectors(info, varbinds, community, dport, pdu):
    """Run every CVE detector over one decoded message; return a list of findings."""
    findings = []
    findings += detect_usm_hmac_truncation(info)
    pdu_tag = info.get("pdu_tag")
    if varbinds:
        findings += detect_cisco_snmp_rce(varbinds, pdu)
        if pdu_tag is not None:
            findings += detect_netsnmp_vacm_malformed(varbinds, pdu_tag, pdu)
    findings += detect_trapd_oversize(varbinds, community, info.get("usm") or {},
                                      dport, pdu)
    return findings


# --- frame → SNMP message extraction (raw pcap path) ------------------------
def _iter_udp(frames):
    """Yield (src, dst, dport, udp_payload) for every UDP datagram in an iterable of
    (ts, ethernet_frame_bytes). Handles IPv4, IPv6 (walking ext headers) and 802.1Q
    tags. Pure bytes — no scapy. Malformed frames are skipped."""
    import ipaddress as _ip
    for item in frames:
        frame = item[1] if isinstance(item, (tuple, list)) else item
        try:
            if len(frame) < 14:
                continue
            off = 12
            etype = (frame[off] << 8) | frame[off + 1]
            off += 2
            while etype in (0x8100, 0x88a8) and len(frame) >= off + 4:   # VLAN tags
                etype = (frame[off + 2] << 8) | frame[off + 3]
                off += 4
            if etype == 0x0800:                                          # IPv4
                if len(frame) < off + 20:
                    continue
                ihl = (frame[off] & 0x0F) * 4
                if frame[off + 9] != 17 or len(frame) < off + ihl + 8:   # proto UDP
                    continue
                src = str(_ip.IPv4Address(bytes(frame[off + 12:off + 16])))
                dst = str(_ip.IPv4Address(bytes(frame[off + 16:off + 20])))
                udp = frame[off + ihl:]
            elif etype == 0x86DD:                                        # IPv6
                if len(frame) < off + 40:
                    continue
                nxt = frame[off + 6]
                src = str(_ip.IPv6Address(bytes(frame[off + 8:off + 24])))
                dst = str(_ip.IPv6Address(bytes(frame[off + 24:off + 40])))
                p = off + 40
                hops = 0
                while nxt in (0, 43, 60, 44) and len(frame) >= p + 2 and hops < 8:
                    ext = 8 if nxt == 44 else (frame[p + 1] + 1) * 8
                    nxt = frame[p]
                    p += ext
                    hops += 1
                if nxt != 17 or len(frame) < p + 8:                      # proto UDP
                    continue
                udp = frame[p:]
            else:
                continue
            dport = (udp[2] << 8) | udp[3]
            payload = udp[8:]
            if payload:
                yield src, dst, dport, bytes(payload)
        except (IndexError, ValueError, TypeError):
            continue


def scan_frames(frames):
    """Decode SNMP (UDP 161/162) out of raw frames and run the CVE detectors.
    Returns a list of finding dicts, each with src/dst/dport/port added. Never
    raises — a frame that does not decode as SNMP is silently skipped."""
    findings = []
    for src, dst, dport, payload in _iter_udp(frames):
        if dport not in (161, 162):
            continue
        try:
            info = parse_snmp(payload)
        except BERError:
            continue
        except Exception:
            continue
        community = ""
        if info.get("version") in (0, 1):
            community = (info.get("community") or b"").decode("latin-1", "replace")
        pdu = PDU_NAMES.get(info.get("pdu_tag"))
        varbinds = []
        if info.get("pdu_tag") is not None and info.get("pdu_value") is not None:
            varbinds = _extract_varbinds(info["pdu_tag"], info["pdu_value"])
        for f in run_cve_detectors(info, varbinds, community, dport, pdu):
            f = dict(f)
            f["src"], f["dst"], f["dport"] = src, dst, dport
            findings.append(f)
    return findings
