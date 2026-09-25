"""Pure-Python IGMP decode from raw L2 frame bytes.

No Scapy, no socket — the self-test drives this directly. The IGMP message is
sliced out of the frame by the IP total-length field (padding-safe: Ethernet
minimum-frame padding must never be parsed as IGMPv3 source records), and IGMP
is parsed straight from the bytes rather than via a scapy IP binding (which only
binds IGMP at ttl==1 and would hide the off-link spoofed packets we watch for).
"""

import struct

# IGMP message types
T_QUERY = 0x11
T_V1_REPORT = 0x12
T_V2_REPORT = 0x16
T_V2_LEAVE = 0x17
T_V3_REPORT = 0x22

# v3 group-record types
GR_MODE_IS_INCLUDE = 1
GR_MODE_IS_EXCLUDE = 2
GR_CHANGE_TO_INCLUDE = 3
GR_CHANGE_TO_EXCLUDE = 4
GR_ALLOW_NEW = 5
GR_BLOCK_OLD = 6

ETH_P_IP = 0x0800
ETH_P_8021Q = 0x8100
IPPROTO_IGMP = 2
IP_OPT_ROUTER_ALERT = 148        # 0x94


def _mac(b):
    return ':'.join('%02x' % x for x in b)


def _ip(b):
    return '%d.%d.%d.%d' % (b[0], b[1], b[2], b[3])


def _checksum(data):
    """Standard 16-bit one's-complement checksum; 0 over a valid message."""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def decode_frame(raw):
    """Decode one raw Ethernet frame into an IGMP message dict, or None if it is
    not IPv4/IGMP. Handles a single 802.1Q tag."""
    if len(raw) < 14:
        return None
    src_mac = _mac(raw[6:12])
    p = 12
    etype = struct.unpack('!H', raw[p:p + 2])[0]
    p += 2
    if etype == ETH_P_8021Q:
        if len(raw) < p + 4:
            return None
        p += 2                                   # TCI
        etype = struct.unpack('!H', raw[p:p + 2])[0]
        p += 2
    if etype != ETH_P_IP:
        return None
    return _decode_ip(raw, p, src_mac)


def _decode_ip(raw, p, src_mac):
    if len(raw) < p + 20:
        return None
    vihl = raw[p]
    if (vihl >> 4) != 4:
        return None
    ihl = (vihl & 0x0f) * 4
    if ihl < 20 or len(raw) < p + ihl:
        return None
    total_len = struct.unpack('!H', raw[p + 2:p + 4])[0]
    ttl = raw[p + 8]
    proto = raw[p + 9]
    ip_src = _ip(raw[p + 12:p + 16])
    ip_dst = _ip(raw[p + 16:p + 20])
    if proto != IPPROTO_IGMP:
        return None
    # Router Alert option?
    router_alert = False
    opt = raw[p + 20:p + ihl]
    i = 0
    while i < len(opt):
        o = opt[i]
        if o == 0:                               # end of options
            break
        if o == 1:                               # NOP
            i += 1
            continue
        if i + 1 >= len(opt):
            break
        olen = opt[i + 1]
        if o == IP_OPT_ROUTER_ALERT:
            router_alert = True
        if olen < 2:
            break
        i += olen
    # Slice IGMP by IP total-length (padding-safe), clamped to captured bytes.
    end = min(p + total_len, len(raw)) if total_len >= ihl else len(raw)
    igmp = raw[p + ihl:end]
    return _decode_igmp(igmp, ttl=ttl, router_alert=router_alert,
                        src_mac=src_mac, ip_src=ip_src, ip_dst=ip_dst)


def _decode_igmp(b, ttl, router_alert, src_mac, ip_src, ip_dst):
    msg = {'src_mac': src_mac, 'ip_src': ip_src, 'ip_dst': ip_dst, 'ttl': ttl,
           'router_alert': router_alert, 'type': None, 'version': None,
           'kind': None, 'group': None, 'groups': [], 'sources': [],
           'checksum_ok': None, 'malformed': None, 'raw_len': len(b)}
    if len(b) < 8:
        msg['malformed'] = 'IGMP message shorter than 8 bytes'
        return msg
    mtype = b[0]
    msg['type'] = mtype
    msg['checksum_ok'] = (_checksum(b) == 0)

    if mtype == T_QUERY:
        # v1/v2 query is 8 bytes; v3 query is longer (has S/QRV/QQIC/numsrc).
        msg['group'] = _ip(b[4:8])
        if len(b) <= 8:
            msg['version'] = 2 if b[1] != 0 else 1
        else:
            msg['version'] = 3
            if len(b) >= 12:
                nsrc = struct.unpack('!H', b[10:12])[0]
                need = 12 + 4 * nsrc
                if len(b) < need:
                    msg['malformed'] = 'v3 query source count exceeds message'
                else:
                    msg['sources'] = [_ip(b[12 + 4 * i:16 + 4 * i]) for i in range(nsrc)]
        msg['kind'] = 'query'
        # A group-specific query names a group; a general query is 0.0.0.0.
        if msg['group'] == '0.0.0.0':
            msg['group'] = None
        return msg

    if mtype == T_V1_REPORT:
        msg['version'] = 1
        msg['kind'] = 'report'
        msg['group'] = _ip(b[4:8])
        return msg
    if mtype == T_V2_REPORT:
        msg['version'] = 2
        msg['kind'] = 'report'
        msg['group'] = _ip(b[4:8])
        return msg
    if mtype == T_V2_LEAVE:
        msg['version'] = 2
        msg['kind'] = 'leave'
        msg['group'] = _ip(b[4:8])
        return msg

    if mtype == T_V3_REPORT:
        msg['version'] = 3
        if len(b) < 8:
            msg['malformed'] = 'v3 report header short'
            return msg
        numgr = struct.unpack('!H', b[6:8])[0]
        i = 8
        recs = []
        for _ in range(numgr):
            if i + 8 > len(b):
                msg['malformed'] = 'v3 numgrp/length mismatch'
                break
            rtype = b[i]
            auxlen = b[i + 1]
            nsrc = struct.unpack('!H', b[i + 2:i + 4])[0]
            grp = _ip(b[i + 4:i + 8])
            i += 8
            need = 4 * nsrc + 4 * auxlen
            if i + need > len(b):
                msg['malformed'] = 'v3 numgrp/length mismatch'
                break
            srcs = [_ip(b[i + 4 * j:i + 4 * j + 4]) for j in range(nsrc)]
            i += need
            recs.append({'group': grp, 'rtype': rtype, 'sources': srcs})
        msg['groups'] = recs
        # Classify each record as join / leave (RFC 3376 semantics).
        for r in recs:
            join = _v3_is_join(r['rtype'], r['sources'])
            msg.setdefault('records', []).append(
                {'group': r['group'], 'kind': 'report' if join else 'leave',
                 'sources': r['sources'], 'rtype': r['rtype']})
        # A single-record report gets the top-level group/kind for convenience.
        if len(recs) == 1:
            msg['group'] = recs[0]['group']
            msg['sources'] = recs[0]['sources']
            msg['kind'] = ('report' if _v3_is_join(recs[0]['rtype'], recs[0]['sources'])
                           else 'leave')
        else:
            msg['kind'] = 'report'
        return msg

    msg['malformed'] = 'unknown IGMP type 0x%02x' % mtype
    return msg


def _v3_is_join(rtype, sources):
    """RFC 3376: EXCLUDE{} == join-all; INCLUDE{} == leave; ALLOW == join;
    BLOCK == leave; INCLUDE with sources == SSM join."""
    if rtype in (GR_MODE_IS_EXCLUDE, GR_CHANGE_TO_EXCLUDE):
        return True
    if rtype in (GR_MODE_IS_INCLUDE, GR_CHANGE_TO_INCLUDE):
        return bool(sources)                     # INCLUDE {} = leaving
    if rtype == GR_ALLOW_NEW:
        return True
    if rtype == GR_BLOCK_OLD:
        return False
    return True
