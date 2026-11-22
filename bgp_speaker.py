"""Receive-only BGP speaker for Ragnar — control-plane ground truth.

Unlike the passive BGP Path Watch (which sniffs BGP off the wire with tcpdump),
this module *establishes* a real BGP session with a configured router as a
RECEIVE-ONLY peer: it sends OPEN + KEEPALIVEs, learns the router's full Adj-RIB-In
from its UPDATEs, and NEVER advertises or withdraws a route of its own. That gives
authoritative control-plane truth (real AS-paths, next-hops, per-prefix churn)
which the path-asymmetry detector's correlator ties back to data-plane symptoms.

Layers (each independently unit-testable, no live peer required):
  * codec    — encode/decode BGP messages (RFC 4271 + 4-octet ASN RFC 6793)
  * framer   — TCP byte stream -> whole BGP messages (marker + length delimited)
  * RIB      — Adj-RIB-In keyed by prefix, with per-prefix churn/flap tracking
  * BGPSpeaker — the FSM (Idle->Connect->OpenSent->OpenConfirm->Established),
                 threaded, receive-only, with hold/keepalive timers

This is a monitoring pattern (like a route collector / a BMP alternative). It is
safe — it can't inject routes — but it does form an adjacency, so the peer router
must be configured to accept it. Everything is opt-in and start/stop controlled.
"""

import ipaddress
import socket
import struct
import threading
import time
from collections import deque

# --- constants --------------------------------------------------------------
BGP_PORT = 179
_MARKER = b'\xff' * 16
_HDR_LEN = 19
_MAX_MSG = 4096

MSG_OPEN, MSG_UPDATE, MSG_NOTIFICATION, MSG_KEEPALIVE, MSG_REFRESH = 1, 2, 3, 4, 5
_MSG_NAME = {1: 'OPEN', 2: 'UPDATE', 3: 'NOTIFICATION', 4: 'KEEPALIVE', 5: 'ROUTE-REFRESH'}

AS_TRANS = 23456                 # 2-byte placeholder for a 4-byte ASN in OPEN
CAP_MP_BGP = 1
CAP_ROUTE_REFRESH = 2
CAP_4OCTET_AS = 65

ATTR_ORIGIN, ATTR_ASPATH, ATTR_NEXTHOP = 1, 2, 3
ATTR_MED, ATTR_LOCALPREF, ATTR_COMMUNITIES = 4, 5, 8
ATTR_MP_REACH, ATTR_MP_UNREACH = 14, 15
AS_SET, AS_SEQUENCE = 1, 2
_ORIGIN_NAME = {0: 'IGP', 1: 'EGP', 2: 'Incomplete'}

# MP-BGP (RFC 4760): IPv6 NLRI rides in MP_REACH_NLRI / MP_UNREACH_NLRI
# attributes, not the base UPDATE fields. AFI 1 = IPv4, AFI 2 = IPv6; SAFI 1 =
# unicast. The RIB/correlator key on prefix strings, so once the codec decodes
# v6 NLRI they flow through unchanged. Receive-only: we still never originate.
AFI_IPV4, AFI_IPV6, SAFI_UNICAST = 1, 2, 1


class BGPError(Exception):
    pass


# --- codec: NLRI prefix (de)serialization ----------------------------------
def pack_prefix(cidr):
    """'10.0.0.0/8' -> BGP NLRI bytes: length-in-bits + ceil(bits/8) address."""
    net, length = cidr.split('/')
    length = int(length)
    octets = [int(x) for x in net.split('.')]
    nbytes = (length + 7) // 8
    return bytes([length]) + bytes(octets[:nbytes])


def unpack_prefixes(data):
    """Parse a run of BGP NLRI (length-bits + packed address) -> ['a.b.c.d/n']."""
    out, i, n = [], 0, len(data)
    while i < n:
        bits = data[i]
        i += 1
        nbytes = (bits + 7) // 8
        if bits > 32 or i + nbytes > n:
            raise BGPError('malformed NLRI')
        octs = list(data[i:i + nbytes]) + [0] * (4 - nbytes)
        out.append('%d.%d.%d.%d/%d' % (octs[0], octs[1], octs[2], octs[3], bits))
        i += nbytes
    return out


def unpack_mp_prefixes(data, afi):
    """Parse a run of MP-BGP NLRI (length-bits + packed address) for AFI 1
    (IPv4) or 2 (IPv6) -> ['addr/len']. Receive-side of RFC 4760."""
    if afi == AFI_IPV6:
        width, full, fam = 128, 16, socket.AF_INET6
    else:
        width, full, fam = 32, 4, socket.AF_INET
    out, i, n = [], 0, len(data)
    while i < n:
        bits = data[i]
        i += 1
        nbytes = (bits + 7) // 8
        if bits > width or i + nbytes > n:
            raise BGPError('malformed MP NLRI')
        raw = bytes(data[i:i + nbytes]) + b'\x00' * (full - nbytes)
        out.append('%s/%d' % (socket.inet_ntop(fam, raw), bits))
        i += nbytes
    return out


# --- codec: message headers + the messages we SEND -------------------------
def encode_header(msg_type, body):
    length = _HDR_LEN + len(body)
    if length > _MAX_MSG:
        raise BGPError('message too large')
    return _MARKER + struct.pack('!HB', length, msg_type) + body


def _encode_capability(code, value):
    return bytes([code, len(value)]) + value


def encode_open(my_as, hold_time, bgp_id, four_octet=True, route_refresh=True):
    """Encode an OPEN. Advertises 4-octet-ASN and route-refresh capabilities."""
    caps = b''
    if four_octet:
        caps += _encode_capability(CAP_4OCTET_AS, struct.pack('!I', my_as))
    if route_refresh:
        caps += _encode_capability(CAP_ROUTE_REFRESH, b'')
    # MP-BGP capability for IPv4-unicast (AFI 1) AND IPv6-unicast (AFI 2), so a
    # dual-stack peer sends us both families over the one session (RFC 4760).
    # Advertising a receive capability is not originating NLRI — still passive.
    caps += _encode_capability(CAP_MP_BGP, struct.pack('!HBB', AFI_IPV4, 0, SAFI_UNICAST))
    caps += _encode_capability(CAP_MP_BGP, struct.pack('!HBB', AFI_IPV6, 0, SAFI_UNICAST))
    opt = b''
    if caps:
        opt = bytes([2, len(caps)]) + caps          # optional param type 2 = capabilities
    two_byte_as = my_as if my_as <= 0xFFFF else AS_TRANS
    bid_int = struct.unpack('!I', socket.inet_aton(bgp_id))[0]
    body = struct.pack('!BHHIB', 4, two_byte_as, hold_time, bid_int, len(opt)) + opt
    return encode_header(MSG_OPEN, body)


def encode_keepalive():
    return encode_header(MSG_KEEPALIVE, b'')


def encode_notification(code, subcode, data=b''):
    return encode_header(MSG_NOTIFICATION, bytes([code, subcode]) + data)


# --- codec: decode the messages we RECEIVE ---------------------------------
def decode_open(body):
    ver, my_as, hold, bid = struct.unpack('!BHHI', body[:9])
    opt_len = body[9]
    opt = body[10:10 + opt_len]
    caps = {'four_octet_as': None, 'route_refresh': False, 'mp': []}
    i = 0
    while i + 2 <= len(opt):
        ptype, plen = opt[i], opt[i + 1]
        pval = opt[i + 2:i + 2 + plen]
        i += 2 + plen
        if ptype != 2:                              # only capabilities
            continue
        j = 0
        while j + 2 <= len(pval):
            code, clen = pval[j], pval[j + 1]
            cval = pval[j + 2:j + 2 + clen]
            j += 2 + clen
            if code == CAP_4OCTET_AS and len(cval) == 4:
                caps['four_octet_as'] = struct.unpack('!I', cval)[0]
            elif code == CAP_ROUTE_REFRESH:
                caps['route_refresh'] = True
            elif code == CAP_MP_BGP and len(cval) >= 4:
                afi, _r, safi = struct.unpack('!HBB', cval[:4])
                caps['mp'].append((afi, safi))
    real_as = caps['four_octet_as'] if (my_as == AS_TRANS and caps['four_octet_as']) else my_as
    return {'version': ver, 'my_as': real_as, 'hold_time': hold,
            'bgp_id': socket.inet_ntoa(struct.pack('!I', bid)), 'caps': caps}


def _decode_as_path(data, four_octet):
    """Decode AS_PATH attribute -> list of ASNs (flattened, sets shown too)."""
    asn_size = 4 if four_octet else 2
    fmt = '!I' if four_octet else '!H'
    path, i = [], 0
    while i + 2 <= len(data):
        _seg_type, count = data[i], data[i + 1]
        i += 2
        for _ in range(count):
            if i + asn_size > len(data):
                return path
            path.append(struct.unpack(fmt, data[i:i + asn_size])[0])
            i += asn_size
    return path


def decode_update(body, four_octet=True):
    """Decode an UPDATE -> {withdrawn[], announced[], origin, as_path[],
    next_hop, communities[], med, local_pref}."""
    wlen = struct.unpack('!H', body[:2])[0]
    withdrawn = unpack_prefixes(body[2:2 + wlen])
    pos = 2 + wlen
    palen = struct.unpack('!H', body[pos:pos + 2])[0]
    pos += 2
    attrs_end = pos + palen
    out = {'withdrawn': withdrawn, 'announced': [], 'origin': None,
           'as_path': [], 'next_hop': None, 'communities': [],
           'med': None, 'local_pref': None}
    i = pos
    while i + 3 <= attrs_end:
        flags, atype = body[i], body[i + 1]
        i += 2
        if flags & 0x10:                            # extended length
            alen = struct.unpack('!H', body[i:i + 2])[0]
            i += 2
        else:
            alen = body[i]
            i += 1
        aval = body[i:i + alen]
        i += alen
        if atype == ATTR_ORIGIN and aval:
            out['origin'] = _ORIGIN_NAME.get(aval[0], aval[0])
        elif atype == ATTR_ASPATH:
            out['as_path'] = _decode_as_path(aval, four_octet)
        elif atype == ATTR_NEXTHOP and len(aval) == 4:
            out['next_hop'] = socket.inet_ntoa(aval)
        elif atype == ATTR_MED and len(aval) == 4:
            out['med'] = struct.unpack('!I', aval)[0]
        elif atype == ATTR_LOCALPREF and len(aval) == 4:
            out['local_pref'] = struct.unpack('!I', aval)[0]
        elif atype == ATTR_COMMUNITIES:
            for k in range(0, len(aval) - 3, 4):
                hi, lo = struct.unpack('!HH', aval[k:k + 4])
                out['communities'].append('%d:%d' % (hi, lo))
        elif atype == ATTR_MP_REACH and len(aval) >= 5:
            # AFI(2) SAFI(1) NHlen(1) NextHop(var) Reserved(1) NLRI(var)
            afi, _safi, nhlen = struct.unpack('!HBB', aval[:4])
            nh = aval[4:4 + nhlen]
            if afi == AFI_IPV6 and len(nh) >= 16:
                # a v6 next-hop may carry global + link-local (RFC 2545); the
                # global (first 16 bytes) is what identifies the path.
                out['next_hop'] = socket.inet_ntop(socket.AF_INET6, nh[:16])
            elif afi == AFI_IPV4 and len(nh) >= 4:
                out['next_hop'] = socket.inet_ntoa(nh[:4])
            try:
                out['announced'] += unpack_mp_prefixes(aval[4 + nhlen + 1:], afi)
            except BGPError:
                pass
        elif atype == ATTR_MP_UNREACH and len(aval) >= 3:
            afi, _safi = struct.unpack('!HB', aval[:3])
            try:
                out['withdrawn'] += unpack_mp_prefixes(aval[3:], afi)
            except BGPError:
                pass
    # base UPDATE NLRI is IPv4-unicast only (RFC 4271); v6 arrived via MP_REACH
    # above, so append rather than overwrite.
    out['announced'] += unpack_prefixes(body[attrs_end:])
    return out


def decode_notification(body):
    code, sub = body[0], body[1]
    return {'code': code, 'subcode': sub, 'data': body[2:]}


# --- framer: TCP byte stream -> whole messages -----------------------------
class BGPFramer:
    """Accumulates bytes and yields complete (msg_type, body) messages. Validates
    the 16-byte marker and length bounds; raises BGPError on a corrupt stream."""

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data):
        self._buf.extend(data)
        out = []
        while len(self._buf) >= _HDR_LEN:
            if bytes(self._buf[:16]) != _MARKER:
                raise BGPError('bad marker (stream desync)')
            length, mtype = struct.unpack('!HB', self._buf[16:19])
            if length < _HDR_LEN or length > _MAX_MSG:
                raise BGPError('bad message length %d' % length)
            if len(self._buf) < length:
                break                               # wait for the rest
            body = bytes(self._buf[_HDR_LEN:length])
            del self._buf[:length]
            out.append((mtype, body))
        return out


# --- RIB: Adj-RIB-In with per-prefix churn tracking ------------------------
class RIB:
    """Adj-RIB-In: the routes the peer has advertised to us. Each prefix carries
    its current path plus churn stats — update/withdraw counts and a sliding
    window of change timestamps used to flag flapping."""

    def __init__(self, flap_window_s=60, flap_threshold=5, churn_cap=64):
        self._lock = threading.Lock()
        self._routes = {}          # prefix -> record
        self.flap_window_s = flap_window_s
        self.flap_threshold = flap_threshold
        self._churn_cap = churn_cap

    def _touch(self, prefix, now):
        r = self._routes.get(prefix)
        if r is None:
            r = {'prefix': prefix, 'first_seen': now, 'last_change': now,
                 'updates': 0, 'withdraws': 0, 'state': 'active',
                 'origin_as': None, 'as_path': [], 'prev_as_path': [],
                 'next_hop': None, 'communities': [],
                 '_changes': deque(maxlen=self._churn_cap)}
            self._routes[prefix] = r
        return r

    def apply_update(self, upd, now=None):
        """Apply a decoded UPDATE to the RIB, returning the list of changed
        prefixes for the correlator. Records churn."""
        now = now or time.time()
        changed = []
        origin_as = upd['as_path'][-1] if upd.get('as_path') else None
        with self._lock:
            for pfx in upd.get('announced', []):
                r = self._touch(pfx, now)
                new_path = upd.get('as_path') or []
                if r['state'] != 'active' or r['as_path'] != new_path or r['next_hop'] != upd.get('next_hop'):
                    r['last_change'] = now
                    r['_changes'].append(now)
                    # Remember the previous AS-path across a genuine path change so
                    # the correlator can show old -> new (which carrier moved, how).
                    if r['as_path'] and r['as_path'] != new_path:
                        r['prev_as_path'] = list(r['as_path'])
                r['state'] = 'active'
                r['updates'] += 1
                r['origin_as'] = origin_as
                r['as_path'] = new_path
                r['next_hop'] = upd.get('next_hop')
                r['communities'] = upd.get('communities') or []
                changed.append(pfx)
            for pfx in upd.get('withdrawn', []):
                r = self._touch(pfx, now)
                r['state'] = 'withdrawn'
                r['withdraws'] += 1
                r['last_change'] = now
                r['_changes'].append(now)
                changed.append(pfx)
        return changed

    def _flap_rate(self, r, now):
        cutoff = now - self.flap_window_s
        return sum(1 for t in r['_changes'] if t >= cutoff)

    def is_flapping(self, prefix, now=None):
        now = now or time.time()
        with self._lock:
            r = self._routes.get(prefix)
            return bool(r and self._flap_rate(r, now) >= self.flap_threshold)

    def lookup(self, ip):
        """Longest-prefix match for an IPv4 or IPv6 address -> the active route
        record (or None). Used by the correlator to attribute a data-plane
        event; same-family only, so a v6 target matches a v6 covering prefix."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best, best_len = None, -1
        with self._lock:
            for pfx, r in self._routes.items():
                if r['state'] != 'active':
                    continue
                try:
                    net = ipaddress.ip_network(pfx, strict=False)
                except ValueError:
                    continue
                if net.version == addr.version and addr in net and net.prefixlen > best_len:
                    best, best_len = r, net.prefixlen
        return self._public(best) if best else None

    def _public(self, r, now=None):
        now = now or time.time()
        return {'prefix': r['prefix'], 'state': r['state'],
                'origin_as': r['origin_as'], 'as_path': list(r['as_path']),
                'prev_as_path': list(r.get('prev_as_path') or []),
                'next_hop': r['next_hop'], 'communities': list(r['communities']),
                'updates': r['updates'], 'withdraws': r['withdraws'],
                'first_seen': r['first_seen'], 'last_change': r['last_change'],
                'change_age_s': round(now - r['last_change'], 1),
                'flap_rate': self._flap_rate(r, now),
                'flapping': self._flap_rate(r, now) >= self.flap_threshold}

    def snapshot(self, limit=200):
        now = time.time()
        with self._lock:
            recs = [self._public(r, now) for r in self._routes.values()]
        recs.sort(key=lambda x: (-x['flap_rate'], x['change_age_s']))
        return {'total': len(recs), 'active': sum(1 for r in recs if r['state'] == 'active'),
                'flapping': sum(1 for r in recs if r['flapping']), 'routes': recs[:limit]}


# --- receive-only speaker (FSM) --------------------------------------------
class BGPSpeaker:
    """Receive-only BGP FSM. Connects to `peer_ip`, negotiates OPEN, keeps the
    session alive with KEEPALIVEs, and feeds decoded UPDATEs into the RIB. It
    never sends an UPDATE, so it cannot advertise or withdraw a route."""

    def __init__(self, peer_ip, peer_as, local_as, router_id,
                 hold_time=90, connect_timeout=10, port=BGP_PORT, on_update=None):
        self.peer_ip = peer_ip
        self.peer_as = int(peer_as)
        self.local_as = int(local_as)
        self.router_id = router_id
        self.hold_time = hold_time
        self.connect_timeout = connect_timeout
        self.port = port
        self.on_update = on_update              # correlator hook: (upd, changed)
        self.rib = RIB()
        self.state = 'Idle'
        self.four_octet = False
        self.peer_info = {}
        self.error = None
        self.stats = {'updates': 0, 'keepalives': 0, 'notifications': 0,
                      'prefixes': 0, 'established_at': None}
        self._sock = None
        self._thread = None
        self._stop = threading.Event()

    # -- lifecycle --
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name='bgp-speaker-%s' % self.peer_ip)
        self._thread.start()

    def stop(self):
        self._stop.set()
        try:
            if self._sock:
                if self.state == 'Established':
                    try:
                        self._sock.sendall(encode_notification(6, 0))  # Cease
                    except OSError:
                        pass
                self._sock.close()
        except OSError:
            pass
        self.state = 'Idle'

    def status(self):
        return {'peer_ip': self.peer_ip, 'peer_as': self.peer_as,
                'local_as': self.local_as, 'state': self.state,
                'four_octet_as': self.four_octet, 'peer_info': self.peer_info,
                'error': self.error, 'stats': dict(self.stats),
                'rib': {'total': self.rib.snapshot(0)['total'],
                        'flapping': self.rib.snapshot(0)['flapping']}}

    # -- the FSM loop --
    def _run(self):
        try:
            self.state = 'Connect'
            self._sock = socket.create_connection((self.peer_ip, self.port),
                                                  timeout=self.connect_timeout)
            self._sock.settimeout(1.0)
            self._sock.sendall(encode_open(self.local_as, self.hold_time,
                                           self.router_id))
            self.state = 'OpenSent'
            framer = BGPFramer()
            last_ka = time.time()
            neg_hold = self.hold_time
            last_rx = time.time()
            while not self._stop.is_set():
                now = time.time()
                # keepalive every hold/3
                ka_int = max(1, neg_hold // 3) if neg_hold else 30
                if self.state in ('OpenConfirm', 'Established') and now - last_ka >= ka_int:
                    self._sock.sendall(encode_keepalive())
                    last_ka = now
                # hold timer expiry
                if neg_hold and self.state == 'Established' and now - last_rx > neg_hold:
                    raise BGPError('hold timer expired')
                try:
                    data = self._sock.recv(8192)
                except socket.timeout:
                    continue
                if not data:
                    raise BGPError('peer closed the connection')
                last_rx = now
                for mtype, body in framer.feed(data):
                    self._handle(mtype, body)
                    if mtype == MSG_OPEN:
                        neg_hold = min(neg_hold or self.hold_time,
                                       self.peer_info.get('hold_time') or self.hold_time)
                        self._sock.sendall(encode_keepalive())
                        self.state = 'OpenConfirm'
                    elif mtype == MSG_KEEPALIVE and self.state == 'OpenConfirm':
                        self.state = 'Established'
                        self.stats['established_at'] = now
        except (BGPError, OSError, struct.error) as e:
            self.error = str(e)
        finally:
            self.state = 'Idle'
            try:
                if self._sock:
                    self._sock.close()
            except OSError:
                pass

    def _handle(self, mtype, body):
        if mtype == MSG_OPEN:
            self.peer_info = decode_open(body)
            self.four_octet = bool(self.peer_info['caps'].get('four_octet_as'))
        elif mtype == MSG_KEEPALIVE:
            self.stats['keepalives'] += 1
        elif mtype == MSG_UPDATE:
            upd = decode_update(body, four_octet=self.four_octet)
            changed = self.rib.apply_update(upd)
            self.stats['updates'] += 1
            self.stats['prefixes'] = self.rib.snapshot(0)['total']
            if self.on_update:
                try:
                    self.on_update(upd, changed)
                except Exception:
                    pass
        elif mtype == MSG_NOTIFICATION:
            self.stats['notifications'] += 1
            n = decode_notification(body)
            self.error = 'peer NOTIFICATION code=%d sub=%d' % (n['code'], n['subcode'])


# --- self-test (no live peer: drives the codec/framer/RIB/FSM offline) -----
def selftest():
    scen = []

    def check(name, ok, detail=''):
        scen.append({'name': name, 'pass': bool(ok), 'detail': detail})

    # 1. prefix round-trip
    check('nlri-roundtrip',
          unpack_prefixes(pack_prefix('198.51.100.0/24') + pack_prefix('10.0.0.0/8'))
          == ['198.51.100.0/24', '10.0.0.0/8'])

    # 2. OPEN encode -> decode (4-octet ASN via AS_TRANS)
    ob = encode_open(4200000001, 90, '10.0.0.9')
    otype, obody = BGPFramer().feed(ob)[0]
    od = decode_open(obody)
    check('open-4octet-as', otype == MSG_OPEN and od['my_as'] == 4200000001
          and od['bgp_id'] == '10.0.0.9' and od['caps']['route_refresh'], str(od))

    # 3. framer reassembles a message split across two recv() chunks
    f = BGPFramer()
    parts = encode_keepalive()
    check('framer-split', f.feed(parts[:5]) == [] and
          f.feed(parts[5:]) == [(MSG_KEEPALIVE, b'')])

    # 4. build a real UPDATE and decode it
    origin = bytes([0x40, ATTR_ORIGIN, 1, 0])                       # IGP
    aspath_val = bytes([AS_SEQUENCE, 2]) + struct.pack('!II', 65001, 65002)
    aspath = bytes([0x40, ATTR_ASPATH, len(aspath_val)]) + aspath_val
    nexthop = bytes([0x40, ATTR_NEXTHOP, 4]) + socket.inet_aton('10.0.0.2')
    attrs = origin + aspath + nexthop
    ubody = struct.pack('!H', 0) + struct.pack('!H', len(attrs)) + attrs + pack_prefix('93.184.216.0/24')
    umsg = encode_header(MSG_UPDATE, ubody)
    _t, ub = BGPFramer().feed(umsg)[0]
    ud = decode_update(ub, four_octet=True)
    check('update-decode', ud['announced'] == ['93.184.216.0/24'] and
          ud['as_path'] == [65001, 65002] and ud['next_hop'] == '10.0.0.2'
          and ud['origin'] == 'IGP', str(ud))

    # 5. RIB churn/flap + longest-prefix lookup
    rib = RIB(flap_window_s=60, flap_threshold=3)
    now = time.time()
    for k in range(4):                                            # 4 changes -> flapping
        rib.apply_update({'announced': ['93.184.216.0/24'], 'withdrawn': [],
                          'as_path': [65001, 65002 + k], 'next_hop': '10.0.0.2',
                          'communities': []}, now=now + k)
    rib.apply_update({'announced': ['10.0.0.0/8'], 'withdrawn': [],
                      'as_path': [65001], 'next_hop': '10.0.0.1', 'communities': []}, now=now)
    lp = rib.lookup('93.184.216.10')
    check('rib-flap-and-lpm', rib.is_flapping('93.184.216.0/24', now + 4)
          and lp and lp['prefix'] == '93.184.216.0/24' and lp['origin_as'] == 65005, str(lp))

    # 6. NOTIFICATION round-trip
    _t, nb = BGPFramer().feed(encode_notification(6, 2, b'x'))[0]
    nd = decode_notification(nb)
    check('notification', nd['code'] == 6 and nd['subcode'] == 2 and nd['data'] == b'x')

    # 7. MP-BGP IPv6 (RFC 4760): OPEN advertises AFI 2, and an MP_REACH_NLRI
    #    UPDATE decodes a v6 prefix + v6 next-hop into the RIB.
    check('open-mp-afi-v6', (AFI_IPV6, SAFI_UNICAST) in od['caps']['mp'], str(od['caps']['mp']))

    v6nlri = bytes([48]) + socket.inet_pton(socket.AF_INET6, '2606:2800:220::')[:6]
    nh6 = socket.inet_pton(socket.AF_INET6, '2001:db8:a::1')
    mpval = struct.pack('!HBB', AFI_IPV6, SAFI_UNICAST, 16) + nh6 + b'\x00' + v6nlri
    mp = bytes([0x80, ATTR_MP_REACH, len(mpval)]) + mpval
    attrs6 = origin + aspath + mp
    ubody6 = struct.pack('!H', 0) + struct.pack('!H', len(attrs6)) + attrs6
    _t, ub6 = BGPFramer().feed(encode_header(MSG_UPDATE, ubody6))[0]
    ud6 = decode_update(ub6, four_octet=True)
    check('update-decode-v6-mp-reach',
          ud6['announced'] == ['2606:2800:220::/48'] and
          ud6['next_hop'] == '2001:db8:a::1' and ud6['as_path'] == [65001, 65002], str(ud6))

    rib6 = RIB()
    rib6.apply_update(ud6, now=now)
    lp6 = rib6.lookup('2606:2800:220::10')
    check('rib-v6-lpm', bool(lp6 and lp6['prefix'] == '2606:2800:220::/48'
          and lp6['origin_as'] == 65002), str(lp6))

    unval = struct.pack('!HB', AFI_IPV6, SAFI_UNICAST) + v6nlri
    un = bytes([0x80, ATTR_MP_UNREACH, len(unval)]) + unval
    ubodyU = struct.pack('!H', 0) + struct.pack('!H', len(un)) + un
    _t, ubU = BGPFramer().feed(encode_header(MSG_UPDATE, ubodyU))[0]
    udU = decode_update(ubU, four_octet=True)
    check('update-decode-v6-mp-unreach', udU['withdrawn'] == ['2606:2800:220::/48'], str(udU))

    passed = all(s['pass'] for s in scen)
    return {'success': passed, 'scenarios': scen}


if __name__ == '__main__':
    import json
    import sys
    r = selftest()
    for s in r['scenarios']:
        print('  [%s] %s%s' % ('PASS' if s['pass'] else 'FAIL', s['name'],
                               '' if s['pass'] else '  -> ' + s['detail']))
    print('BGP speaker self-test:', 'OK' if r['success'] else 'FAILED')
    if '--json' in sys.argv:
        print(json.dumps(r, indent=2, default=str))
    sys.exit(0 if r['success'] else 1)
