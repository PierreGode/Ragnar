#!/usr/bin/env python3
"""blewatch.py — passive Bluetooth Low Energy attack monitor (Ragnar).

The BLE counterpart to the Wi-Fi/ND spoofing watchers: a passive reader of the
BLE link layer captured by an external sniffer (Adafruit Bluefruit LE Sniffer /
nRF51822, or any nRF-Sniffer device feeding a pcap). It flags advertising-layer
impersonation (beacon/device clones, two radios sharing one address), rogue-AdvA
beacon spoofing, advertising floods / BLE-spam tooling, and connection-layer
abuse it can see when the sniffer follows a link (CONNECT_IND races, version /
feature swaps, Just-Works pairing downgrade, forced re-pair storms).

Detection only — it never transmits a BLE packet or scans. **Passive:** the
sniffer hardware does the RX; blewatch only parses. Field extraction is a
hand-rolled raw-byte parser over the captured BLE Link-Layer PDU (no dissector),
so `--self-test`/`--replay` need no radio and the self-test needs no Scapy.
Findings carry a stable BLE-0xx code; findings about one PDU are merged into a
single alert (highest severity + evidence).

Capture link types understood (pcap DLT):
  * 251  LINKTYPE_BLUETOOTH_LE_LL             (bare LE LL PDU)
  * 256  LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR   (10-byte BLE pseudo-header + PDU)
  * 272  LINKTYPE_NORDIC_BLE                  (Nordic sniffer header + PDU) *

* The Nordic (272) header layout is version-dependent and is parsed best-effort;
  it is UNVALIDATED against real hardware on this box (no sniffer attached). The
  256/251 paths are the canonical Wireshark BLE link types and are fully tested.

See docs/blewatch.md.
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import time
from collections import defaultdict, deque

MODULE = 'blewatch'
SEV_RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

# pcap data-link types we can strip down to a BLE LL PDU.
DLT_BLE_LL = 251
DLT_BLE_LL_PHDR = 256
DLT_NORDIC_BLE = 272

ADV_ACCESS_ADDR = 0x8E89BED6          # fixed AA of the advertising physical channel
ADV_CHANNELS = (37, 38, 39)

# Advertising PDU types (header low nibble).
ADV_IND, ADV_DIRECT_IND, ADV_NONCONN_IND = 0x0, 0x1, 0x2
SCAN_REQ, SCAN_RSP, CONNECT_IND, ADV_SCAN_IND, ADV_EXT_IND = 0x3, 0x4, 0x5, 0x6, 0x7
_ADVNAME = {0x0: 'ADV_IND', 0x1: 'ADV_DIRECT_IND', 0x2: 'ADV_NONCONN_IND',
            0x3: 'SCAN_REQ', 0x4: 'SCAN_RSP', 0x5: 'CONNECT_IND',
            0x6: 'ADV_SCAN_IND', 0x7: 'ADV_EXT_IND'}

# AD (advertising data) structure types we read.
AD_FLAGS = 0x01
AD_UUID16_INC, AD_UUID16_ALL = 0x02, 0x03
AD_UUID128_INC, AD_UUID128_ALL = 0x06, 0x07
AD_NAME_SHORT, AD_NAME_FULL = 0x08, 0x09
AD_TXPOWER = 0x0A
AD_SVCDATA16, AD_SVCDATA128 = 0x16, 0x21
AD_APPEARANCE = 0x19
AD_MANUF = 0xFF

# LL control opcodes (data physical channel).
LL_TERMINATE_IND = 0x02
LL_FEATURE_REQ, LL_FEATURE_RSP = 0x08, 0x09
LL_VERSION_IND = 0x0C
SMP_CID = 0x0006                       # L2CAP channel for the Security Manager
SMP_PAIRING_REQ, SMP_PAIRING_RSP = 0x01, 0x02
SMP_AUTHREQ_MITM = 0x04                # AuthReq MITM-protection bit

# Vendor / spam signatures. company -> short name (manufacturer-specific data).
_COMPANY = {0x004C: 'Apple', 0x0006: 'Microsoft', 0x00E0: 'Google',
            0x0075: 'Samsung', 0x0157: 'Huawei'}
# Known BLE-spam shapes: (company, first-byte(s) of manuf data). Seen flooding
# from rotating random addresses by Flipper Zero / "Sour Apple" / Android spam.
_SPAM_MANUF = {
    (0x004C, 0x07): 'Apple proximity-pairing popup (AirPods/Nearby spam)',
    (0x004C, 0x0F): 'Apple Nearby-action spam',
    (0x0006, 0x03): 'Microsoft Swift Pair spam',
    (0x0075, 0x42): 'Samsung Easy-Setup spam',
}
_SPAM_SVC = {0xFE2C: 'Google Fast Pair spam', 0xFD5A: 'Fast Pair spam'}

CODES = {
    'BLE-001': ('high', 'known device AdvA advertising a changed identity (name/services) — clone'),
    'BLE-002': ('critical', 'one AdvA advertising conflicting payloads at once — two radios (impersonation)'),
    'BLE-003': ('high', 'one public address bound to conflicting device names (identity reuse)'),
    'BLE-004': ('medium', 'resolvable-private-address rotation storm (tracking evasion / adv churn)'),
    'BLE-005': ('high', 'trusted beacon UUID advertised from a new address (beacon spoof)'),
    'BLE-006': ('medium', 'advertising-interval collapse — beacon flood from one AdvA'),
    'BLE-007': ('high', 'advertising flood across many AdvAs (advertising-channel DoS)'),
    'BLE-008': ('high', 'CONNECT_IND targeting a known device (connection hijack attempt)'),
    'BLE-009': ('critical', 'duplicate CONNECT_IND racing a central for one device (connection MITM)'),
    'BLE-010': ('high', 'LL_VERSION_IND identity changed mid-connection (device swap)'),
    'BLE-011': ('high', 'pairing downgraded to Just-Works where baseline required MITM protection'),
    'BLE-012': ('high', 'repeated LL_TERMINATE_IND / reconnect for one device (forced re-pair window)'),
    'BLE-013': ('high', 'advertising flood matching BLE-spam tooling signatures'),
    'BLE-014': ('medium', 'malformed / truncated BLE PDU or over-running AD structure'),
    'BLE-015': ('low', 'manufacturer-specific data shape inconsistent with the claimed vendor'),
    'BLE-016': ('high', 'untrusted AdvA advertising a protected service-UUID set (GATT masquerade)'),
}

DEFAULTS = {
    'trusted_devices': {},            # addr -> {name, services[], mitm:bool}  (or a bare list of addrs)
    'beacon_baseline': [],            # [{uuid, addr}] of legitimate iBeacon/Eddystone UUIDs
    'trusted_services': [],           # service UUIDs only a trusted AdvA may advertise
    'adv_flood_window_s': 10.0, 'adv_flood_count': 60,          # per single AdvA
    'advertiser_flood_window_s': 10.0, 'advertiser_flood_count': 25,  # distinct AdvAs
    'rpa_window_s': 10.0, 'rpa_count': 40,                      # distinct RPAs
    'clone_flap_window_s': 15.0, 'clone_flap_count': 4,         # distinct payloads / AdvA
    'connect_window_s': 10.0,
    'terminate_window_s': 20.0, 'terminate_count': 4,
}


# ===========================================================================
# pcap reader (classic libpcap, either endianness) -> (dlt, frame, ts)
# ===========================================================================
def iter_pcap(path):
    with open(path, 'rb') as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
            end, nano = '>', magic == b'\xa1\xb2\x3c\x4d'
        elif magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
            end, nano = '<', magic == b'\x4d\x3c\xb2\xa1'
        else:
            raise ValueError('not a classic pcap file (bad magic)')
        dlt = struct.unpack(end + 'I', gh[20:24])[0]
        rechdr = struct.Struct(end + 'IIII')
        while True:
            h = fh.read(16)
            if len(h) < 16:
                break
            ts_s, ts_f, caplen, _orig = rechdr.unpack(h)
            data = fh.read(caplen)
            if len(data) < caplen:
                break
            ts = ts_s + ts_f / (1e9 if nano else 1e6)
            yield dlt, data, ts


def _s8(x):
    return x - 256 if x >= 128 else x


def strip_to_ll(dlt, frame):
    """Return (meta, ll_pdu_bytes) for a captured frame, or (None, None) if the
    link type is not BLE / the frame is too short. meta carries channel/rssi/crc
    where the pseudo-header provides them."""
    meta = {'channel': None, 'rssi': None, 'crc_ok': None}
    if dlt == DLT_BLE_LL:
        return meta, frame
    if dlt == DLT_BLE_LL_PHDR:
        if len(frame) < 10:
            return None, None
        meta['channel'] = frame[0]
        meta['rssi'] = _s8(frame[1])
        flags = frame[8] | (frame[9] << 8)
        if flags & 0x0400:                       # CRC checked
            meta['crc_ok'] = bool(flags & 0x0800)
        return meta, frame[10:]
    if dlt == DLT_NORDIC_BLE:
        # Best-effort (version-dependent, UNVALIDATED on hardware): board(1),
        # header_len(1), then header_len bytes [flags, channel, rssi, ...].
        if len(frame) < 3:
            return None, None
        hlen = frame[1]
        if len(frame) < 2 + hlen or hlen < 3:
            return None, None
        hdr = frame[2:2 + hlen]
        meta['crc_ok'] = bool(hdr[0] & 0x01)
        meta['channel'] = hdr[1]
        meta['rssi'] = -hdr[2]
        return meta, frame[2 + hlen:]
    return None, None


# ===========================================================================
# BLE Link-Layer PDU parser
# ===========================================================================
def _addr(b, i):
    # BLE addresses are little-endian on the wire; present MSB-first.
    return ':'.join('%02x' % x for x in b[i + 5:i - 1 if i else None:-1]) if i else \
        ':'.join('%02x' % x for x in b[5::-1])


def _addr_at(b, i):
    return ':'.join('%02x' % b[i + k] for k in range(5, -1, -1))


def _addr_type(tx_add):
    return 'random' if tx_add else 'public'


def _rpa_class(addr, addr_type):
    """For a random address classify the top two bits of the MSB:
    01=resolvable, 11=static, 00=non-resolvable."""
    if addr_type != 'random':
        return 'public'
    try:
        msb = int(addr.split(':')[0], 16)
    except (ValueError, IndexError):
        return 'random'
    top = (msb >> 6) & 0x3
    return {0b01: 'rpa', 0b11: 'static', 0b00: 'nonresolvable'}.get(top, 'random')


def _be16(b, i):
    return (b[i] << 8) | b[i + 1]


def _le16(b, i):
    return b[i] | (b[i + 1] << 8)


def _uuid16(v):
    return '%04x' % v


def _uuid128(b):
    # 16-byte UUID, little-endian on the wire -> canonical 8-4-4-4-12 string.
    r = bytes(b[15::-1])
    h = r.hex()
    return '%s-%s-%s-%s-%s' % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def parse_ad(payload):
    """Walk AD structures. Returns a dict of extracted fields + 'malformed'."""
    ad = {'flags': None, 'name': None, 'uuids16': [], 'uuids128': [],
          'svc_data': [], 'manuf': None, 'appearance': None, 'malformed': False,
          'raw': bytes(payload)}
    i, n = 0, len(payload)
    while i < n:
        ln = payload[i]
        if ln == 0:
            break                                   # zero-length pads the PDU out
        if i + 1 + ln > n:
            ad['malformed'] = True
            break
        atype = payload[i + 1]
        val = payload[i + 2:i + 1 + ln]
        if atype == AD_FLAGS and val:
            ad['flags'] = val[0]
        elif atype in (AD_NAME_SHORT, AD_NAME_FULL):
            try:
                ad['name'] = val.decode('utf-8', 'replace')
            except Exception:
                ad['name'] = val.decode('latin-1', 'replace')
        elif atype in (AD_UUID16_INC, AD_UUID16_ALL):
            for k in range(0, len(val) - 1, 2):
                ad['uuids16'].append(_uuid16(_le16(val, k)))
        elif atype in (AD_UUID128_INC, AD_UUID128_ALL) and len(val) >= 16:
            ad['uuids128'].append(_uuid128(val[:16]))
        elif atype == AD_SVCDATA16 and len(val) >= 2:
            ad['svc_data'].append({'uuid': _uuid16(_le16(val, 0)), 'data': val[2:]})
        elif atype == AD_SVCDATA128 and len(val) >= 16:
            ad['svc_data'].append({'uuid': _uuid128(val[:16]), 'data': val[16:]})
        elif atype == AD_APPEARANCE and len(val) >= 2:
            ad['appearance'] = _le16(val, 0)
        elif atype == AD_MANUF and len(val) >= 2:
            ad['manuf'] = {'company': _le16(val, 0), 'data': val[2:]}
        i += 1 + ln
    return ad


def _ibeacon(manuf):
    """Decode an iBeacon frame from Apple manufacturer data, or None."""
    if not manuf or manuf.get('company') != 0x004C:
        return None
    d = manuf['data']
    if len(d) >= 23 and d[0] == 0x02 and d[1] == 0x15:
        return {'uuid': _uuid128(bytes(d[2:18][::-1])) if False else d[2:18].hex(),
                'major': _be16(d, 18), 'minor': _be16(d, 20), 'tx': _s8(d[22])}
    return None


def parse_ble(ll, meta):
    """Parse a BLE Link-Layer PDU (bytes starting at the Access Address).
    Returns a dict describing the PDU. Never raises; truncation -> malformed."""
    d = {'kind': None, 'malformed': None, 'channel': meta.get('channel'),
         'rssi': meta.get('rssi'), 'crc_ok': meta.get('crc_ok')}
    if ll is None or len(ll) < 6:
        d['kind'] = 'malformed'
        d['malformed'] = 'PDU shorter than LL header'
        return d
    aa = struct.unpack_from('<I', ll, 0)[0]
    hdr0, length = ll[4], ll[5]
    d['aa'] = aa
    is_adv = (aa == ADV_ACCESS_ADDR) or (meta.get('channel') in ADV_CHANNELS)
    body = ll[6:6 + (length & 0x3F if is_adv else length)]
    if len(body) < (length & 0x3F if is_adv else length):
        d['kind'] = 'malformed'
        d['malformed'] = 'PDU payload truncated (len field %d, have %d)' % (length, len(body))
        return d
    try:
        if is_adv:
            return _parse_adv(d, hdr0, body)
        return _parse_data(d, hdr0, body)
    except (IndexError, struct.error, ValueError) as e:
        d['kind'] = 'malformed'
        d['malformed'] = 'PDU body: %s' % e
        return d


def _parse_adv(d, hdr0, body):
    ptype = hdr0 & 0x0F
    d['kind'] = 'adv'
    d['adv_type'] = ptype
    d['adv_name'] = _ADVNAME.get(ptype, 'ADV_0x%X' % ptype)
    d['tx_add'] = (hdr0 >> 6) & 1
    d['rx_add'] = (hdr0 >> 7) & 1
    d['adva'] = d['inita'] = d['target'] = d['conn_aa'] = None
    d['ad'] = None
    if ptype in (ADV_IND, ADV_NONCONN_IND, ADV_SCAN_IND, SCAN_RSP):
        if len(body) < 6:
            raise ValueError('adv PDU missing AdvA')
        d['adva'] = _addr_at(body, 0)
        d['addr_type'] = _addr_type(d['tx_add'])
        d['ad'] = parse_ad(body[6:])
    elif ptype == ADV_DIRECT_IND:
        if len(body) < 12:
            raise ValueError('ADV_DIRECT_IND short')
        d['adva'] = _addr_at(body, 0)
        d['target'] = _addr_at(body, 6)
        d['addr_type'] = _addr_type(d['tx_add'])
    elif ptype == SCAN_REQ:
        if len(body) < 12:
            raise ValueError('SCAN_REQ short')
        d['inita'] = _addr_at(body, 0)
        d['adva'] = _addr_at(body, 6)
        d['addr_type'] = _addr_type(d['rx_add'])
    elif ptype == CONNECT_IND:
        if len(body) < 34:
            raise ValueError('CONNECT_IND short')
        d['inita'] = _addr_at(body, 0)
        d['adva'] = _addr_at(body, 6)
        d['addr_type'] = _addr_type(d['rx_add'])
        d['conn_aa'] = struct.unpack_from('<I', body, 12)[0]
    elif ptype == ADV_EXT_IND:
        d['adv_ext'] = True                          # extended header: identity not parsed here
    return d


def _parse_data(d, hdr0, body):
    d['kind'] = 'data'
    llid = hdr0 & 0x03
    d['llid'] = llid
    d['ll_ctrl'] = d['smp'] = None
    if llid == 0x03 and body:                        # LL Control PDU
        op = body[0]
        ctrl = {'opcode': op}
        if op == LL_VERSION_IND and len(body) >= 6:
            ctrl.update({'version': body[1], 'company': _le16(body, 2),
                         'subversion': _le16(body, 4)})
        ctrl['name'] = {LL_TERMINATE_IND: 'LL_TERMINATE_IND',
                        LL_VERSION_IND: 'LL_VERSION_IND',
                        LL_FEATURE_REQ: 'LL_FEATURE_REQ',
                        LL_FEATURE_RSP: 'LL_FEATURE_RSP'}.get(op, 'LL_CTRL_0x%02X' % op)
        d['ll_ctrl'] = ctrl
    elif llid in (0x01, 0x02) and len(body) >= 4:    # L2CAP; start fragment carries the header
        l2_len, cid = _le16(body, 0), _le16(body, 2)
        if cid == SMP_CID and len(body) >= 5:
            code = body[4]
            smp = {'code': code}
            if code in (SMP_PAIRING_REQ, SMP_PAIRING_RSP) and len(body) >= 8:
                smp['authreq'] = body[7]
                smp['mitm'] = bool(body[7] & SMP_AUTHREQ_MITM)
            d['smp'] = smp
    return d


# ===========================================================================
# Engine
# ===========================================================================
def _norm_trusted(td):
    """trusted_devices as a bare list of addrs OR a dict addr->meta -> dict."""
    out = {}
    if isinstance(td, dict):
        for k, v in td.items():
            out[k.lower()] = v if isinstance(v, dict) else {}
    elif isinstance(td, (list, tuple)):
        for k in td:
            out[str(k).lower()] = {}
    return out


class BleWatch:
    def __init__(self, config=None, emit=None):
        c = dict(DEFAULTS)
        c.update(config or {})
        self.cfg = c
        self.emit = emit or (lambda a: None)
        self.trusted = _norm_trusted(c.get('trusted_devices'))
        self.beacons = {str(b.get('uuid', '')).lower(): str(b.get('addr', '')).lower()
                        for b in (c.get('beacon_baseline') or []) if b.get('uuid')}
        self.trusted_services = {str(u).lower() for u in (c.get('trusted_services') or [])}
        # state
        self._adv = {}                               # adva -> {hash,name,services,flaps}
        self._pub_names = defaultdict(set)           # public addr -> {names}
        self._adv_times = defaultdict(deque)         # adva -> ts (per-AdvA flood)
        self._advertisers = deque()                  # (ts, adva) distinct-advertiser flood
        self._spam = deque()                         # (ts, adva) spam-shaped adv
        self._rpa = deque()                          # ts of distinct RPAs
        self._rpa_seen = {}                          # rpa addr -> last ts
        self._connect = defaultdict(deque)           # adva -> (ts, inita)
        self._conn = {}                              # conn AA -> {adva, ts}
        self._version = {}                           # aa/adva -> (version,company,subversion)
        self._term = defaultdict(deque)              # adva -> ts of TERMINATE
        self.frames = 0
        self.stats = defaultdict(int)

    @staticmethod
    def _trim(dq, ts, window, keyed=True):
        while dq and ts - (dq[0][0] if keyed else dq[0]) > window:
            dq.popleft()

    # -- public entry --------------------------------------------------------
    def process_frame(self, dlt, frame, ts=None):
        meta, ll = strip_to_ll(dlt, frame)
        if ll is None:
            return None
        return self.process_pdu(ll, meta, ts)

    def process_pdu(self, ll, meta=None, ts=None):
        pkt = parse_ble(ll, meta or {})
        if ts is None:
            ts = time.time()
        self.frames += 1
        f = []
        if pkt.get('malformed'):
            f.append(('BLE-014', pkt['malformed']))
            return self._merge(pkt, f, ts)
        if pkt['kind'] == 'adv':
            if pkt.get('adv_type') == CONNECT_IND:
                f += self._on_connect(pkt, ts)
            else:
                f += self._on_adv(pkt, ts)
        elif pkt['kind'] == 'data':
            f += self._on_data(pkt, ts)
        if f:
            return self._merge(pkt, f, ts)
        return None

    # -- advertising ---------------------------------------------------------
    def _identity(self, ad):
        """The stable identity of an advertiser: its name + sorted service UUIDs.
        Dynamic manufacturer/sensor payload is deliberately excluded so a sensor
        beacon streaming data does not look like a clone."""
        svcs = tuple(sorted(u.lower() for u in ad.get('uuids16', []) + ad.get('uuids128', [])))
        return (ad.get('name'), svcs)

    def _services(self, ad):
        return [u.lower() for u in ad.get('uuids16', []) + ad.get('uuids128', [])] + \
               [s['uuid'].lower() for s in ad.get('svc_data', [])]

    def _spam_label(self, ad):
        m = ad.get('manuf')
        if m and (m['company'], (m['data'][0] if m['data'] else -1)) in _SPAM_MANUF:
            return _SPAM_MANUF[(m['company'], m['data'][0])]
        for s in ad.get('svc_data', []):
            try:
                u = int(s['uuid'], 16)
            except (ValueError, TypeError):
                continue
            if u in _SPAM_SVC:
                return _SPAM_SVC[u]
        return None

    def _on_adv(self, pkt, ts):
        out = []
        adva = pkt.get('adva')
        ad = pkt.get('ad')
        if not adva or ad is None:
            return out                               # DIRECT_IND / SCAN_REQ / ext: no AD identity
        if ad.get('malformed'):
            out.append(('BLE-014', 'AD structure overruns the %s PDU from %s'
                        % (pkt['adv_name'], adva)))
        akey = adva.lower()
        rpa_class = _rpa_class(adva, pkt.get('addr_type', 'public'))
        ident = self._identity(ad)
        services = self._services(ad)
        phash = hashlib.blake2b(ad['raw'], digest_size=8).hexdigest()
        trusted_here = akey in self.trusted

        # --- BLE-001 / BLE-002 clone & impersonation --------------------------
        prev = self._adv.get(akey)
        if prev is None:
            self._adv[akey] = {'hash': phash, 'ident': ident, 'flaps': deque()}
        else:
            if phash != prev['hash']:
                fl = prev['flaps']
                fl.append((ts, phash))
                self._trim(fl, ts, self.cfg['clone_flap_window_s'])
                distinct = len({h for _t, h in fl})
                if distinct >= self.cfg['clone_flap_count']:
                    out.append(('BLE-002', '%s is advertising %d conflicting payloads within '
                                '%.0fs — two radios sharing one address (impersonation)'
                                % (adva, distinct + 1, self.cfg['clone_flap_window_s'])))
                elif ident != prev['ident']:
                    out.append(('BLE-001', '%s identity changed %r -> %r — device clone'
                                % (adva, prev['ident'], ident)))
                prev['hash'], prev['ident'] = phash, ident
        # A configured trusted device whose advertised identity does not match its
        # baseline is always a clone, even on the first drift.
        if trusted_here:
            base = self.trusted[akey]
            bname = base.get('name')
            if bname and ad.get('name') and ad['name'] != bname:
                out.append(('BLE-001', '%s (trusted) advertises name %r, baseline %r — clone'
                            % (adva, ad['name'], bname)))

        # --- BLE-003 public address reused across names -----------------------
        if pkt.get('addr_type') == 'public' and ad.get('name'):
            names = self._pub_names[akey]
            names.add(ad['name'])
            if len(names) >= 2:
                out.append(('BLE-003', 'public address %s bound to conflicting names %s — '
                            'identity reuse' % (adva, sorted(names))))

        # --- BLE-005 beacon spoof / BLE-016 service masquerade ----------------
        ib = _ibeacon(ad.get('manuf'))
        beacon_uuids = ([ib['uuid'].lower()] if ib else []) + \
            [s['uuid'].lower() for s in ad.get('svc_data', [])]
        for u in beacon_uuids:
            base_addr = self.beacons.get(u)
            if base_addr and base_addr != akey:
                out.append(('BLE-005', 'beacon UUID %s advertised from %s, baseline %s — '
                            'beacon spoof' % (u, adva, base_addr)))
        if self.trusted_services and not trusted_here:
            hit = self.trusted_services.intersection(services)
            if hit:
                out.append(('BLE-016', 'untrusted %s advertises protected service %s — GATT '
                            'service masquerade' % (adva, sorted(hit))))

        # --- BLE-015 vendor shape mismatch ------------------------------------
        m = ad.get('manuf')
        if m and m['company'] in _COMPANY and len(m['data']) < 2:
            out.append(('BLE-015', '%s claims vendor %s but carries a %d-byte manufacturer '
                        'payload — shape mismatch' % (adva, _COMPANY[m['company']], len(m['data']))))

        # --- BLE-004 RPA rotation storm ---------------------------------------
        if rpa_class == 'rpa':
            if akey not in self._rpa_seen:
                self._rpa.append(ts)
            self._rpa_seen[akey] = ts
            self._trim(self._rpa, ts, self.cfg['rpa_window_s'], keyed=False)
            if len(self._rpa) >= self.cfg['rpa_count']:
                out.append(('BLE-004', '%d distinct resolvable-private addresses in %.0fs — '
                            'rotation storm (tracking evasion / adv churn)'
                            % (len(self._rpa), self.cfg['rpa_window_s'])))

        # --- BLE-006 per-AdvA flood -------------------------------------------
        dq = self._adv_times[akey]
        dq.append(ts)
        self._trim(dq, ts, self.cfg['adv_flood_window_s'], keyed=False)
        if len(dq) >= self.cfg['adv_flood_count']:
            out.append(('BLE-006', '%s advertising-interval collapse (%d adv in %.0fs) — '
                        'beacon flood' % (adva, len(dq), self.cfg['adv_flood_window_s'])))

        # --- BLE-007 / BLE-013 advertiser flood (generic vs spam-shaped) ------
        self._advertisers.append((ts, akey))
        self._trim(self._advertisers, ts, self.cfg['advertiser_flood_window_s'])
        spam = self._spam_label(ad)
        if spam:
            self._spam.append((ts, akey))
            self._trim(self._spam, ts, self.cfg['advertiser_flood_window_s'])
        distinct_adv = len({a for _t, a in self._advertisers})
        if distinct_adv >= self.cfg['advertiser_flood_count']:
            distinct_spam = len({a for _t, a in self._spam})
            if spam and distinct_spam >= self.cfg['advertiser_flood_count'] // 2:
                out.append(('BLE-013', 'advertising flood of %d addresses matching BLE-spam '
                            'tooling (%s)' % (distinct_spam, spam)))
            else:
                out.append(('BLE-007', '%d distinct advertisers in %.0fs — advertising-channel '
                            'flood' % (distinct_adv, self.cfg['advertiser_flood_window_s'])))
        return out

    # -- CONNECT_IND ---------------------------------------------------------
    def _on_connect(self, pkt, ts):
        out = []
        adva, inita = pkt.get('adva'), pkt.get('inita')
        if not adva:
            return out
        akey = adva.lower()
        if pkt.get('conn_aa') is not None:
            self._conn[pkt['conn_aa']] = {'adva': akey, 'ts': ts}
        known = akey in self.trusted or akey in self._adv
        if known:
            out.append(('BLE-008', 'CONNECT_IND from %s to known device %s — connection '
                        'hijack attempt' % (inita, adva)))
        dq = self._connect[akey]
        dq.append((ts, inita))
        self._trim(dq, ts, self.cfg['connect_window_s'])
        inits = {i for _t, i in dq if i}
        if len(inits) >= 2:
            out.append(('BLE-009', '%d initiators raced CONNECT_IND for %s within %.0fs — '
                        'connection MITM' % (len(inits), adva, self.cfg['connect_window_s'])))
        # A CONNECT_IND arriving inside a recent TERMINATE storm = forced re-pair.
        term = self._term.get(akey)
        if term:
            self._trim(term, ts, self.cfg['terminate_window_s'], keyed=False)
            if len(term) >= self.cfg['terminate_count']:
                out.append(('BLE-012', 'reconnect to %s after %d LL_TERMINATE_IND in %.0fs — '
                            'forced re-pair window' % (adva, len(term),
                            self.cfg['terminate_window_s'])))
        return out

    # -- data channel --------------------------------------------------------
    def _on_data(self, pkt, ts):
        out = []
        aa = pkt.get('aa')
        dev = self._conn.get(aa)
        key = dev['adva'] if dev else ('aa:%08x' % aa)
        ctrl = pkt.get('ll_ctrl')
        if ctrl:
            if ctrl['opcode'] == LL_VERSION_IND and 'version' in ctrl:
                sig = (ctrl['version'], ctrl['company'], ctrl['subversion'])
                prev = self._version.get(key)
                if prev is not None and prev != sig:
                    out.append(('BLE-010', 'LL_VERSION_IND for %s changed %r -> %r mid-connection '
                                '— device swap' % (key, prev, sig)))
                self._version[key] = sig
            elif ctrl['opcode'] == LL_TERMINATE_IND:
                dq = self._term[key]
                dq.append(ts)
                self._trim(dq, ts, self.cfg['terminate_window_s'], keyed=False)
                if len(dq) >= self.cfg['terminate_count']:
                    out.append(('BLE-012', '%d LL_TERMINATE_IND for %s in %.0fs — forced '
                                're-pair / disconnect storm' % (len(dq), key,
                                self.cfg['terminate_window_s'])))
        smp = pkt.get('smp')
        if smp and 'mitm' in smp:
            base = self.trusted.get(key if dev else '', {})
            want_mitm = base.get('mitm')
            if want_mitm and not smp['mitm']:
                out.append(('BLE-011', 'pairing with %s requests Just-Works (no MITM) where the '
                            'baseline requires MITM protection — downgrade' % key))
        return out

    # -- merge + emit --------------------------------------------------------
    def _merge(self, pkt, findings, ts):
        seen, uniq = set(), []
        for code, detail in findings:
            if code not in seen:
                seen.add(code)
                uniq.append((code, detail))
        worst = max(uniq, key=lambda c: SEV_RANK[CODES[c[0]][0]])
        alert = {
            'ts': ts, 'module': MODULE, 'severity': CODES[worst[0]][0],
            'kind': pkt.get('kind'), 'pdu': pkt.get('adv_name')
            or (pkt.get('ll_ctrl') or {}).get('name'),
            'adva': pkt.get('adva'), 'inita': pkt.get('inita'),
            'channel': pkt.get('channel'), 'rssi': pkt.get('rssi'),
            'codes': [c for c, _ in uniq], 'summary': worst[1],
            'evidence': [{'code': c, 'severity': CODES[c][0], 'detail': d}
                         for c, d in sorted(uniq, key=lambda x: -SEV_RANK[CODES[x[0]][0]])],
        }
        self.stats[alert['severity']] += 1
        self.emit(alert)
        return alert


# ===========================================================================
# Capture front ends
# ===========================================================================
def run_replay(path, guard):
    for dlt, frame, ts in iter_pcap(path):
        try:
            guard.process_frame(dlt, frame, ts)
        except Exception:
            continue                                 # one bad frame never kills the run


def find_sniffer():
    """Best-effort locate an attached nRF/Bluefruit LE sniffer serial device.
    Returns a device path or None. Honours $RAGNAR_BLE_SNIFFER."""
    env = os.environ.get('RAGNAR_BLE_SNIFFER')
    if env:
        return env if os.path.exists(env) else None
    import glob
    for pat in ('/dev/serial/by-id/*Sniffer*', '/dev/serial/by-id/*nRF*',
                '/dev/serial/by-id/*Segger*', '/dev/serial/by-id/*Bluefruit*'):
        hits = glob.glob(pat)
        if hits:
            return sorted(hits)[0]
    # Fall back to a bare CDC-ACM port only if exactly one is present.
    acm = sorted(glob.glob('/dev/ttyACM*'))
    return acm[0] if len(acm) == 1 else None


def run_live(device, guard, seconds, fifo=None):
    """Drive the Nordic nRF Sniffer extcap to a temp pcap and replay it. Requires
    the vendor extcap helper (nrf_sniffer_ble.py) on PATH / in common locations.
    UNVALIDATED on this box (no sniffer); the parser path is what the self-test
    exercises."""
    import shutil
    import subprocess
    import tempfile
    helper = None
    for cand in ('nrf_sniffer_ble.py', 'nrf_sniffer_ble'):
        helper = shutil.which(cand) or helper
    for p in ('/usr/lib/x86_64-linux-gnu/wireshark/extcap/nrf_sniffer_ble.py',
              os.path.expanduser('~/.config/wireshark/extcap/nrf_sniffer_ble.py'),
              '/usr/lib/wireshark/extcap/nrf_sniffer_ble.py'):
        if not helper and os.path.exists(p):
            helper = p
    if not helper:
        raise RuntimeError('nRF Sniffer extcap helper not found; capture a pcap with '
                           'Wireshark + nRF Sniffer and use --replay')
    fd, pcap = tempfile.mkstemp(suffix='.pcap')
    os.close(fd)
    cmd = [helper, '--capture', '--extcap-interface', device, '--fifo', pcap]
    sys.stderr.write('blewatch: %s on %s for %ds (extcap)\n' % (os.path.basename(helper),
                     device, seconds))
    proc = subprocess.Popen(cmd)
    try:
        proc.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    try:
        run_replay(pcap, guard)
    finally:
        try:
            os.remove(pcap)
        except OSError:
            pass


def make_emitter(out_fh, echo):
    def emit(a):
        if out_fh:
            out_fh.write(json.dumps(a) + '\n')
            out_fh.flush()
        if echo:
            sys.stderr.write('  !! [%s] %s %s :: %s\n' % (a['severity'], a.get('pdu') or '',
                             ','.join(a['codes']), a['summary']))
    return emit


def main(argv=None):
    ap = argparse.ArgumentParser(prog='blewatch',
                                 description='Passive BLE attack monitor (detection-only).')
    ap.add_argument('-i', '--device', help='sniffer serial device (default: autodetect)')
    ap.add_argument('--replay', help='replay a BLE pcap instead of live capture')
    ap.add_argument('--seconds', type=int, default=20, help='live capture duration')
    ap.add_argument('-c', '--config', help='JSON config (trusted_devices/beacons + thresholds)')
    ap.add_argument('--jsonl', '-o', help="JSON-lines output path ('-' = stdout)")
    ap.add_argument('--echo', action='store_true', help='echo alerts to stderr')
    ap.add_argument('--list-devices', action='store_true', help='print the autodetected sniffer')
    ap.add_argument('--self-test', action='store_true')
    args = ap.parse_args(argv)

    if args.self_test:
        import blewatch_selftest
        return blewatch_selftest.run(verbose=True)
    if args.list_devices:
        dev = find_sniffer()
        print(dev or '(no nRF/Bluefruit LE sniffer found)')
        return 0 if dev else 1

    cfg = {}
    if args.config:
        with open(args.config) as f:
            cfg = json.load(f)
    out_fh = sys.stdout if args.jsonl == '-' else (open(args.jsonl, 'a') if args.jsonl else None)
    guard = BleWatch(cfg, emit=make_emitter(out_fh, args.echo or not args.jsonl))

    if args.replay:
        run_replay(args.replay, guard)
    else:
        dev = args.device or find_sniffer()
        if not dev:
            sys.stderr.write('error: no BLE sniffer found (set $RAGNAR_BLE_SNIFFER, pass '
                             '-i, or use --replay).\n')
            return 2
        try:
            run_live(dev, guard, args.seconds)
        except KeyboardInterrupt:
            pass
        except RuntimeError as e:
            sys.stderr.write('error: %s\n' % e)
            return 2
    sys.stderr.write('blewatch: %d PDUs, alerts %s\n' % (guard.frames, dict(guard.stats)))
    if out_fh and out_fh is not sys.stdout:
        out_fh.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
