#!/usr/bin/env python3
"""isiswatch.py — passive IS-IS security scanner (Ragnar).

Companion to ospfwatch/eigrpwatch. Passive-first, detection-only: it listens for
IS-IS PDUs and flags security-relevant posture and anomalies. It never transmits
IS-IS, forms adjacencies, injects LSPs, or otherwise touches the control plane.

IS-IS rides directly on Layer 2 (ISO CLNS in 802.3 frames with an LLC header
where DSAP == SSAP == 0xFE), so the scanner must sit on the same broadcast domain
/ VLAN as the adjacency, or be fed frames via a SPAN/mirror or a passive tap, and
the NIC must receive the IS-IS multicast MACs (01:80:C2:00:00:14 AllL1IS,
:15 AllL2IS) — hence promiscuous capture.

The binary TLV parser is pure Python (no Scapy), so `--self-test` runs with no
Scapy and no NIC. Scapy is imported lazily for live capture only.

Deps: Python 3.9+, Scapy (live capture only). See docs/isiswatch.md.
"""

import argparse
import json
import os
import struct
import sys
import time
from collections import OrderedDict, deque

# --- IS-IS PDU types (low 5 bits of the type byte) --------------------------
PDU_L1_LAN_IIH = 15
PDU_L2_LAN_IIH = 16
PDU_P2P_IIH = 17
PDU_L1_LSP = 18
PDU_L2_LSP = 20
PDU_L1_CSNP = 24
PDU_L2_CSNP = 25
PDU_L1_PSNP = 26
PDU_L2_PSNP = 27

_LAN_IIH = {PDU_L1_LAN_IIH, PDU_L2_LAN_IIH}
_LSP = {PDU_L1_LSP, PDU_L2_LSP}
_CSNP = {PDU_L1_CSNP, PDU_L2_CSNP}
_PSNP = {PDU_L1_PSNP, PDU_L2_PSNP}

# --- TLV codes --------------------------------------------------------------
TLV_AREA = 1
TLV_IS_NEIGH = 2            # legacy narrow IS reachability
TLV_PADDING = 8
TLV_LSP_ENTRIES = 9
TLV_AUTH = 10
TLV_EXT_IS_REACH = 22       # wide metrics (RFC 5305)
TLV_PROTO_SUPPORTED = 129
TLV_IP_INT_REACH = 128      # legacy narrow IPv4
TLV_IP_EXT_REACH = 130      # legacy narrow IPv4 external
TLV_IP_IF_ADDR = 132
TLV_EXT_IP_REACH = 135      # wide IPv4 (RFC 5305)
TLV_HOSTNAME = 137
TLV_MT_IS_REACH = 222
TLV_MT_IP_REACH = 235
TLV_THREE_WAY = 240         # P2P three-way adjacency (RFC 5303)

_NARROW_TLVS = {TLV_IS_NEIGH, TLV_IP_INT_REACH, TLV_IP_EXT_REACH}

# --- Authentication TLV auth-type byte --------------------------------------
AUTH_CLEARTEXT = 1
AUTH_HMAC_MD5 = 54          # RFC 5304
AUTH_GENERIC_CRYPTO = 3     # RFC 5310 (HMAC-SHA family)
_AUTH_KNOWN = {AUTH_CLEARTEXT, AUTH_HMAC_MD5, AUTH_GENERIC_CRYPTO}

DIS_MAX_PRIORITY = 127
SEQ_HIGH = 0xFFFFFF00       # LSP seq this near the wrap == seq-number attack

# --- severity ---------------------------------------------------------------
SEV_RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


# ===========================================================================
# Pure-Python IS-IS frame + PDU parser
# ===========================================================================
def _fmt_id(b):
    """6-byte system-id -> 'xxxx.xxxx.xxxx'."""
    h = b.hex()
    return '.'.join(h[i:i + 4] for i in range(0, 12, 4))


def _fmt_lspid(b):
    """8-byte LSP-id -> 'xxxx.xxxx.xxxx.YY-ZZ'."""
    return '{}.{:02x}-{:02x}'.format(_fmt_id(b[:6]), b[6], b[7])


def _fmt_area(b):
    return b.hex()


class _Malformed(Exception):
    pass


def _walk_tlvs(buf):
    """Yield (tlv_type, value_bytes) from a TLV blob; raise on overrun."""
    i, n = 0, len(buf)
    while i < n:
        if i + 2 > n:
            raise _Malformed('truncated TLV header')
        ttype = buf[i]
        tlen = buf[i + 1]
        i += 2
        if i + tlen > n:
            raise _Malformed('TLV length {} overruns PDU'.format(tlen))
        yield ttype, buf[i:i + tlen]
        i += tlen


def _isis_offset(raw):
    """Locate the IS-IS payload start (0x83) after Ethernet/802.1Q/LLC. Returns
    (offset, src_mac_str) or (None, None). The FE FE 03 83 signature — LLC
    DSAP/SSAP OSI + control UI + IRPD — is distinctive at the L2 boundary and
    handles tagged/untagged and present/absent 802.3 length uniformly."""
    if len(raw) < 17:
        return None, None
    sig = raw.find(b'\xfe\xfe\x03\x83', 12, 40)
    if sig < 0:
        return None, None
    src = ':'.join('{:02x}'.format(x) for x in raw[6:12])
    return sig + 3, src


def parse_isis_frame(raw):
    """Parse one raw L2 frame into an IS-IS PDU dict, or None if it isn't IS-IS.

    Returns keys: kind ('iih'/'lsp'/'csnp'/'psnp'), level (1/2/None for p2p),
    p2p (bool), system_id, src_mac, areas, auth_present, auth_type, hostname,
    priority, holding_time, lifetime, seq, overload, lsp_id, three_way, padding,
    narrow_metrics, tlv_types, malformed (None or reason)."""
    off, src_mac = _isis_offset(raw)
    if off is None:
        return None
    pdu = {'kind': None, 'level': None, 'p2p': False, 'system_id': None,
           'src_mac': src_mac, 'areas': [], 'auth_present': False,
           'auth_type': None, 'hostname': None, 'priority': None,
           'holding_time': None, 'lifetime': None, 'seq': None, 'overload': False,
           'lsp_id': None, 'three_way': False, 'padding': False,
           'narrow_metrics': False, 'tlv_types': [], 'malformed': None,
           'pdu_type': None, 'pdu_len_field': None,
           'trailing_len': 0, 'trailing_nonzero': False}
    b = raw[off:]
    try:
        if len(b) < 8:
            raise _Malformed('common header truncated')
        if b[0] != 0x83:
            return None
        id_len = b[3] or 6
        ptype = b[4] & 0x1f
        pdu['pdu_type'] = ptype
        max_area = b[7]  # noqa: F841 (parsed for completeness)
        body = b[8:]
        plen = None                              # IS-IS PDU Length field (from 0x83)

        if ptype in _LAN_IIH or ptype == PDU_P2P_IIH:
            pdu['kind'] = 'iih'
            if ptype == PDU_L1_LAN_IIH:
                pdu['level'] = 1
            elif ptype == PDU_L2_LAN_IIH:
                pdu['level'] = 2
            else:
                pdu['p2p'] = True
            if len(body) < 1 + id_len + 2 + 2:
                raise _Malformed('IIH header truncated')
            j = 1                                   # skip circuit type
            pdu['system_id'] = _fmt_id(body[j:j + id_len]); j += id_len
            pdu['holding_time'] = struct.unpack('!H', body[j:j + 2])[0]; j += 2
            plen = struct.unpack('!H', body[j:j + 2])[0]; j += 2   # PDU length
            if ptype in _LAN_IIH:
                if len(body) < j + 1 + (id_len + 1):
                    raise _Malformed('LAN IIH header truncated')
                pdu['priority'] = body[j] & 0x7f; j += 1
                j += id_len + 1                      # LAN ID
            else:
                if len(body) < j + 1:
                    raise _Malformed('P2P IIH header truncated')
                j += 1                               # local circuit id
            tlvs = body[j:]

        elif ptype in _LSP:
            pdu['kind'] = 'lsp'
            pdu['level'] = 1 if ptype == PDU_L1_LSP else 2
            need = 2 + 2 + (id_len + 2) + 4 + 2 + 1
            if len(body) < need:
                raise _Malformed('LSP header truncated')
            plen = struct.unpack('!H', body[0:2])[0]; j = 2        # PDU length
            pdu['lifetime'] = struct.unpack('!H', body[j:j + 2])[0]; j += 2
            lspid = body[j:j + id_len + 2]; j += id_len + 2
            pdu['lsp_id'] = _fmt_lspid(lspid)
            pdu['system_id'] = _fmt_id(lspid[:6])
            pdu['seq'] = struct.unpack('!I', body[j:j + 4])[0]; j += 4
            j += 2                                    # checksum
            flags = body[j]; j += 1
            pdu['overload'] = bool(flags & 0x04)
            tlvs = body[j:]

        elif ptype in _CSNP or ptype in _PSNP:
            pdu['kind'] = 'csnp' if ptype in _CSNP else 'psnp'
            pdu['level'] = 1 if ptype in (PDU_L1_CSNP, PDU_L1_PSNP) else 2
            if len(body) < 2 + (id_len + 1):
                raise _Malformed('SNP header truncated')
            plen = struct.unpack('!H', body[0:2])[0]; j = 2        # PDU length
            pdu['system_id'] = _fmt_id(body[j:j + id_len])   # source id
            j += id_len + 1
            if ptype in _CSNP:
                j += 2 * (id_len + 2)                 # start + end LSP id
            tlvs = body[j:]
        else:
            return None                               # unknown PDU type: ignore

        # Bound the TLV region by the IS-IS PDU Length field. The kernel/NIC pads
        # every frame to the 60-byte Ethernet minimum, so a short PDU arrives with
        # trailing zeros; walking to the captured end parses them as type=0/len=0
        # TLVs (or trips a bogus overrun on a kept FCS / snaplen cut). PDU Length is
        # the authoritative end of the PDU — everything past it is padding-or-smuggle.
        pdu['pdu_len_field'] = plen
        tlv_start = len(body) - len(tlvs)             # == j
        if plen and 8 <= plen and tlv_start <= (plen - 8) <= len(body):
            trailing = tlvs[(plen - 8) - tlv_start:]
            tlvs = tlvs[:(plen - 8) - tlv_start]
        elif plen and (plen - 8) > len(body):
            trailing = b''                            # PDU claims more than captured
            pdu['malformed'] = pdu['malformed'] or \
                'pdu-length {} exceeds captured {} bytes'.format(plen, len(body) + 8)
        else:
            trailing = b''                            # no/implausible length: fall back
        # All-zero trailer is benign Ethernet padding; any non-zero byte is data
        # smuggled past the PDU end (covert channel / Etherleak) — surface it.
        if trailing:
            pdu['trailing_len'] = len(trailing)
            if trailing.strip(b'\x00'):
                pdu['trailing_nonzero'] = True

        for ttype, val in _walk_tlvs(tlvs):
            pdu['tlv_types'].append(ttype)
            if ttype == TLV_AREA:
                k = 0
                while k < len(val):
                    alen = val[k]; k += 1
                    if k + alen > len(val):
                        raise _Malformed('area entry overruns TLV')
                    pdu['areas'].append(_fmt_area(val[k:k + alen])); k += alen
            elif ttype == TLV_AUTH:
                pdu['auth_present'] = True
                pdu['auth_type'] = val[0] if val else None
                if val and val[0] == AUTH_CLEARTEXT:
                    pdu['auth_pw_len'] = len(val) - 1
                    pdu['auth_pw_first'] = chr(val[1]) if len(val) > 1 else ''
            elif ttype == TLV_HOSTNAME:
                pdu['hostname'] = val.decode('ascii', 'replace')
            elif ttype == TLV_PADDING:
                pdu['padding'] = True
            elif ttype == TLV_THREE_WAY:
                pdu['three_way'] = True
            elif ttype in _NARROW_TLVS:
                pdu['narrow_metrics'] = True
    except _Malformed as e:
        pdu['malformed'] = str(e)
    except Exception as e:                            # any parse surprise: one PDU
        pdu['malformed'] = '{}: {}'.format(type(e).__name__, e)
    if pdu['kind'] is None and pdu['malformed'] is None:
        return None
    return pdu


# ===========================================================================
# Detector engine
# ===========================================================================
class IsisWatch:
    """Stateful passive detector. Feed PDUs via observe(); read snapshot()."""

    def __init__(self, baseline=None, churn_threshold=5, churn_window=20.0):
        baseline = baseline or {}
        self.known = set(baseline.get('known_systems') or [])
        self.expected_areas = set(baseline.get('expected_areas') or [])
        self.expected_auth = baseline.get('expected_auth')
        self.learn_window = float(baseline.get('learn_window') or 0)
        self.churn_threshold = int(churn_threshold)
        self.churn_window = float(churn_window)
        self._start = None
        self._learned = set()
        # per (system, level) auth kinds seen: 'keyed' / 'unkeyed'
        self._auth_seen = {}
        # LSP re-flood tracking: lsp_id -> deque[timestamps]
        self._lsp_times = {}
        # findings: (code, system, level) -> record
        self.findings = OrderedDict()
        self.pdu_count = 0
        self.systems = {}          # system_id -> {hostname, areas, levels, macs}

    # -- finding bookkeeping --------------------------------------------------
    def _add(self, code, severity, system, level, detail, now):
        key = (code, system, level)
        rec = self.findings.get(key)
        if rec is None:
            self.findings[key] = {
                'code': code, 'severity': severity, 'system': system,
                'level': level, 'detail': detail, 'count': 1,
                'first_seen': now, 'last_seen': now}
        else:
            rec['count'] += 1
            rec['last_seen'] = now
            rec['detail'] = detail

    def _learning(self, now):
        return self.learn_window > 0 and (now - self._start) < self.learn_window

    def observe(self, pdu, now=None):
        if pdu is None:
            return
        if now is None:
            now = time.time()
        if self._start is None:
            self._start = now
        self.pdu_count += 1
        sid = pdu.get('system_id')
        lvl = pdu.get('level')

        if pdu.get('malformed'):
            self._add('ISIS-MALFORMED', 'medium', sid or '?', lvl,
                      'structurally inconsistent PDU: ' + pdu['malformed'], now)
            return
        if pdu.get('trailing_nonzero'):
            self._add('ISIS-TRAILING-DATA', 'medium', sid or '?', lvl,
                      '{} non-zero byte(s) after the declared PDU length — data '
                      'smuggled past the PDU end (covert channel / Etherleak)'
                      .format(pdu.get('trailing_len') or 0), now)
        if not sid:
            return

        s = self.systems.setdefault(sid, {'hostname': None, 'areas': set(),
                                           'levels': set(), 'macs': set()})
        if pdu.get('hostname'):
            s['hostname'] = pdu['hostname']
        s['areas'].update(pdu.get('areas') or [])
        if lvl:
            s['levels'].add(lvl)
        if pdu.get('src_mac'):
            s['macs'].add(pdu['src_mac'])

        # Learn window: absorb system-ids as known.
        if self._learning(now):
            self._learned.add(sid)

        self._check_auth(pdu, sid, lvl, now)
        self._check_rogue(pdu, sid, lvl, now)
        self._check_area(pdu, sid, lvl, now)
        if pdu['kind'] == 'lsp':
            self._check_lsp(pdu, sid, lvl, now)
        if pdu['kind'] == 'iih':
            self._check_iih(pdu, sid, lvl, now)

    # -- individual detectors -------------------------------------------------
    def _check_auth(self, pdu, sid, lvl, now):
        if pdu['kind'] not in ('iih', 'lsp'):
            return
        at = pdu.get('auth_type')
        if not pdu.get('auth_present'):
            sev = 'high' if self.expected_auth else 'medium'
            self._add('ISIS-AUTH-MISSING', sev, sid, lvl,
                      'PDU with no Authentication TLV (spoofing / LSP-injection '
                      'exposure)', now)
            self._auth_seen.setdefault((sid, lvl), set()).add('unkeyed')
        elif at == AUTH_CLEARTEXT:
            pw_len = pdu.get('auth_pw_len', 0)
            first = pdu.get('auth_pw_first', '')
            self._add('ISIS-AUTH-CLEARTEXT', 'critical', sid, lvl,
                      'cleartext password on the wire (len {}, starts {!r}…)'
                      .format(pw_len, first), now)
            self._auth_seen.setdefault((sid, lvl), set()).add('unkeyed')
        elif at == AUTH_HMAC_MD5:
            self._add('ISIS-AUTH-HMAC-MD5', 'medium', sid, lvl,
                      'deprecated HMAC-MD5 (RFC 5304); move to RFC 5310 HMAC-SHA',
                      now)
            self._auth_seen.setdefault((sid, lvl), set()).add('keyed')
        elif at == AUTH_GENERIC_CRYPTO:
            self._auth_seen.setdefault((sid, lvl), set()).add('keyed')
        else:
            self._add('ISIS-AUTH-UNKNOWN', 'low', sid, lvl,
                      'non-standard authentication type {}'.format(at), now)
            self._auth_seen.setdefault((sid, lvl), set()).add('keyed')

        kinds = self._auth_seen.get((sid, lvl)) or set()
        if 'keyed' in kinds and 'unkeyed' in kinds:
            self._add('ISIS-AUTH-MIXED', 'medium', sid, lvl,
                      'same system seen both authenticated and unauthenticated',
                      now)

    def _check_rogue(self, pdu, sid, lvl, now):
        if pdu['kind'] not in ('iih', 'lsp'):
            return
        # No baseline and no learn window => stay quiet (no crying wolf).
        if not self.known and self.learn_window == 0:
            return
        if self._learning(now):
            return
        allowed = self.known | self._learned
        if sid not in allowed:
            self._add('ISIS-ROGUE-SYSTEM', 'high', sid, lvl,
                      'system-id not in the known/learned baseline', now)

    def _check_area(self, pdu, sid, lvl, now):
        if lvl != 1 or not self.expected_areas or not pdu.get('areas'):
            return
        outside = [a for a in pdu['areas'] if a not in self.expected_areas]
        if outside:
            self._add('ISIS-AREA-MISMATCH', 'medium', sid, lvl,
                      'L1 area(s) {} outside expected {}'.format(
                          outside, sorted(self.expected_areas)), now)

    def _check_lsp(self, pdu, sid, lvl, now):
        if pdu.get('lifetime') == 0:
            self._add('ISIS-LSP-PURGE', 'high', sid, lvl,
                      'LSP {} Remaining Lifetime 0 (purge / blackhole)'.format(
                          pdu.get('lsp_id')), now)
        if pdu.get('overload'):
            self._add('ISIS-LSP-OVERLOAD', 'medium', sid, lvl,
                      'Overload (OL) bit set — traffic steering / denial', now)
        seq = pdu.get('seq') or 0
        if seq >= SEQ_HIGH:
            self._add('ISIS-LSP-SEQ-ANOMALY', 'medium', sid, lvl,
                      'LSP sequence {:#010x} near 0xFFFFFFFF wrap (seq attack)'
                      .format(seq), now)
        if pdu.get('narrow_metrics'):
            self._add('ISIS-NARROW-METRICS', 'low', sid, lvl,
                      'legacy narrow metric TLVs instead of wide (RFC 5305)', now)
        # Churn: rapid re-flood of the same LSP id within the window.
        lid = pdu.get('lsp_id')
        if lid:
            dq = self._lsp_times.setdefault(lid, deque())
            dq.append(now)
            while dq and now - dq[0] > self.churn_window:
                dq.popleft()
            if len(dq) >= self.churn_threshold:
                self._add('ISIS-LSP-CHURN', 'medium', sid, lvl,
                          '{} re-floods of {} within {:.0f}s (instability / flood)'
                          .format(len(dq), lid, self.churn_window), now)

    def _check_iih(self, pdu, sid, lvl, now):
        if pdu.get('priority') == DIS_MAX_PRIORITY:
            self._add('ISIS-DIS-MAXPRIO', 'low', sid, lvl,
                      'Hello DIS priority 127 (possible DIS takeover)', now)
        if pdu.get('p2p') and not pdu.get('three_way'):
            self._add('ISIS-P2P-NO-3WAY', 'medium', sid, lvl,
                      'P2P Hello without the three-way adjacency TLV (RFC 5303)',
                      now)
        if pdu.get('padding'):
            self._add('ISIS-HELLO-PADDING', 'info', sid, lvl,
                      'Hello padding (TLV 8) — bandwidth waste / amplification',
                      now)

    # -- output ---------------------------------------------------------------
    def snapshot(self):
        findings = sorted(
            self.findings.values(),
            key=lambda r: (-SEV_RANK[r['severity']], r['code'], r['system']))
        by_sev = {}
        by_code = {}
        for r in findings:
            by_sev[r['severity']] = by_sev.get(r['severity'], 0) + 1
            by_code[r['code']] = by_code.get(r['code'], 0) + 1
        return {
            'module': 'isiswatch',
            'pdu_count': self.pdu_count,
            'system_count': len(self.systems),
            'systems': [
                {'system_id': k, 'hostname': v['hostname'],
                 'areas': sorted(v['areas']), 'levels': sorted(v['levels']),
                 'macs': sorted(v['macs'])}
                for k, v in sorted(self.systems.items())],
            'findings': findings,
            'summary': {'by_severity': by_sev, 'by_code': by_code,
                        'total': len(findings)},
        }


# ===========================================================================
# Live capture (scapy, lazy import)
# ===========================================================================
DEFAULT_BPF = ('(ether[14:2] = 0xfefe) or ether dst 01:80:c2:00:00:14 '
               'or ether dst 01:80:c2:00:00:15')


def run_live(iface, watch, duration=None, verbose=False, bpf=DEFAULT_BPF,
             web_json=None, web_interval=5.0):
    from scapy.all import sniff
    last_write = [time.time()]

    def handle(pkt):
        raw = bytes(pkt)
        pdu = parse_isis_frame(raw)
        if pdu is None:
            return
        now = time.time()
        before = len(watch.findings)
        watch.observe(pdu, now)
        if verbose:
            sys.stderr.write('  {} {} sys={} {}\n'.format(
                'L' + str(pdu.get('level')) if pdu.get('level') else 'p2p',
                pdu.get('kind'), pdu.get('system_id'),
                'MALFORMED' if pdu.get('malformed') else ''))
        if len(watch.findings) != before and verbose:
            newest = list(watch.findings.values())[-1]
            sys.stderr.write('    !! {} [{}] {}\n'.format(
                newest['code'], newest['severity'], newest['detail']))
        if web_json and now - last_write[0] >= web_interval:
            _write_json(web_json, watch.snapshot())
            last_write[0] = now

    sys.stderr.write('isiswatch: passive on {} (promisc) — Ctrl-C to stop\n'
                     .format(iface))
    stop = (lambda p: False)
    sniff(iface=iface, filter=(bpf or None), prn=handle, store=False,
          timeout=duration, stop_filter=stop)
    if web_json:
        _write_json(web_json, watch.snapshot())


def _write_json(path, obj):
    try:
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(obj, f, indent=2)
        os.replace(tmp, path)
    except OSError as e:
        sys.stderr.write('isiswatch: could not write {}: {}\n'.format(path, e))


# ===========================================================================
# CLI
# ===========================================================================
def main(argv=None):
    ap = argparse.ArgumentParser(description='Passive IS-IS security scanner (detection-only).')
    ap.add_argument('-i', '--iface', help='capture interface (SPAN/tap-facing)')
    ap.add_argument('-b', '--baseline', help='baseline JSON')
    ap.add_argument('-v', '--verbose', action='store_true', help='print each PDU')
    ap.add_argument('--web-json', help='periodically write a snapshot for the web UI')
    ap.add_argument('--json-out', help='write the final snapshot on exit')
    ap.add_argument('--churn-threshold', type=int, default=5, help='LSP re-flood count (default 5)')
    ap.add_argument('--churn-window', type=float, default=20.0, help='re-flood window s (default 20)')
    ap.add_argument('--filter', dest='bpf', default=None,
                    help='override capture BPF ("" disables, filter in Python)')
    ap.add_argument('--duration', type=int, help='stop after N seconds')
    ap.add_argument('--self-test', action='store_true', help='run the offline self-test')
    args = ap.parse_args(argv)

    if args.self_test:
        import isiswatch_selftest
        return isiswatch_selftest.run(verbose=True)

    baseline = {}
    if args.baseline:
        with open(args.baseline) as f:
            baseline = json.load(f)

    watch = IsisWatch(baseline=baseline, churn_threshold=args.churn_threshold,
                      churn_window=args.churn_window)

    if not args.iface:
        ap.error('one of -i/--iface or --self-test is required')
    if os.geteuid() != 0:
        sys.stderr.write('error: live capture needs root / CAP_NET_RAW.\n')
        return 2
    bpf = DEFAULT_BPF if args.bpf is None else (args.bpf or None)
    try:
        run_live(args.iface, watch, duration=args.duration, verbose=args.verbose,
                 bpf=bpf, web_json=args.web_json)
    except KeyboardInterrupt:
        pass
    snap = watch.snapshot()
    if args.json_out:
        _write_json(args.json_out, snap)
    sys.stderr.write('isiswatch: {} PDUs, {} systems, {} findings ({})\n'.format(
        snap['pdu_count'], snap['system_count'], snap['summary']['total'],
        snap['summary']['by_severity']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
