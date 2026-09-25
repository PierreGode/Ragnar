#!/usr/bin/env python3
"""snmpwatch.py — passive SNMP community-exposure scanner (Ragnar).

Detection-only: snmpwatch never emits an SNMP packet — no walking, no community
guessing, no GET/SET. It watches SNMP already on the wire (BPF udp port 161/162)
and flags the exposure. The community strings it prints are the ones the network
is leaking on its own.

The SNMP/BER decoder is pure Python (no Scapy), so `--selftest` runs with no
Scapy and no NIC. Scapy is used only for live capture.

See docs/snmpwatch.md. Requires CAP_NET_RAW for live capture.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

# ===========================================================================
# Minimal BER / ASN.1 decoder (bounds-checked; a malformed message raises
# BerError and is dropped per-packet, never crashing the sniffer).
# ===========================================================================


class BerError(Exception):
    pass


def read_tlv(b, i):
    """Return (tag, value_bytes, next_index). Single-byte tags (all SNMP uses)."""
    if i + 2 > len(b):
        raise BerError('truncated TLV header')
    tag = b[i]
    ln = b[i + 1]
    j = i + 2
    if ln & 0x80:
        n = ln & 0x7f
        if n == 0 or j + n > len(b):
            raise BerError('bad long-form length')
        ln = int.from_bytes(b[j:j + n], 'big')
        j += n
    if j + ln > len(b):
        raise BerError('length overruns buffer')
    return tag, b[j:j + ln], j + ln


def ber_int(v):
    if not v:
        return 0
    n = int.from_bytes(v, 'big')
    if v[0] & 0x80:                              # negative (two's complement)
        n -= 1 << (8 * len(v))
    return n


def ber_oid(v):
    if not v:
        return ''
    out = [str(v[0] // 40), str(v[0] % 40)]
    n = 0
    for byte in v[1:]:
        n = (n << 7) | (byte & 0x7f)
        if not (byte & 0x80):
            out.append(str(n))
            n = 0
    return '.'.join(out)


def ber_children(v):
    """Yield (tag, value, _next) for each TLV inside a constructed value."""
    i = 0
    while i < len(v):
        tag, val, i = read_tlv(v, i)
        yield tag, val


# ===========================================================================
# BER encode helpers (for the self-test's pure-Python message builders)
# ===========================================================================
def _enc_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(body)]) + body


def enc(tag, value):
    return bytes([tag]) + _enc_len(len(value)) + value


def enc_int(n):
    if n == 0:
        return enc(0x02, b'\x00')
    body = n.to_bytes((n.bit_length() + 8) // 8, 'big', signed=True)
    return enc(0x02, body)


def enc_octet(s):
    if isinstance(s, str):
        s = s.encode()
    return enc(0x04, s)


def enc_oid(oid):
    parts = [int(x) for x in oid.split('.')]
    body = bytes([40 * parts[0] + parts[1]])
    for n in parts[2:]:
        if n < 0x80:
            body += bytes([n])
        else:
            chunk = []
            while n:
                chunk.insert(0, n & 0x7f)
                n >>= 7
            for k in range(len(chunk) - 1):
                chunk[k] |= 0x80
            body += bytes(chunk)
    return enc(0x06, body)


def enc_seq(*items):
    return enc(0x30, b''.join(items))


# ===========================================================================
# SNMP message model
# ===========================================================================
PDU_TAGS = {0xa0: 'GetRequest', 0xa1: 'GetNextRequest', 0xa2: 'GetResponse',
            0xa3: 'SetRequest', 0xa4: 'Trap', 0xa5: 'GetBulkRequest',
            0xa6: 'InformRequest', 0xa7: 'V2Trap', 0xa8: 'Report'}

V3_MODES = {(False, False): 'noAuthNoPriv', (True, False): 'authNoPriv',
            (True, True): 'authPriv', (False, True): 'privNoAuth'}


def _parse_pdu(tag, val):
    pdu = {'pdu': PDU_TAGS.get(tag, 'PDU-0x%02x' % tag), 'oids': []}
    kids = list(ber_children(val))
    # request-id, error-status/non-repeaters, error-index/max-reps, varbinds
    if len(kids) >= 4:
        pdu['request_id'] = ber_int(kids[0][1])
        pdu['error_or_nonrep'] = ber_int(kids[1][1])
        pdu['erridx_or_maxrep'] = ber_int(kids[2][1])
        varbinds = kids[3][1]
    elif kids:
        varbinds = kids[-1][1]
    else:
        varbinds = b''
    if tag == 0xa5:
        pdu['max_repetitions'] = pdu.get('erridx_or_maxrep')
    for vtag, vval in ber_children(varbinds):
        if vtag != 0x30:
            continue
        vb = list(ber_children(vval))
        if vb and vb[0][0] == 0x06:
            pdu['oids'].append(ber_oid(vb[0][1]))
    return pdu


def parse_snmp(payload):
    """Parse an SNMP UDP payload into a message dict, or raise BerError."""
    tag, body, _ = read_tlv(payload, 0)
    if tag != 0x30:
        raise BerError('SNMP message is not a SEQUENCE')
    kids = list(ber_children(body))
    if len(kids) < 3:
        raise BerError('short SNMP message')
    version = ber_int(kids[0][1])
    msg = {'version_num': version, 'version': None, 'community': None,
           'pdu': None, 'oids': [], 'v3_mode': None, 'v3_auth': None,
           'v3_priv': None, 'v3_plaintext': None, 'claims_priv_plaintext': False,
           'context_engine_id': None, 'context_name': None, 'malformed': None}
    if version in (0, 1):                        # SNMPv1 / v2c
        msg['version'] = 'v1' if version == 0 else 'v2c'
        msg['community'] = kids[1][1].decode('latin1')
        ptag, pval = kids[2][0], kids[2][1]
        pdu = _parse_pdu(ptag, pval)
        msg.update({'pdu': pdu['pdu'], 'oids': pdu['oids']})
        msg['max_repetitions'] = pdu.get('max_repetitions')
        return msg
    if version == 3:
        msg['version'] = 'v3'
        # kids: [msgVersion, msgGlobalData SEQ, msgSecurityParameters OCTET, msgData]
        gd = list(ber_children(kids[1][1]))
        # gd: msgID, msgMaxSize, msgFlags OCTET(1), msgSecurityModel
        flags = gd[2][1] if len(gd) >= 3 else b'\x00'
        fb = flags[0] if flags else 0
        auth = bool(fb & 0x01)
        priv = bool(fb & 0x02)
        msg['v3_auth'], msg['v3_priv'] = auth, priv
        msg['v3_mode'] = V3_MODES[(auth, priv)]
        data = kids[3]
        # msgData CHOICE: plaintext ScopedPDU (SEQUENCE 0x30) or encryptedPDU
        # (OCTET STRING 0x04). The BER tag is authoritative — read the wire.
        msg['v3_plaintext'] = (data[0] == 0x30)
        if priv and data[0] == 0x30:
            msg['claims_priv_plaintext'] = True
        if data[0] == 0x30:
            scoped = list(ber_children(data[1]))
            if len(scoped) >= 3:
                msg['context_engine_id'] = scoped[0][1].hex()
                msg['context_name'] = scoped[1][1].decode('latin1', 'replace')
                ptag, pval = scoped[2][0], scoped[2][1]
                if ptag in PDU_TAGS:
                    pdu = _parse_pdu(ptag, pval)
                    msg['pdu'] = pdu['pdu']
                    msg['oids'] = pdu['oids']
                    msg['max_repetitions'] = pdu.get('max_repetitions')
        return msg
    raise BerError('unknown SNMP version %d' % version)


# ===========================================================================
# OID-hint table — write-sensitive branches (longest prefix wins)
# ===========================================================================
OID_HINTS = [
    ('1.3.6.1.4.1.9.9.96', 'CISCO-CONFIG-COPY-MIB', 'config exfil/push over TFTP in cleartext'),
    ('1.3.6.1.4.1.9.2.1.55', 'OLD-CISCO writeNet', 'copy running-config to a TFTP server'),
    ('1.3.6.1.4.1.9.2.1.54', 'OLD-CISCO writeMem', 'write memory (persist a config change)'),
    ('1.3.6.1.6.3.15.1.2.2', 'usmUserTable', 'SNMPv3 user creation/modification'),
    ('1.3.6.1.6.3.16', 'vacm MIB', 'access-control model changes'),
    ('1.3.6.1.6.3.12', 'target MIB', 'notification target redirection'),
    ('1.3.6.1.6.3.13', 'notification MIB', 'notification config changes'),
    ('1.3.6.1.2.1.2.2.1.7', 'ifAdminStatus', 'interface up/down (DoS)'),
    ('1.3.6.1.2.1.4.1', 'ipForwarding', 'toggle IP forwarding'),
    ('1.3.6.1.2.1.1.5', 'sysName', 'device identity'),
    ('1.3.6.1.2.1.1.4', 'sysContact', 'device identity'),
    ('1.3.6.1.2.1.1.6', 'sysLocation', 'device identity'),
]


def oid_hints(oids):
    """Longest-prefix match each OID against the sensitive-branch table."""
    hints = []
    for oid in oids:
        best = None
        for prefix, name, note in OID_HINTS:
            if (oid == prefix or oid.startswith(prefix + '.')) and (
                    best is None or len(prefix) > len(best[0])):
                best = (prefix, name, note)
        if best:
            hints.append({'oid': oid, 'mib': best[1], 'note': best[2]})
    return hints


# ===========================================================================
# Severity engine
# ===========================================================================
DEFAULT_COMMUNITIES = frozenset((
    'public', 'private', 'community', 'cisco', 'manager', 'admin', 'snmp',
    'default', 'write', 'read', 'monitor', 'netman', 'ilo', 'secret', 'password',
    'security', 'router', 'switch', 'test', 'guest', '0', ''))

SEV_RANK = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}


def classify(msg):
    """Return (severity, reason, hints) for one SNMP message."""
    hints = oid_hints(msg.get('oids') or [])
    is_set = msg.get('pdu') == 'SetRequest'
    if msg['version'] in ('v1', 'v2c'):
        comm = msg.get('community')
        default = (comm or '').lower() in DEFAULT_COMMUNITIES
        if is_set:
            r = ('SNMP{} SetRequest in cleartext (community "{}") — write access is '
                 'forgeable/replayable by any on-path host'.format(msg['version'], comm))
            if hints:
                r += ' — writing ' + ', '.join(h['mib'] for h in hints)
            return 'CRITICAL', r, hints
        base = ('default/well-known ' if default else '') + 'community "{}"'.format(comm)
        r = 'SNMP{} {} in cleartext — harvestable by any on-path listener'.format(
            msg['version'], base)
        return 'HIGH', r, hints
    # v3
    mode = msg.get('v3_mode')
    if msg.get('claims_priv_plaintext'):
        return 'HIGH', ('SNMPv3 msgFlags claim privacy but msgData is a plaintext '
                        'ScopedPDU (BER SEQUENCE) — payload is not encrypted'), hints
    if mode == 'privNoAuth':
        return 'MEDIUM', ('SNMPv3 privNoAuth — illegal flag combo (RFC 3412 §6.4); '
                          'malformed or hostile agent'), hints
    if mode == 'noAuthNoPriv':
        if is_set:
            r = ('SNMPv3 noAuthNoPriv SetRequest — no auth key; the write is forgeable '
                 'by any on-path host (same as a v2c SET)')
            if hints:
                r += ' — writing ' + ', '.join(h['mib'] for h in hints)
            return 'CRITICAL', r, hints
        r = 'SNMPv3 noAuthNoPriv — auth and encryption both off; no benefit over v2c'
        if hints:
            r += ' — reading ' + ', '.join(h['mib'] for h in hints)
        return 'MEDIUM', r, hints
    if mode == 'authNoPriv':
        r = 'SNMPv3 authNoPriv — authenticated but varbinds are visible in cleartext'
        if hints:
            r += ' — {} {}'.format('writing' if is_set else 'reading',
                                   ', '.join(h['mib'] for h in hints))
        return 'LOW', r, hints
    return 'INFO', 'SNMPv3 authPriv — authenticated and encrypted (secure)', hints


# ===========================================================================
# Watch engine
# ===========================================================================
class SnmpWatch:
    def __init__(self):
        self.findings = {}          # key -> record
        self.packets = 0
        self.malformed = 0
        self._comm_agents = {}      # community -> set of agent ips
        self._comm_writes = set()   # communities seen writing

    @staticmethod
    def _agent(src, sport, dst, dport):
        if dport == 161:
            return dst, src
        if sport == 161:
            return src, dst
        if dport == 162:
            return src, dst
        return dst, src

    def observe(self, msg, src, sport, dst, dport, now=None):
        if now is None:
            now = time.time()
        self.packets += 1
        if msg.get('malformed'):
            self.malformed += 1
        agent, _mgr = self._agent(src, sport, dst, dport)
        sev, reason, hints = classify(msg)
        if msg['version'] in ('v1', 'v2c'):
            comm = msg.get('community')
            self._comm_agents.setdefault(comm, set()).add(agent)
            if msg.get('pdu') == 'SetRequest':
                self._comm_writes.add(comm)
        key = (src, dst, msg['version'], msg.get('community'), msg.get('pdu'),
               msg.get('v3_mode'))
        rec = self.findings.get(key)
        if rec is None:
            self.findings[key] = {
                'src': src, 'dst': dst, 'agent': agent, 'version': msg['version'],
                'community': msg.get('community'), 'pdu': msg.get('pdu'),
                'v3_mode': msg.get('v3_mode'), 'severity': sev, 'reason': reason,
                'oids': list(msg.get('oids') or []),
                'oid_hints': hints, 'count': 1, 'first_seen': now, 'last_seen': now,
                'context_engine_id': msg.get('context_engine_id'),
                'context_name': msg.get('context_name')}
        else:
            rec['count'] += 1
            rec['last_seen'] = now
            for o in (msg.get('oids') or []):
                if o not in rec['oids']:
                    rec['oids'].append(o)
            for h in hints:
                if h not in rec['oid_hints']:
                    rec['oid_hints'].append(h)

    def community_reuse(self):
        out = []
        for comm in sorted(a for a, ags in self._comm_agents.items() if len(ags) >= 2):
            ags = sorted(self._comm_agents[comm])
            writes = comm in self._comm_writes
            out.append({'community': comm, 'agents': ags, 'writes': writes,
                        'severity': 'CRITICAL' if writes else 'HIGH'})
        return out

    def report(self):
        findings = sorted(self.findings.values(),
                          key=lambda r: (-SEV_RANK[r['severity']], r['src'], r['dst']))
        sev_counts = {}
        for r in findings:
            sev_counts[r['severity']] = sev_counts.get(r['severity'], 0) + 1
        insecure = any(f['version'] in ('v1', 'v2c') or
                       (f['version'] == 'v3' and f['v3_mode'] != 'authPriv'
                        and f['severity'] != 'INFO')
                       for f in findings)
        return {
            'module': 'snmpwatch',
            'generated': datetime.now(timezone.utc).isoformat(),
            'stats': {'packets': self.packets, 'malformed': self.malformed,
                      'findings': len(findings)},
            'severity_counts': sev_counts,
            'insecure_versions_present': insecure,
            'community_reuse': self.community_reuse(),
            'findings': findings,
        }


# ===========================================================================
# Live capture (scapy, lazy)
# ===========================================================================
def run_live(iface, watch, duration=None):
    from scapy.all import sniff
    from scapy.layers.inet import IP, UDP
    try:
        from scapy.layers.inet6 import IPv6
    except Exception:
        IPv6 = None

    def handle(pkt):
        ipl = pkt.getlayer(IP) or (IPv6 and pkt.getlayer(IPv6))
        if not ipl or not pkt.haslayer(UDP):
            return
        u = pkt[UDP]
        payload = bytes(u.payload)
        if not payload:
            return
        try:
            msg = parse_snmp(payload)
        except BerError:
            return
        watch.observe(msg, ipl.src, int(u.sport), ipl.dst, int(u.dport))

    sys.stderr.write('snmpwatch: passive on {} (udp 161/162) — Ctrl-C to stop\n'.format(iface))
    sniff(iface=iface, filter='udp and (port 161 or port 162)', prn=handle,
          store=False, timeout=duration)


# ===========================================================================
# CLI
# ===========================================================================
def main(argv=None):
    ap = argparse.ArgumentParser(description='Passive SNMP community-exposure scanner (detection-only).')
    ap.add_argument('-i', '--iface', help='capture interface (SPAN/tap-facing)')
    ap.add_argument('--json', help="write JSON report on exit ('-' = stdout)")
    ap.add_argument('-t', '--duration', type=int, help='stop after N seconds')
    ap.add_argument('--selftest', action='store_true', help='run the offline self-test')
    args = ap.parse_args(argv)

    if args.selftest:
        import snmpwatch_selftest
        return snmpwatch_selftest.run(verbose=True)

    if not args.iface:
        ap.error('one of -i/--iface or --selftest is required')
    if os.geteuid() != 0:
        sys.stderr.write('error: live capture needs root / CAP_NET_RAW.\n')
        return 2
    watch = SnmpWatch()
    try:
        run_live(args.iface, watch, duration=args.duration)
    except KeyboardInterrupt:
        pass
    rep = watch.report()
    if args.json == '-':
        print(json.dumps(rep, indent=2))
    elif args.json:
        os.makedirs(os.path.dirname(args.json) or '.', exist_ok=True)
        with open(args.json, 'w') as f:
            json.dump(rep, f, indent=2)
    sys.stderr.write('snmpwatch: {} packets, {} findings, insecure={} ({})\n'.format(
        rep['stats']['packets'], rep['stats']['findings'],
        rep['insecure_versions_present'], rep['severity_counts']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
