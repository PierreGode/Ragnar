#!/usr/bin/env python3
"""certwatch.py — passive TLS certificate triage for the Ragnar suite.

Watches TLS handshakes crossing a tap / SPAN / bridge and triages every X.509
certificate it can *observe* for expiry and validity problems. Detection only —
certwatch never opens a socket, never probes, never sends a byte. Same
passive-first posture as the rest of the suite.

The one caveat that shapes everything: the server certificate is cleartext on
the wire only for TLS 1.0/1.1/1.2. In TLS 1.3 the Certificate message is
encrypted under the handshake keys, so it is not observable passively. certwatch
turns that into a feature — for a 1.3 flow it emits an *inventory* record (SNI +
negotiated version) marked cert-not-observable, so "no cert because 1.3" is
distinguishable from "no cert because parse failure."

The heavy TLS byte-parsing (ClientHello SNI, ServerHello version, the
Certificate message, record/segment reassembly) is reused from tls_watch.py —
one audited parser, not two. certwatch owns the passive capture, the flow
tracker (bounded memory, LRU + TTL eviction), the cert triage, batch mode over
pcap directories, and the self-test.

Requires scapy (capture) and cryptography (X.509). See docs/certwatch.md.
"""

import argparse
import gzip
import os
import re
import sys
import time
from collections import OrderedDict
from datetime import datetime, timezone

# tls_watch is a core module in the repo root (this file is under python/).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tls_watch as _tw

# ---------------------------------------------------------------------------
# Tunables. Memory is bounded by MAX_FLOWS * MAX_FLOW_BYTES worst case.
# ---------------------------------------------------------------------------
DEFAULT_PORTS = (443, 465, 636, 853, 993, 995, 8443, 9443, 10250)
MAX_FLOWS = 512
MAX_FLOW_BYTES = 64 * 1024
FLOW_TTL = 30.0                     # seconds a flow may sit idle before eviction
DEFAULT_WARN_DAYS = 30
LONG_VALIDITY_DAYS = 398            # CA/Browser Forum max for public certs

_VERSION_NAME = {0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1',
                 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3'}

# Status ordering: worst finding severity sets the record status.
_STATUS_RANK = {'OK': 0, 'INFO': 1, 'WARN': 2, 'CRIT': 3}
_SEV_STATUS = {'INFO': 'INFO', 'WARN': 'WARN', 'CRIT': 'CRIT'}


def _version_name(v):
    return _VERSION_NAME.get(v, '0x{:04x}'.format(v)) if v else 'unknown'


# ===========================================================================
# Certificate triage — the finding engine
# ===========================================================================
def triage_cert(der, sni, now, warn_days=DEFAULT_WARN_DAYS):
    """Triage a single leaf certificate (DER). Returns (status, findings, info).

    findings is a list of {code, sev, msg}; info carries the parsed fields a
    SIEM wants (subject/issuer/serial/dates/key/sig + signed days_left)."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

    cert = x509.load_der_x509_certificate(der)
    findings = []

    def add(sev, code, msg):
        findings.append({'code': code, 'sev': sev, 'msg': msg})

    def cn(name):
        try:
            a = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            return a[0].value if a else None
        except Exception:
            return None

    subject_cn = cn(cert.subject)
    issuer_cn = cn(cert.issuer)
    try:
        sans = list(cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except Exception:
        sans = []
    nb = cert.not_valid_before_utc
    na = cert.not_valid_after_utc
    sig = (cert.signature_hash_algorithm.name
           if cert.signature_hash_algorithm else None)
    self_signed = cert.subject == cert.issuer
    validity_days = max(0, (na - nb).days)
    # Signed days-to-expiry: negative once expired, so a SIEM can alert on
    # days_left < N without regexing a message string.
    days_left = int((na - now).total_seconds() // 86400)

    # Public-key strength.
    key_type, key_bits = 'unknown', None
    try:
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            key_type, key_bits = 'RSA', pub.key_size
            if key_bits < 2048:
                add('WARN', 'WEAK_KEY', 'RSA key {} bits (<2048)'.format(key_bits))
        elif isinstance(pub, dsa.DSAPublicKey):
            key_type, key_bits = 'DSA', pub.key_size
            add('WARN', 'WEAK_KEY', 'DSA key ({} bits) — deprecated'.format(key_bits))
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            key_type, key_bits = 'EC', pub.curve.key_size
            if key_bits < 256:
                add('WARN', 'WEAK_KEY', 'EC key {} bits (<256)'.format(key_bits))
        else:
            key_type = type(pub).__name__.replace('PublicKey', '')  # Ed25519/Ed448
    except Exception:
        pass

    # Validity window.
    if now > na:
        add('CRIT', 'EXPIRED', 'certificate expired {} ({}d ago)'.format(
            na.date(), -days_left))
    elif now < nb:
        add('CRIT', 'NOT_YET_VALID', 'certificate not valid until {}'.format(nb.date()))
    elif days_left <= warn_days:
        add('WARN', 'EXPIRING_SOON', 'certificate expires in {}d ({})'.format(
            days_left, na.date()))

    # Signature strength.
    low = (sig or '').lower()
    if low in ('md5', 'md2'):
        add('CRIT', 'WEAK_SIG_MD5', 'signed with {}'.format(sig.upper()))
    elif low == 'sha1':
        add('CRIT', 'WEAK_SIG_SHA1', 'signed with SHA-1')

    # Name coverage (only when we actually observed the SNI on this flow).
    if sni:
        names = list(sans) + ([subject_cn] if subject_cn else [])
        if not any(_tw._host_matches(sni, n) for n in names):
            add('CRIT', 'NAME_MISMATCH',
                "observed SNI '{}' not covered by cert names {}".format(sni, names or []))

    # Hygiene.
    if self_signed:
        add('WARN', 'SELF_SIGNED', 'issuer == subject (self-signed)')
    if not sans:
        add('WARN', 'MISSING_SAN', 'no subjectAltName (CN-only cert)')
    if validity_days > LONG_VALIDITY_DAYS:
        add('INFO', 'LONG_VALIDITY',
            'validity window {}d (>{}d)'.format(validity_days, LONG_VALIDITY_DAYS))
    if any(s.startswith('*.') for s in sans):
        add('INFO', 'WILDCARD', 'wildcard SAN present')
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            add('INFO', 'CA_CERT', 'BasicConstraints CA:TRUE presented as leaf')
    except Exception:
        pass

    status = 'OK'
    for f in findings:
        if _STATUS_RANK[_SEV_STATUS[f['sev']]] > _STATUS_RANK[status]:
            status = _SEV_STATUS[f['sev']]

    info = {
        'subject_cn': subject_cn, 'issuer_cn': issuer_cn,
        'serial': '{:x}'.format(cert.serial_number),
        'not_before': nb.isoformat(), 'not_after': na.isoformat(),
        'days_left': days_left, 'validity_days': validity_days,
        'sig_alg': sig, 'key_type': key_type, 'key_bits': key_bits,
        'self_signed': self_signed, 'sans': sans,
    }
    return status, findings, info


# ===========================================================================
# Flow tracker — bounded, passive reassembly of TLS-over-TCP handshakes
# ===========================================================================
class FlowTracker:
    """Reassembles TLS handshakes per canonical flow and yields a triage record
    the instant the Certificate (TLS 1.2) or a 1.3 ServerHello is seen. Bounded:
    at most MAX_FLOWS live flows (LRU), MAX_FLOW_BYTES per flow, FLOW_TTL idle."""

    def __init__(self, warn_days=DEFAULT_WARN_DAYS):
        self.warn_days = warn_days
        # fkey -> {'segs': {dir4tuple: {seq: payload}}, 'bytes': int,
        #          'last': ts, 'done': bool}
        self.flows = OrderedDict()
        self._last_sweep = 0.0
        self.stats = {'flows': 0, 'records': 0, 'evicted_ttl': 0,
                      'evicted_lru': 0, 'evicted_cap': 0}

    @staticmethod
    def _fkey(a, b):
        return (a, b) if a <= b else (b, a)

    def add_segment(self, src, sport, dst, dport, seq, payload, now):
        """Feed one TCP segment. Returns a record dict when the flow resolves,
        else None."""
        a, b = (src, sport), (dst, dport)
        fk = self._fkey(a, b)
        fl = self.flows.get(fk)
        if fl is None:
            fl = {'segs': {}, 'bytes': 0, 'last': now, 'done': False}
            self.flows[fk] = fl
            self.stats['flows'] += 1
            if len(self.flows) > MAX_FLOWS:
                self.flows.popitem(last=False)
                self.stats['evicted_lru'] += 1
        self.flows.move_to_end(fk)
        fl['last'] = now
        if fl['done']:
            return None

        d = (src, sport, dst, dport)
        segs = fl['segs'].setdefault(d, {})
        if seq not in segs:
            fl['bytes'] += len(payload)
            segs[seq] = payload
        if fl['bytes'] > MAX_FLOW_BYTES:
            fl['done'] = True
            self.stats['evicted_cap'] += 1
            return None

        return self._resolve(fk, fl, now)

    def _stream(self, fl, d):
        segs = fl['segs'].get(d)
        if not segs:
            return b''
        return b''.join(segs[s] for s in sorted(segs))

    def _resolve(self, fk, fl, now):
        # Gather handshake messages from both directions. SNI comes from the
        # ClientHello side, ServerHello/Certificate from the server side — we
        # don't need to know which is which up front.
        sni = None
        server = None
        server_dir = None
        certs = None
        for d in list(fl['segs']):
            for mtype, body in _tw._handshake_from_tls_stream(self._stream(fl, d)):
                if mtype == 0x01 and sni is None:
                    try:
                        sni = _tw.parse_client_hello(body).get('sni')
                    except Exception:
                        pass
                elif mtype == 0x02 and server is None:
                    try:
                        server = _tw.parse_server_hello(body)
                        server_dir = d
                    except Exception:
                        pass
                elif mtype == 0x0b and certs is None:
                    try:
                        certs = _tw.parse_certificates(body)
                        server_dir = d
                    except Exception:
                        pass

        if certs:
            fl['done'] = True
            rec = self._cert_record(server_dir, sni, server, certs, now)
            self._retire(fk)
            return rec
        if server is not None and server['neg_version'] == 0x0304:
            fl['done'] = True
            rec = self._inventory_record(server_dir, sni, server)
            self._retire(fk)
            return rec
        return None

    def _retire(self, fk):
        self.flows.pop(fk, None)

    def _endpoint(self, server_dir):
        if server_dir:
            return server_dir[0], server_dir[1]
        return None, None

    def _cert_record(self, server_dir, sni, server, certs, now):
        ip, port = self._endpoint(server_dir)
        ver = server['neg_version'] if server else 0x0303
        rec = {'module': 'certwatch', 'type': 'cert', 'status': 'OK',
               'sni': sni, 'version': _version_name(ver),
               'server_ip': ip, 'server_port': port,
               'chain_len': len(certs), 'findings': []}
        # `now` is a float epoch (packet/wall time) used for flow timing; triage
        # compares against cert datetimes, so convert at this boundary.
        now_dt = datetime.fromtimestamp(now, timezone.utc)
        try:
            status, findings, info = triage_cert(certs[0], sni, now_dt, self.warn_days)
            rec['status'] = status
            rec['findings'] = findings
            rec.update(info)
        except Exception as exc:
            rec['status'] = 'INFO'
            rec['findings'] = [{'code': 'PARSE_ERROR', 'sev': 'INFO',
                                'msg': 'leaf parse failed: {}'.format(exc)}]
        self.stats['records'] += 1
        return rec

    def _inventory_record(self, server_dir, sni, server):
        ip, port = self._endpoint(server_dir)
        self.stats['records'] += 1
        return {'module': 'certwatch', 'type': 'inventory', 'status': 'INFO',
                'sni': sni, 'version': _version_name(server['neg_version']),
                'server_ip': ip, 'server_port': port, 'chain_len': 0,
                'findings': [{'code': 'CERT_NOT_OBSERVABLE', 'sev': 'INFO',
                              'msg': 'TLS 1.3 encrypts the Certificate message; '
                                     'not observable passively'}]}

    def sweep(self, now):
        """Evict idle flows past FLOW_TTL. Cheap, rate-limited to ~1/s."""
        if now - self._last_sweep < 1.0:
            return
        self._last_sweep = now
        stale = [fk for fk, fl in self.flows.items() if now - fl['last'] > FLOW_TTL]
        for fk in stale:
            self.flows.pop(fk, None)
            self.stats['evicted_ttl'] += 1


# ===========================================================================
# Packet handling (live + pcap share one path)
# ===========================================================================
def _scapy():
    from scapy.layers.inet import IP, TCP
    try:
        from scapy.layers.inet6 import IPv6
    except Exception:
        IPv6 = None
    return IP, IPv6, TCP


def _raw_payload(l4):
    # .original is the exact wire bytes; bytes(l4.payload) re-serializes lossily
    # if scapy's TLS layer is loaded.
    pl = l4.payload
    orig = getattr(pl, 'original', b'')
    return bytes(orig) if orig else bytes(pl)


def _port_ok(sport, dport, ports):
    return ports is None or sport in ports or dport in ports


def make_handler(tracker, ports, emit):
    """Return a scapy prn callback that feeds TCP payloads into the tracker and
    calls emit(record) for each resolved flow. `ports=None` means all TCP."""
    IP, IPv6, TCP = _scapy()

    def handle(pkt):
        ipl = pkt.getlayer(IP) or (IPv6 and pkt.getlayer(IPv6))
        if not ipl or not pkt.haslayer(TCP):
            return
        t = pkt[TCP]
        if not _port_ok(int(t.sport), int(t.dport), ports):
            return
        pay = _raw_payload(t)
        now = time.time()
        tracker.sweep(now)
        if not pay:
            return
        rec = tracker.add_segment(ipl.src, int(t.sport), ipl.dst, int(t.dport),
                                  int(t.seq), pay, now)
        if rec:
            emit(rec)
    return handle


# ===========================================================================
# Output filtering
# ===========================================================================
def status_at_least(rec, min_status):
    if not min_status:
        return True
    return _STATUS_RANK.get(rec.get('status', 'OK'), 0) >= _STATUS_RANK[min_status]


def format_text(rec):
    tag = rec.get('sni') or rec.get('subject_cn') or '?'
    ep = '{}:{}'.format(rec.get('server_ip') or '?', rec.get('server_port') or '?')
    codes = ','.join(f['code'] for f in rec.get('findings', [])) or '-'
    dl = rec.get('days_left')
    dl = '' if dl is None else ' days_left={}'.format(dl)
    return '[{:4}] {} {} {} {}{}'.format(rec['status'], rec['type'], ep, tag,
                                         codes, dl)


def emit_record(rec, as_json, min_status, out=sys.stdout):
    if not status_at_least(rec, min_status):
        return False
    if as_json:
        import json
        out.write(json.dumps(rec, sort_keys=True) + '\n')
    else:
        out.write(format_text(rec) + '\n')
    out.flush()
    return True


# ===========================================================================
# Live + single-pcap runners
# ===========================================================================
def run_live(iface, ports, as_json, min_status, warn_days):
    from scapy.all import sniff
    tracker = FlowTracker(warn_days=warn_days)
    if ports is None:
        bpf = 'tcp'
    else:
        bpf = 'tcp and (' + ' or '.join('port {}'.format(p) for p in ports) + ')'
    handler = make_handler(tracker, ports, lambda r: emit_record(r, as_json, min_status))
    sys.stderr.write('certwatch: passive on {} ({}) — Ctrl-C to stop\n'
                     .format(iface, 'all TCP' if ports is None else 'ports '
                             + ','.join(map(str, ports))))
    sniff(iface=iface, filter=bpf, prn=handler, store=False)
    return tracker.stats


def _iter_pcap_packets(path):
    """Yield packets from a pcap/pcapng, transparently gunzipping .gz. Raises on
    a corrupt file so the batch layer can note-and-skip."""
    from scapy.all import PcapReader
    if path.endswith('.gz'):
        import tempfile
        with gzip.open(path, 'rb') as gz:
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                tmp = tf.name
                tf.write(gz.read())
        try:
            with PcapReader(tmp) as pr:
                for p in pr:
                    yield p
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
    else:
        with PcapReader(path) as pr:
            for p in pr:
                yield p


def run_pcap(path, ports, tracker=None, on_record=None, warn_days=DEFAULT_WARN_DAYS):
    """Triage one capture. Returns list of records (also streamed to on_record).
    Pass a shared `tracker` to carry flow state across a rotation set."""
    IP, IPv6, TCP = _scapy()
    own = tracker is None
    if own:
        tracker = FlowTracker(warn_days=warn_days)
    records = []

    def emit(r):
        r = dict(r, pcap=os.path.basename(path))
        records.append(r)
        if on_record:
            on_record(r)

    for p in _iter_pcap_packets(path):
        ipl = p.getlayer(IP) or (IPv6 and p.getlayer(IPv6))
        if not ipl or not p.haslayer(TCP):
            continue
        t = p[TCP]
        if not _port_ok(int(t.sport), int(t.dport), ports):
            continue
        pay = _raw_payload(t)
        if not pay:
            continue
        # pcap time is monotonic-ish per file; use packet time for TTL sweeps.
        now = float(getattr(p, 'time', time.time()))
        rec = tracker.add_segment(ipl.src, int(t.sport), ipl.dst, int(t.dport),
                                  int(t.seq), pay, now)
        if rec:
            emit(rec)
    return records


# ===========================================================================
# Batch mode over a directory of captures
# ===========================================================================
# tcpdump rotation lands the index AFTER the extension: capture.pcap0,
# capture.pcap1, ... A naive endswith('.pcap') silently skips those.
_CAP_RE = re.compile(r'\.(pcap|pcapng|cap|dmp)(\d+)?(\.gz)?$', re.IGNORECASE)


def _is_capture(name):
    return bool(_CAP_RE.search(name))


def _natural_key(path):
    """Sort key so capture.pcap2 precedes capture.pcap10."""
    return [int(t) if t.isdigit() else t.lower()
            for t in re.split(r'(\d+)', path)]


def find_captures(root, recursive):
    out = []
    if recursive:
        for dirpath, _dirs, files in os.walk(root):
            out += [os.path.join(dirpath, f) for f in files if _is_capture(f)]
    else:
        out += [os.path.join(root, f) for f in os.listdir(root)
                if _is_capture(f) and os.path.isfile(os.path.join(root, f))]
    return sorted(out, key=_natural_key)


def run_batch(root, ports, as_json, min_status, warn_days, recursive=False,
              dedupe=False, carry_state=False, out=sys.stdout):
    """Triage every capture under `root`. Returns the batch_summary dict."""
    captures = find_captures(root, recursive)
    summary = {'module': 'certwatch', 'type': 'batch_summary',
               'files': 0, 'skipped': 0, 'records': 0,
               'by_status': {}, 'by_code': {}}
    # dedupe: (server_ip, serial) -> aggregated record
    seen = OrderedDict()
    shared = FlowTracker(warn_days=warn_days) if carry_state else None

    def account(rec):
        summary['by_status'][rec['status']] = summary['by_status'].get(rec['status'], 0) + 1
        for f in rec.get('findings', []):
            summary['by_code'][f['code']] = summary['by_code'].get(f['code'], 0) + 1

    def handle(rec):
        summary['records'] += 1
        account(rec)
        if dedupe:
            key = (rec.get('server_ip'), rec.get('serial') or rec.get('sni')
                   or rec.get('type'))
            agg = seen.get(key)
            if agg is None:
                rec = dict(rec, seen_count=1, seen_in=[rec.get('pcap')])
                seen[key] = rec
            else:
                agg['seen_count'] += 1
                if rec.get('pcap') not in agg['seen_in']:
                    agg['seen_in'].append(rec.get('pcap'))
            return
        emit_record(rec, as_json, min_status, out)

    for path in captures:
        sys.stderr.write('certwatch: {}\n'.format(path))
        try:
            run_pcap(path, ports, tracker=shared, on_record=handle, warn_days=warn_days)
            summary['files'] += 1
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            summary['skipped'] += 1
            sys.stderr.write('  skipped (corrupt/unreadable): {}\n'.format(exc))

    if dedupe:
        for rec in seen.values():
            emit_record(rec, as_json, min_status, out)

    if as_json:
        emit_record(summary, True, None, out)
    else:
        sys.stderr.write('certwatch batch: {} files, {} skipped, {} records; '
                         'status {} codes {}\n'.format(
                             summary['files'], summary['skipped'], summary['records'],
                             summary['by_status'], summary['by_code']))
    return summary


# ===========================================================================
# CLI
# ===========================================================================
def _parse_ports(spec):
    if spec is None:
        return DEFAULT_PORTS
    if spec.strip().lower() == 'any':
        return None
    return tuple(int(p) for p in spec.split(',') if p.strip())


def main(argv=None):
    ap = argparse.ArgumentParser(description='Passive TLS certificate triage (detection only).')
    src = ap.add_mutually_exclusive_group()
    src.add_argument('-i', '--iface', help='live capture on this interface (mirror/monitor)')
    src.add_argument('-r', '--read', help='triage a single pcap/pcapng (.gz ok)')
    src.add_argument('--pcap-dir', help='batch-triage every capture in a directory')
    src.add_argument('--selftest', action='store_true', help='run the offline self-test')
    ap.add_argument('--ports', default=None,
                    help="ports to watch (default {}; 'any' = all TCP)".format(
                        ','.join(map(str, DEFAULT_PORTS))))
    ap.add_argument('--warn-days', type=int, default=DEFAULT_WARN_DAYS,
                    help='EXPIRING_SOON threshold in days (default 30)')
    ap.add_argument('--json', action='store_true', help='emit JSON lines to stdout')
    ap.add_argument('--min-status', choices=['INFO', 'WARN', 'CRIT'], default=None,
                    help='only emit records at or above this status')
    ap.add_argument('--recursive', action='store_true', help='batch: descend into subdirs')
    ap.add_argument('--dedupe', action='store_true',
                    help='batch: collapse repeat sightings (server+serial)')
    ap.add_argument('--carry-state', action='store_true',
                    help='batch: keep flow state across files (rotation sets ONLY)')
    args = ap.parse_args(argv)

    if args.selftest:
        import certwatch_selftest
        return certwatch_selftest.run(verbose=True)

    ports = _parse_ports(args.ports)

    if args.iface:
        if os.geteuid() != 0:
            sys.stderr.write('error: live capture needs root / CAP_NET_RAW.\n')
            return 2
        run_live(args.iface, ports, args.json, args.min_status, args.warn_days)
        return 0
    if args.read:
        recs = run_pcap(args.read, ports, warn_days=args.warn_days)
        for r in recs:
            emit_record(r, args.json, args.min_status)
        return 0
    if args.pcap_dir:
        run_batch(args.pcap_dir, ports, args.json, args.min_status, args.warn_days,
                  recursive=args.recursive, dedupe=args.dedupe,
                  carry_state=args.carry_state)
        return 0

    ap.print_help()
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
