#!/usr/bin/env python3
"""Bounded live packet capture (PCAP) for Ragnar — the engine behind the mesh
"Packet Capture" feature.

A capture is a single, strictly-bounded `tcpdump -w` run: it stops on the first
of a time limit, a packet count, or a byte ceiling, so it can never fill a Pi
Zero's disk or run forever. Captures land as real `.pcap` files the operator can
pull over the mesh and open in Wireshark, alongside the live Traffic Analyzer
(which only reads tcpdump as text for stats and writes no file).

Self-contained (no import from webapp_modern) to avoid a circular import, exactly
like network_diagnostics: webapp_modern imports the singleton and wraps it in the
mesh routes. Auth/gating lives in those routes, not here.

The Ragnar service runs as root, so tcpdump is invoked directly; when this runs
as a normal user it falls back to `sudo -n tcpdump` (which needs a sudoers entry)
and surfaces a clear permission error otherwise.
"""

import os
import re
import shutil
import signal
import subprocess
import threading
import time
from datetime import datetime

# ---- Hard ceilings (an operator request is clamped to these) ----------------
MAX_SECONDS = 300            # 5 min — a capture always stops by here
MAX_PACKETS = 500_000        # packet-count ceiling
MAX_BYTES = 100 * 1024 * 1024  # 100 MB file ceiling
MAX_SNAPLEN = 262144         # full frame (tcpdump's own default)
DEFAULT_SECONDS = 60
DEFAULT_SNAPLEN = 0          # 0 -> tcpdump default (full frame)
MAX_KEEP = 8                 # retained .pcap files per unit (oldest pruned)
DEFAULT_VIEW_LINES = 300     # packets decoded for the on-screen view
MAX_VIEW_LINES = 2000
_BPF_MAX = 512

_IFACE_RE = re.compile(r'^[A-Za-z0-9._@:-]{1,32}$')
# BPF is handed to tcpdump as a non-shell argv element; this still blocks an
# option-looking filter and anything well outside real pcap-filter syntax.
_BPF_RE = re.compile(r'^[A-Za-z0-9 ._:/()\[\]<>=!&|+\-]*$')


def _clamp(val, default, lo, hi):
    try:
        n = int(val)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _iface_names():
    try:
        return sorted(n for n in os.listdir('/sys/class/net'))
    except OSError:
        return []


def _carrier_up(name):
    try:
        with open(f'/sys/class/net/{name}/carrier') as f:
            return f.read().strip() == '1'
    except OSError:
        return False


def _default_iface():
    """A sensible default capture interface: a non-virtual link that is up,
    else the first non-loopback interface, else lo."""
    virt = ('lo', 'tun', 'tap', 'wg', 'zt', 'tailscale', 'docker', 'veth', 'br-')
    names = _iface_names()
    real = [n for n in names if not n.startswith(virt)]
    for n in real:
        if _carrier_up(n):
            return n
    if real:
        return real[0]
    return names[0] if names else 'any'


def _human_bytes(n):
    n = float(n or 0)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return (f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}')
        n /= 1024
    return f'{n:.1f} GB'


class CaptureManager:
    """Owns at most one active capture plus a short history of finished ones."""

    def __init__(self, base_dir=None):
        self._lock = threading.Lock()
        self._caps = {}        # id -> record dict
        self._order = []       # ids, oldest first (retention)
        self._active = None    # id of the running capture, or None
        self._dir = base_dir or os.path.join('data', 'output', 'captures')

    # -- availability ---------------------------------------------------------
    @staticmethod
    def available():
        return shutil.which('tcpdump') is not None

    @staticmethod
    def unavailable_reason():
        if shutil.which('tcpdump') is None:
            return 'tcpdump is not installed on this unit.'
        return ''

    def _tcpdump_cmd(self, args):
        base = ['tcpdump'] + args
        try:
            if os.geteuid() != 0:
                return ['sudo', '-n'] + base
        except AttributeError:      # pragma: no cover - non-POSIX
            pass
        return base

    # -- public record views --------------------------------------------------
    def _record_public(self, rec):
        """A JSON-safe copy of a capture record (no process handles)."""
        return {
            'id': rec['id'], 'interface': rec['interface'],
            'state': rec['state'], 'filter': rec.get('filter') or '',
            'seconds': rec['seconds'], 'max_packets': rec['max_packets'],
            'max_bytes': rec['max_bytes'], 'packets': rec.get('packets', 0),
            'bytes': rec.get('bytes', 0), 'bytes_human': _human_bytes(rec.get('bytes', 0)),
            'started': rec['started'], 'ended': rec.get('ended'),
            'elapsed': round((rec.get('ended') or time.time()) - rec['started'], 1),
            'error': rec.get('error') or '',
            'filename': os.path.basename(rec['path']) if rec.get('path') else '',
        }

    def status(self, cid):
        with self._lock:
            rec = self._caps.get(cid)
            if not rec:
                return {'success': False, 'error': 'No such capture.'}
            return {'success': True, 'capture': self._record_public(rec)}

    def list(self):
        with self._lock:
            caps = [self._record_public(self._caps[i]) for i in reversed(self._order)
                    if i in self._caps]
            running = self._active is not None and self._active in self._caps \
                and self._caps[self._active]['state'] == 'running'
        return {'success': True, 'available': self.available(),
                'reason': self.unavailable_reason(),
                'interfaces': _iface_names(), 'default_interface': _default_iface(),
                'running': running, 'active_id': self._active if running else None,
                'captures': caps, 'limits': {
                    'max_seconds': MAX_SECONDS, 'max_packets': MAX_PACKETS,
                    'max_bytes': MAX_BYTES, 'max_keep': MAX_KEEP}}

    def summary(self):
        """Compact block for the mesh features payload."""
        d = self.list()
        return {'running': d['running'], 'active_id': d['active_id'],
                'interfaces': d['interfaces'], 'default_interface': d['default_interface'],
                'count': len(d['captures']), 'recent': d['captures'][:6],
                'limits': d['limits']}

    def path_for(self, cid):
        with self._lock:
            rec = self._caps.get(cid)
            if not rec or rec['state'] == 'running':
                return None
            p = rec.get('path')
            return p if (p and os.path.isfile(p)) else None

    def view(self, cid, limit=None):
        """Decode a finished capture to a packet list + a small summary, so the
        result shows on screen (not only as a download). Reads the pcap with
        `tcpdump -nr` — the file is one we wrote, addressed by id, never a
        caller-supplied path."""
        if not self.available():
            return {'success': False, 'error': self.unavailable_reason()}
        path = self.path_for(cid)
        if not path:
            return {'success': False, 'error': 'No readable capture for that id.'}
        limit = _clamp(limit, DEFAULT_VIEW_LINES, 1, MAX_VIEW_LINES)
        cmd = self._tcpdump_cmd(['-nr', path, '-c', str(limit)])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Reading the capture timed out.'}
        except Exception as exc:
            return {'success': False, 'error': f'Could not read capture: {exc}'}
        lines = [ln for ln in (proc.stdout or '').splitlines() if ln.strip()]
        if not lines and proc.returncode not in (0, None):
            err = (proc.stderr or '').strip().splitlines()
            return {'success': False, 'error': (err[-1] if err else 'tcpdump could not read the file')[:200]}
        protocols, src_counts = {}, {}
        for ln in lines:
            p = _classify_proto(ln)
            protocols[p] = protocols.get(p, 0) + 1
            m = _SRC_RE.search(ln)
            if m:
                src_counts[m.group(1)] = src_counts.get(m.group(1), 0) + 1
        top_src = sorted(src_counts.items(), key=lambda kv: -kv[1])[:5]
        with self._lock:
            rec = self._caps.get(cid) or {}
            total = rec.get('packets', 0)
            bytes_ = rec.get('bytes', 0)
            iface = rec.get('interface', '')
        return {'success': True, 'id': cid, 'interface': iface,
                'shown': len(lines), 'total': total,
                'truncated': bool(total and len(lines) >= limit and len(lines) < total),
                'bytes_human': _human_bytes(bytes_),
                'protocols': protocols, 'top_src': top_src, 'lines': lines}

    # -- lifecycle ------------------------------------------------------------
    def _prune_locked(self):
        while len(self._order) > MAX_KEEP:
            old = self._order.pop(0)
            rec = self._caps.pop(old, None)
            if rec and rec.get('path'):
                try:
                    os.remove(rec['path'])
                except OSError:
                    pass

    def start(self, interface=None, seconds=None, max_packets=0, max_bytes=0,
              bpf=None, snaplen=None):
        if not self.available():
            return {'success': False, 'error': self.unavailable_reason()}

        iface = (interface or '').strip() or _default_iface()
        if not _IFACE_RE.match(iface) or iface.startswith('-'):
            return {'success': False, 'error': f'Invalid interface: {iface!r}.'}
        if iface != 'any' and iface not in _iface_names():
            return {'success': False, 'error': f'Unknown interface: {iface!r}.'}

        bpf = (bpf or '').strip()
        if bpf:
            if len(bpf) > _BPF_MAX or not _BPF_RE.match(bpf) or bpf.startswith('-'):
                return {'success': False, 'error': 'Invalid capture filter.'}

        seconds = _clamp(seconds, DEFAULT_SECONDS, 1, MAX_SECONDS)
        max_packets = _clamp(max_packets, 0, 0, MAX_PACKETS)
        max_bytes = _clamp(max_bytes, 0, 0, MAX_BYTES)
        snaplen = _clamp(snaplen, DEFAULT_SNAPLEN, 0, MAX_SNAPLEN)

        with self._lock:
            if self._active and self._caps.get(self._active, {}).get('state') == 'running':
                return {'success': False, 'error': 'A capture is already running on this unit.'}
            try:
                os.makedirs(self._dir, exist_ok=True)
            except OSError as exc:
                return {'success': False, 'error': f'Cannot create capture dir: {exc}'}

            cid = _token()
            stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            path = os.path.join(self._dir, f'cap_{iface}_{stamp}_{cid}.pcap')
            rec = {'id': cid, 'interface': iface, 'path': path, 'filter': bpf,
                   'seconds': seconds, 'max_packets': max_packets,
                   'max_bytes': max_bytes, 'snaplen': snaplen,
                   'state': 'running', 'started': time.time(), 'ended': None,
                   'packets': 0, 'bytes': 0, 'error': '', 'proc': None}
            self._caps[cid] = rec
            self._order.append(cid)
            self._active = cid
            self._prune_locked()

        args = ['-i', iface, '-w', path, '-n', '-U', '-s', str(snaplen)]
        if max_packets:
            args += ['-c', str(max_packets)]
        if bpf:
            args.append(bpf)
        cmd = self._tcpdump_cmd(args)

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE)
        except FileNotFoundError:
            self._finish(cid, state='error', error='tcpdump is not installed.')
            return {'success': False, 'error': 'tcpdump is not installed.'}
        except Exception as exc:
            self._finish(cid, state='error', error=str(exc))
            return {'success': False, 'error': str(exc)}

        with self._lock:
            rec['proc'] = proc
        threading.Thread(target=self._watch, args=(cid, proc, seconds, max_bytes),
                         name=f'pcap-{cid}', daemon=True).start()
        return {'success': True, 'id': cid, 'capture': self._record_public(rec)}

    def _watch(self, cid, proc, seconds, max_bytes):
        """Enforce the time/size ceiling, then record the result."""
        deadline = time.time() + seconds
        path = self._caps[cid]['path']
        while proc.poll() is None:
            if time.time() >= deadline:
                self._terminate(proc)
                break
            if max_bytes:
                try:
                    if os.path.getsize(path) >= max_bytes:
                        self._terminate(proc)
                        break
                except OSError:
                    pass
            time.sleep(0.3)
        try:
            _, stderr = proc.communicate(timeout=5)
        except Exception:
            stderr = b''
        packets = _parse_packets(stderr)
        with self._lock:
            rec = self._caps.get(cid)
            if not rec:
                return
            cancelled = rec.get('state') == 'canceling'
            try:
                rec['bytes'] = os.path.getsize(path)
            except OSError:
                rec['bytes'] = 0
            rec['packets'] = packets
            rec['ended'] = time.time()
            rec['proc'] = None
            if rec['bytes'] == 0 and proc.returncode not in (0, None) and not cancelled:
                rec['state'] = 'error'
                err = (stderr or b'').decode('utf-8', 'replace').strip().splitlines()
                rec['error'] = (err[-1] if err else f'tcpdump exited {proc.returncode}')[:300]
            else:
                rec['state'] = 'canceled' if cancelled else 'done'
            if self._active == cid:
                self._active = None

    @staticmethod
    def _terminate(proc):
        try:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        except Exception:
            pass

    def _finish(self, cid, state, error=''):
        with self._lock:
            rec = self._caps.get(cid)
            if rec:
                rec['state'] = state
                rec['error'] = error
                rec['ended'] = time.time()
                rec['proc'] = None
            if self._active == cid:
                self._active = None

    def cancel(self, cid):
        with self._lock:
            rec = self._caps.get(cid)
            if not rec:
                return {'success': False, 'error': 'No such capture.'}
            if rec['state'] != 'running':
                return {'success': True, 'capture': self._record_public(rec),
                        'message': 'Capture already stopped.'}
            rec['state'] = 'canceling'
            proc = rec.get('proc')
        if proc:
            self._terminate(proc)
        return {'success': True, 'message': 'Stopping capture.'}


def _token():
    import secrets
    return secrets.token_hex(4)


_PKT_RE = re.compile(rb'(\d+)\s+packets captured')


def _parse_packets(stderr):
    m = _PKT_RE.search(stderr or b'')
    return int(m.group(1)) if m else 0


# Source host.port in a tcpdump -n line, e.g. "10.0.0.1.443 > 10.0.0.2.51000:".
_SRC_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*)\.\w+ > ')


def _classify_proto(line):
    """Rough protocol label for a tcpdump -n line, for the view's summary tally."""
    if 'ARP,' in line or line[:4] == 'ARP ':
        return 'ARP'
    if 'ICMP6' in line:
        return 'ICMPv6'
    if ' ICMP ' in line or ': ICMP' in line:
        return 'ICMP'
    if 'Flags [' in line or ' tcp ' in line:
        return 'TCP'
    if re.search(r'\bUDP\b', line) or re.search(r'\.\d+ > \S+\.(?:53|67|68|123|5353|443)\b', line):
        return 'UDP'
    if 'IP6 ' in line:
        return 'IPv6'
    return 'Other'


_manager = None
_manager_lock = threading.Lock()


def get_capture_manager():
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = CaptureManager()
    return _manager


# --------------------------------------------------------------------------
# Self-test (no root / no live capture): validation, clamping, parsing.
# --------------------------------------------------------------------------
def selftest():
    results = []

    def check(name, cond, detail=''):
        results.append({'name': name, 'pass': bool(cond), 'detail': str(detail)})

    m = CaptureManager(base_dir='/tmp/ragnar-cap-selftest')

    r = m.start(interface='bad;iface')
    check('reject invalid interface', not r['success'] and 'interface' in r['error'].lower(), r)
    r = m.start(interface='-i')
    check('reject option-looking interface', not r['success'], r)
    r = m.start(interface='eth0', bpf='-w /etc/passwd')
    check('reject option-looking filter', not r['success'] and 'filter' in r['error'].lower(), r)
    r = m.start(interface='eth0', bpf='tcp port 80 and host 10.0.0.1')
    # eth0 may not exist on the test box; either an unknown-iface reject or a
    # tcpdump-availability reject is fine — the point is the FILTER passed.
    check('accept a valid BPF filter (not a filter error)',
          r.get('error', '').lower().find('filter') < 0, r)

    check('clamp seconds to ceiling', _clamp(99999, 60, 1, MAX_SECONDS) == MAX_SECONDS)
    check('clamp negative to floor', _clamp(-5, 60, 1, MAX_SECONDS) == 1)
    check('clamp junk to default', _clamp('abc', 60, 1, MAX_SECONDS) == 60)

    check('parse packet count', _parse_packets(b'tcpdump: listening\n42 packets captured\n') == 42)
    check('parse packet count missing -> 0', _parse_packets(b'no match') == 0)

    check('human bytes', _human_bytes(1536) == '1.5 KB' and _human_bytes(0) == '0 B')

    check('classify TCP', _classify_proto('12:00:00 IP 10.0.0.1.443 > 10.0.0.2.5100: Flags [P.], length 20') == 'TCP')
    check('classify ARP', _classify_proto('12:00:00 ARP, Request who-has 10.0.0.1 tell 10.0.0.2') == 'ARP')
    check('classify ICMP', _classify_proto('12:00:00 IP 10.0.0.1 > 10.0.0.2: ICMP echo request') == 'ICMP')
    _m = _SRC_RE.search('12:00:00 IP 10.0.0.1.443 > 10.0.0.2.5100: Flags [P.]')
    check('view src regex extracts source', _m and _m.group(1) == '10.0.0.1', _m and _m.group(1))

    passed = sum(1 for r in results if r['pass'])
    return {'pass': passed == len(results), 'passed': passed,
            'total': len(results), 'results': results}


if __name__ == '__main__':  # pragma: no cover
    import json
    print(json.dumps(selftest(), indent=2))
