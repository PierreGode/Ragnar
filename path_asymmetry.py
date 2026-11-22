"""Path-asymmetry / one-way-delay (OWD) detector for Ragnar — the data-plane side.

Replaces hop-count (TTL) inference with *measured* one-way delay. A tiny UDP
reflector stamps the reverse leg, a prober stamps the forward leg, giving the
OWAMP/TWAMP 4-timestamp set per probe:

    T1 = prober send      T2 = reflector recv
    T3 = reflector send   T4 = prober recv

    fwd = T2 - T1         rev = T4 - T3         RTT = (T4-T1) - (T3-T2)   [offset-free]

The honest catch (see the design note in the code review): a single unsynced
clock pair CANNOT separate a *constant* clock offset theta from a *constant* path
asymmetry — they alias. So this detector:
  * estimates the slowly-varying clock offset with Paxson's min-pair method over
    a sliding window (theta_hat = (min(fwd) - min(rev)) / 2), and
  * reports **de-offset asymmetry** = (fwd - rev) - 2*theta_hat, which cancels
    the window baseline and is therefore sensitive to asymmetry *changes/events*
    (a path shift that adds delay in one direction) — the thing you actually want
    to alarm on — at millisecond resolution instead of integer hops.
Absolute asymmetry is only trustworthy when the clocks are synchronised (PTP/GPS);
set clock_synced=True and the raw asymmetry is reported as authoritative too.

Layers, each unit-testable with no network:
  * Reflector / Prober — the measurement wire
  * AsymmetryDetector  — offset estimator + hysteretic event emitter
  * passive_hopcount_asymmetry — TTL fallback when there is no reflector
  * correlate — ties a data-plane event to control-plane truth from a RIB
"""

import math
import re
import socket
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Iterable, Optional, Sequence

_MAGIC = b'RGWD'
_PKT = struct.Struct('!4sIddd')       # magic, seq, t1, t2, t3
DEFAULT_PORT = 33434


# --- reflector: stamps T2 (recv) and T3 (send) -----------------------------
class Reflector:
    """UDP one-way-delay reflector. Echoes each probe with reflector recv/send
    timestamps. Passive to the network — it only answers probes sent to it."""

    def __init__(self, bind='0.0.0.0', port=DEFAULT_PORT):
        self.bind = bind
        self.port = port
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self.count = 0

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind, self.port))
        self._sock.settimeout(0.5)
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name='owd-reflector')
        self._thread.start()

    def stop(self):
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass

    def _run(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            t2 = time.time()
            if len(data) < _PKT.size or data[:4] != _MAGIC:
                continue
            _m, seq, t1, _a, _b = _PKT.unpack(data[:_PKT.size])
            t3 = time.time()
            try:
                self._sock.sendto(_PKT.pack(_MAGIC, seq, t1, t2, t3), addr)
                self.count += 1
            except OSError:
                pass


# --- prober: sends T1, records T4 ------------------------------------------
def probe_once(target, port=DEFAULT_PORT, seq=0, timeout=1.0):
    """Send one probe; return (t1, t2, t3, t4) or None on loss/timeout."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        t1 = time.time()
        s.sendto(_PKT.pack(_MAGIC, seq, t1, 0.0, 0.0), (target, port))
        data, _ = s.recvfrom(2048)
        t4 = time.time()
        if len(data) < _PKT.size or data[:4] != _MAGIC:
            return None
        _m, rseq, rt1, t2, t3 = _PKT.unpack(data[:_PKT.size])
        if rseq != seq:
            return None
        return (rt1, t2, t3, t4)
    except (socket.timeout, OSError):
        return None
    finally:
        s.close()


def probe_series(target, port=DEFAULT_PORT, count=20, interval=0.05, timeout=1.0):
    """Send a burst of probes; return the list of (t1,t2,t3,t4) samples received."""
    samples = []
    for i in range(count):
        s = probe_once(target, port, seq=i, timeout=timeout)
        if s:
            samples.append(s)
        time.sleep(interval)
    return samples


# --- detector: offset estimation + asymmetry events ------------------------
class AsymmetryDetector:
    """Consumes (T1,T2,T3,T4) samples, removes the slowly-varying clock offset
    with Paxson's min-pair estimator over a sliding window, and emits hysteretic
    asymmetry events carrying measured OWD (ms) — not hop-count inference."""

    def __init__(self, window=64, threshold_ms=5.0, enter_n=3, exit_ratio=0.5,
                 clock_synced=False, target=None):
        self.window = window
        self.threshold_ms = threshold_ms
        self.enter_n = enter_n
        self.exit_ratio = exit_ratio
        self.clock_synced = clock_synced
        self.target = target
        self._fwd = deque(maxlen=window)
        self._rev = deque(maxlen=window)
        self._rtt = deque(maxlen=window)
        self._over = 0
        self._under = 0
        self.state = 'symmetric'
        self.samples = 0
        self.last = None

    def theta_ms(self):
        """Estimated clock offset (ms). Paxson min-pair over the window."""
        if not self._fwd:
            return 0.0
        return (min(self._fwd) - min(self._rev)) / 2.0 * 1000.0

    def add(self, t1, t2, t3, t4):
        """Add a sample; return an event dict on a state transition, else None."""
        fwd = t2 - t1
        rev = t4 - t3
        rtt = (t4 - t1) - (t3 - t2)
        self._fwd.append(fwd)
        self._rev.append(rev)
        self._rtt.append(rtt)
        self.samples += 1
        theta = (min(self._fwd) - min(self._rev)) / 2.0
        # de-offset asymmetry: (fwd-rev) - 2*theta, cancels the window baseline
        asym_ms = ((fwd - rev) - 2.0 * theta) * 1000.0
        raw_asym_ms = (fwd - rev) * 1000.0
        self.last = {
            'fwd_ms': round(fwd * 1000.0, 3), 'rev_ms': round(rev * 1000.0, 3),
            'rtt_ms': round(rtt * 1000.0, 3), 'theta_ms': round(theta * 1000.0, 3),
            'asymmetry_ms': round(asym_ms, 3), 'raw_asymmetry_ms': round(raw_asym_ms, 3),
            'samples': self.samples,
        }
        # hysteresis on |de-offset asymmetry|
        mag = abs(asym_ms)
        event = None
        if mag >= self.threshold_ms:
            self._over += 1
            self._under = 0
            if self.state == 'symmetric' and self._over >= self.enter_n:
                self.state = 'asymmetric'
                event = self._event('asymmetry_detected', asym_ms)
        else:
            self._under += 1
            self._over = 0
            if self.state == 'asymmetric' and mag <= self.threshold_ms * self.exit_ratio \
                    and self._under >= self.enter_n:
                self.state = 'symmetric'
                event = self._event('asymmetry_cleared', asym_ms)
        return event

    def _event(self, kind, asym_ms):
        return {
            'kind': kind, 'target': self.target, 'ts': time.time(),
            'asymmetry_ms': round(asym_ms, 3),
            'direction': 'forward-longer' if asym_ms > 0 else 'reverse-longer',
            'measured': True, 'method': 'owd',
            'clock_synced': self.clock_synced,
            'absolute_trustworthy': self.clock_synced,
            'rtt_ms': self.last['rtt_ms'], 'theta_ms': self.last['theta_ms'],
            'fwd_ms': self.last['fwd_ms'], 'rev_ms': self.last['rev_ms'],
        }

    def summary(self):
        return {'state': self.state, 'samples': self.samples,
                'target': self.target, 'clock_synced': self.clock_synced,
                'threshold_ms': self.threshold_ms, 'last': self.last,
                'rtt_min_ms': round(min(self._rtt) * 1000.0, 3) if self._rtt else None,
                'theta_ms': round(self.theta_ms(), 3)}


# --- passive fallback: hop-count asymmetry from TTL -------------------------
_TTL_RE = re.compile(r'\bttl\s+(\d+)', re.I)
_SRC_RE = re.compile(r'\bIP6?\s+(\d{1,3}(?:\.\d{1,3}){3})')


def _guess_initial_ttl(observed):
    for base in (64, 128, 255):
        if observed <= base:
            return base
    return 255


def passive_hopcount_asymmetry(tcpdump_text, local_ip=None):
    """Coarse fallback when there is no reflector: infer per-peer hop distance
    from observed TTL (initial_ttl - observed). Reports hop counts, and — if a
    local_ip and its reverse-direction TTL are both seen — a hop-count delta.
    This is the OLD inference; the OWD detector supersedes it when a reflector
    is reachable."""
    hops = {}
    for line in tcpdump_text.splitlines():
        sm = _SRC_RE.search(line)
        tm = _TTL_RE.search(line)
        if sm and tm:
            ttl = int(tm.group(1))
            h = _guess_initial_ttl(ttl) - ttl
            hops.setdefault(sm.group(1), []).append(h)
    per_peer = {ip: min(v) for ip, v in hops.items() if v}   # min hop = shortest seen
    return {'method': 'hopcount', 'measured': False,
            'per_peer_hops': per_peer,
            'note': 'TTL-inferred hop distance (fallback); use the OWD reflector '
                    'for measured, millisecond-resolution asymmetry'}


# --- correlator: control-plane truth (RIB) <- data-plane event -------------
def correlate(event, rib):
    """Annotate a data-plane asymmetry `event` (needs a 'target' IP) with the
    control-plane truth from a BGP RIB: the covering prefix, AS-path, origin AS,
    and whether that prefix is currently flapping / recently changed. This is
    what ties measured asymmetry back to *why* — a route change rather than a
    transient — turning a symptom into an attributable event."""
    out = dict(event)
    target = event.get('target')
    route = rib.lookup(target) if (rib and target) else None
    if route is None:
        out['control_plane'] = None
        out['attribution'] = 'no covering route in RIB (target off-domain or RIB empty)'
        return out
    out['control_plane'] = {
        'prefix': route['prefix'], 'origin_as': route['origin_as'],
        'as_path': route['as_path'], 'next_hop': route['next_hop'],
        'flapping': route['flapping'], 'flap_rate': route['flap_rate'],
        'change_age_s': route['change_age_s'],
    }
    # attribution heuristic: a recent control-plane change coincident with the
    # data-plane asymmetry event strongly implicates a route change.
    if route['flapping']:
        out['attribution'] = ('correlated with a FLAPPING route for %s (%d changes/window) '
                              '— asymmetry is route-churn driven'
                              % (route['prefix'], route['flap_rate']))
    elif route['change_age_s'] is not None and route['change_age_s'] < 120:
        out['attribution'] = ('coincides with a route change for %s %.0fs ago via AS-path %s '
                              '— likely a path shift'
                              % (route['prefix'], route['change_age_s'],
                                 ' '.join(map(str, route['as_path']))))
    else:
        out['attribution'] = ('route for %s stable (last change %ss ago) — asymmetry is '
                              'data-plane (congestion/TE), not a routing change'
                              % (route['prefix'], route['change_age_s']))
    return out


def correlate_multi(event, named_ribs, window_s=30.0):
    """Correlate a data-plane event against MULTIPLE carrier RIBs — one BGP
    session per carrier-facing router. For a multi-homed operator this names
    *which* carrier's covering prefix churned (confirm) and which are stable, so
    you know where to open the incident call. Returns the event annotated with a
    per-carrier breakdown, `carriers_confirmed` / `carriers_stable` lists, an
    upgraded `verdict`, and a scope hint.

    Scope logic: one carrier moving => churn is in its AS or an upstream peer of
    it; all covering carriers moving together => upstream of all of them (origin
    AS or a major shared transit)."""
    out = dict(event)
    target = event.get('target')
    carriers, confirmed, stable, absent = [], [], [], []
    for name, rib in (named_ribs or {}).items():
        route = rib.lookup(target) if (rib and target) else None
        if route is None:
            carriers.append({'carrier': name, 'status': 'absent'})
            absent.append(name)
            continue
        recent = bool(route['flapping'] or
                      (route['change_age_s'] is not None and route['change_age_s'] <= window_s))
        status = 'confirm' if recent else 'stable'
        carriers.append({'carrier': name, 'status': status, 'prefix': route['prefix'],
                         'as_path': route['as_path'], 'prev_as_path': route.get('prev_as_path') or [],
                         'origin_as': route['origin_as'], 'change_age_s': route['change_age_s'],
                         'flapping': route['flapping'], 'flap_rate': route['flap_rate']})
        (confirmed if recent else stable).append(name)

    out['carriers'] = carriers
    out['carriers_confirmed'] = confirmed
    out['carriers_stable'] = stable
    covering = confirmed + stable

    if confirmed:
        out['verdict'] = 'confirmed'
        tag = []
        if confirmed:
            tag.append('%s confirm' % ', '.join(confirmed))
        if stable:
            tag.append('%s stable' % ', '.join(stable))
        detail = []
        for c in carriers:
            if c['status'] != 'confirm':
                continue
            if c.get('prev_as_path'):
                detail.append('%s: prefix %s AS-path %s -> %s' % (
                    c['carrier'], c['prefix'], c['prev_as_path'], c['as_path']))
            else:
                detail.append('%s: prefix %s churned %.0fs ago (AS-path %s)' % (
                    c['carrier'], c['prefix'], c['change_age_s'] or 0, c['as_path']))
        out['attribution'] = 'confirmed [%s] :: BGP RIB corroborates: %s' % (
            '; '.join(tag), '; '.join(detail))
        if len(confirmed) == 1 and len(covering) > 1:
            out['scope'] = ('single-carrier: churn is in %s or an upstream peer of it'
                            % confirmed[0])
        elif len(confirmed) > 1 and len(confirmed) == len(covering):
            out['scope'] = ('all-carriers: upstream of every carrier — look at the '
                            'origin AS or a major shared transit')
        else:
            out['scope'] = 'multi-carrier: %d of %d covering carriers moved' % (
                len(confirmed), len(covering))
    elif covering:
        out['attribution'] = ('all carriers stable [%s] — asymmetry is data-plane '
                              '(congestion/TE), not a routing change' % ', '.join(stable))
    else:
        out['attribution'] = 'no covering route in any carrier RIB (target off-domain)'
    return out


# ==========================================================================
# BGP Path Watch v2 — flow-consistent (Paris) traceroute + convergence scoring
# ==========================================================================
# The OWD detector above answers "is the path asymmetric?". This half answers
# "is the path *changing* — a BGP (re)convergence?". It fingerprints the path
# per ECMP flow (Paris-consistent: one flow id held constant across a TTL sweep
# so a change WITHIN a flow is a real routing change, while differences ACROSS
# flows are just ECMP and are not counted as churn), tracks loops / oscillation
# / flapping over time, scores a suspected convergence event, and — where a
# receive-only BGP collector is peered — upgrades the verdict to `confirmed`
# with the control-plane cause. Ported from the standalone pathwatch v2
# (analyze.py + probe.py), kept detection-only: the trace is active probing run
# only on demand, never during passive rotation.

STD_INITIAL_TTLS = (32, 64, 128, 255)


def infer_initial_ttl(recv_ttl):
    """Smallest standard initial TTL >= the received value (None on nonsense)."""
    if recv_ttl is None or recv_ttl < 1 or recv_ttl > 255:
        return None
    for init in STD_INITIAL_TTLS:
        if recv_ttl <= init:
            return init
    return None


def reverse_hops(recv_ttl):
    """Hops the reply took back to us = initial_ttl - recv_ttl (an inference:
    anycast / TTL-rewriting middleboxes / non-standard initial TTLs can lie)."""
    init = infer_initial_ttl(recv_ttl)
    if init is None:
        return None
    return init - recv_ttl


@dataclass
class AsymmetryVerdict:
    forward_hops: Optional[int]
    reverse_hops: Optional[int]
    delta: Optional[int]            # reverse - forward (positive => return longer)
    asymmetric: bool
    confidence: str                 # none | low | medium | high
    note: str = ""


def assess_asymmetry(forward_hops, reply_ttl, threshold=3):
    """Compare forward hop count vs TTL-inferred reverse hop count."""
    rev = reverse_hops(reply_ttl) if reply_ttl is not None else None
    if forward_hops is None or rev is None:
        missing = ("target did not complete forward trace" if forward_hops is None
                   else "no usable reply TTL")
        return AsymmetryVerdict(forward_hops, rev, None, False, "none",
                                "undetermined: " + missing)
    delta = rev - forward_hops
    mag = abs(delta)
    asymmetric = mag >= threshold
    if not asymmetric:
        conf = "none"
    elif mag >= threshold * 2:
        conf = "high"
    elif mag >= threshold + 1:
        conf = "medium"
    else:
        conf = "low"
    direction = "return path longer" if delta > 0 else "forward path longer"
    note = ("%s by %d hop(s)" % (direction, mag) if asymmetric
            else "paths within %d hops (symmetric enough)" % threshold)
    return AsymmetryVerdict(forward_hops, rev, delta, asymmetric, conf, note)


def _collapse(seq):
    out = []
    for x in seq:
        if not out or out[-1] != x:
            out.append(x)
    return out


def ip_path_fingerprint(hops):
    """Fingerprint an ordered list of hop IPs; keep '*' gaps as position-holders
    but trim leading/trailing gaps."""
    norm = [h if h else "*" for h in hops]
    while norm and norm[0] == "*":
        norm.pop(0)
    while norm and norm[-1] == "*":
        norm.pop()
    return tuple(norm)


def as_path_fingerprint(asns):
    """BGP-meaningful signature: drop unresolved (None) and collapse consecutive
    duplicates — robust to intra-AS load balancing."""
    return tuple(_collapse([a for a in asns if a]))


def has_loop(hops):
    """A real IP repeating at two TTLs => forwarding loop (mid-convergence)."""
    seen = set()
    for h in hops:
        if not h or h == "*":
            continue
        if h in seen:
            return True
        seen.add(h)
    return False


class EwmaChart:
    """Incremental EWMA/EWMV; flags a sample whose z-score vs the prior estimate
    exceeds k (after warmup) — an RTT shelf-jump, the convergence signal, not
    steady jitter."""

    def __init__(self, alpha=0.2, k=4.0, warmup=8, min_std_ms=0.5):
        self.alpha = alpha
        self.k = k
        self.warmup = warmup
        self.min_std = min_std_ms
        self.n = 0
        self.mean = 0.0
        self.var = 0.0

    def update(self, x):
        self.n += 1
        if self.n == 1:
            self.mean = x
            self.var = 0.0
            return (False, 0.0)
        std = max(math.sqrt(self.var), self.min_std)
        z = (x - self.mean) / std
        is_step = self.n > self.warmup and abs(z) >= self.k
        diff = x - self.mean
        self.mean += self.alpha * diff
        self.var = (1 - self.alpha) * (self.var + self.alpha * diff * diff)
        return (is_step, z)


class FlapTracker:
    """Rolling window of path fingerprints; counts transitions (flapping) and
    detects A->B->A oscillation."""

    def __init__(self, window=12, flap_transitions=4):
        self.window = window
        self.flap_transitions = flap_transitions
        self.fps = deque(maxlen=window)

    def update(self, fp):
        prev = self.fps[-1] if self.fps else None
        changed = prev is not None and fp != prev
        self.fps.append(fp)
        transitions = sum(1 for a, b in zip(self.fps, list(self.fps)[1:]) if a != b)
        distinct = len(set(self.fps))
        return {"changed": changed, "transitions": transitions, "distinct": distinct,
                "oscillating": self._oscillates(),
                "flapping": transitions >= self.flap_transitions}

    def _oscillates(self):
        seq = list(self.fps)
        for i in range(2, len(seq)):
            if seq[i] == seq[i - 2] and seq[i] != seq[i - 1]:
                return True
        return False


@dataclass
class ConvergenceEvidence:
    loss_burst: int = 0
    rtt_step: bool = False
    rtt_z: float = 0.0
    as_path_changed: bool = False
    ip_path_changed: bool = False
    loop: bool = False
    oscillating: bool = False
    flapping: bool = False
    rib_confirmed: bool = False
    rib_cause: str = ""


@dataclass
class ConvergenceVerdict:
    score: int
    suspected: bool
    severity: str                   # none | watch | suspected | active | confirmed
    reasons: list = field(default_factory=list)
    evidence: Optional[ConvergenceEvidence] = None


_CONV_WEIGHTS = {
    "rib_confirmed": 6, "as_path_changed": 4, "loop": 4, "oscillating": 3,
    "flapping": 3, "loss_burst": 2, "rtt_step": 2, "ip_path_changed": 1,
}


def score_convergence(ev, loss_burst_min=3, suspect_at=5):
    """Combine evidence into a single suspicion score + human reasons."""
    score = 0
    reasons = []
    if ev.rib_confirmed:
        score += _CONV_WEIGHTS["rib_confirmed"]
        reasons.append("BGP RIB corroborates: " + (ev.rib_cause or "control-plane event"))
    if ev.as_path_changed:
        score += _CONV_WEIGHTS["as_path_changed"]
        reasons.append("AS-path changed within a fixed flow (real routing change)")
    if ev.loop:
        score += _CONV_WEIGHTS["loop"]
        reasons.append("forwarding loop in trace (transient loop = mid-convergence)")
    if ev.oscillating:
        score += _CONV_WEIGHTS["oscillating"]
        reasons.append("path oscillating A->B->A")
    if ev.flapping:
        score += _CONV_WEIGHTS["flapping"]
        reasons.append("path flapping (many transitions in window)")
    if ev.loss_burst >= loss_burst_min:
        score += _CONV_WEIGHTS["loss_burst"]
        reasons.append("loss burst of %d consecutive probes" % ev.loss_burst)
    if ev.rtt_step:
        score += _CONV_WEIGHTS["rtt_step"]
        reasons.append("RTT step-change (z=%.1f)" % ev.rtt_z)
    if ev.ip_path_changed and not ev.as_path_changed:
        score += _CONV_WEIGHTS["ip_path_changed"]
        reasons.append("intra-AS path change (IP-path only)")

    suspected = score >= suspect_at
    if ev.rib_confirmed:
        severity = "confirmed"
        suspected = True
    elif score == 0:
        severity = "none"
    elif score < suspect_at:
        severity = "watch"
    elif ev.loss_burst >= loss_burst_min and (ev.as_path_changed or ev.loop):
        severity = "active"
    else:
        severity = "suspected"
    return ConvergenceVerdict(score, suspected, severity, reasons, ev)


# --- flow-consistent (Paris) traceroute -----------------------------------
_TRACE_PAYLOAD = b"pathwatch-flow--"
_ICMP_ECHO_REPLY, _ICMP_DEST_UNREACH, _ICMP_TIME_EXCEEDED = 0, 3, 11


@dataclass
class HopResult:
    ttl: int
    ip: Optional[str]
    rtt_ms: Optional[float]
    recv_ttl: Optional[int]
    reached: bool
    kind: Optional[str]


@dataclass
class TraceResult:
    target: str
    flow: int
    method: str
    hops: list
    reached: bool
    forward_hops: Optional[int]
    target_reply_ttl: Optional[int]

    def ip_path(self):
        return [h.ip for h in self.hops]


def build_probe(target, ttl, flow, method="icmp"):
    """Construct a single flow-selected probe. `flow` is the ECMP/path selector,
    held constant across a TTL sweep (Paris). scapy imported lazily."""
    from scapy.all import IP, ICMP, UDP, TCP, Raw
    ip = IP(dst=target, ttl=ttl)
    if method == "icmp":
        return ip / ICMP(id=flow & 0xFFFF, seq=1) / Raw(_TRACE_PAYLOAD)
    if method == "udp":
        return ip / UDP(sport=(flow & 0x7FFF) | 0x8000, dport=33434) / Raw(_TRACE_PAYLOAD)
    if method == "tcp-syn":
        return ip / TCP(sport=(flow & 0x7FFF) | 0x8000, dport=443, flags="S")
    raise ValueError("unknown method %r" % method)


def parse_reply(sent, reply, target):
    """Interpret a reply against the probe we sent (scapy layers, imported lazily)."""
    from scapy.all import IP, ICMP, TCP
    ttl = sent[IP].ttl
    if reply is None:
        return HopResult(ttl, None, None, None, False, None)
    src = reply[IP].src
    recv_ttl = reply[IP].ttl
    rtt_ms = None
    if getattr(sent, "sent_time", None) and getattr(reply, "time", None):
        rtt_ms = (reply.time - sent.sent_time) * 1000.0
    reached = (src == target)
    kind = None
    if reply.haslayer(ICMP):
        t = int(reply[ICMP].type)
        if t == _ICMP_TIME_EXCEEDED:
            kind = "time-exceeded"
        elif t == _ICMP_ECHO_REPLY:
            kind = "echo-reply"
            reached = True
        elif t == _ICMP_DEST_UNREACH:
            kind = "unreachable"
            reached = reached or (src == target)
    elif reply.haslayer(TCP):
        kind = "tcp-reply"
        reached = (src == target)
    return HopResult(ttl, src, rtt_ms, recv_ttl, reached, kind)


def scapy_sender(pkt, timeout):
    """Production send_fn (scapy sr1; needs root / CAP_NET_RAW). Lazy import."""
    from scapy.all import sr1
    return sr1(pkt, timeout=timeout, verbose=0)


def trace_flow(target, flow, send_fn=None, method="icmp", max_ttl=30,
               timeout=1.0, stop_on_reach=True):
    """Run one flow-consistent trace and return the ordered path. send_fn is the
    injectable send/recv (scapy sr1 in prod, a fake in tests)."""
    send_fn = send_fn or scapy_sender
    hops = []
    reached = False
    forward_hops = None
    target_reply_ttl = None
    for ttl in range(1, max_ttl + 1):
        pkt = build_probe(target, ttl, flow, method)
        t0 = time.time()
        reply = send_fn(pkt, timeout)
        if reply is not None and not getattr(pkt, "sent_time", None):
            try:
                pkt.sent_time = t0
                if not getattr(reply, "time", None):
                    reply.time = time.time()
            except Exception:
                pass
        hop = parse_reply(pkt, reply, target)
        hops.append(hop)
        if hop.reached:
            reached = True
            forward_hops = ttl
            target_reply_ttl = hop.recv_ttl
            if stop_on_reach:
                break
    return TraceResult(target, flow, method, hops, reached, forward_hops,
                       target_reply_ttl)


def floor_ping(target, flow, send_fn=None, method="icmp", ttl=64, timeout=1.0):
    """A single full-TTL probe: RTT + the target's reply TTL (reverse-hop signal).
    Used by the latency floor to cheaply detect loss bursts / RTT steps."""
    send_fn = send_fn or scapy_sender
    pkt = build_probe(target, ttl, flow, method)
    t0 = time.time()
    reply = send_fn(pkt, timeout)
    if reply is not None and not getattr(pkt, "sent_time", None):
        try:
            pkt.sent_time = t0
            if not getattr(reply, "time", None):
                reply.time = time.time()
        except Exception:
            pass
    return parse_reply(pkt, reply, target)


# --- on-demand convergence orchestrator (fits the in-app snapshot model) ---
_CONV_FP_HISTORY = 12          # per-flow fingerprint window (FlapTracker)
_CONV_RTT_HISTORY = 48         # per-flow RTT window (EWMA step chart)


def assess_convergence(target, traces, prior=None, asn_of=None, named_ribs=None,
                       floor_rtts=None, loss_burst=0, loss_burst_min=3,
                       suspect_at=5, correlate_window_s=30.0):
    """Score a convergence event from one snapshot of per-flow traces, diffed
    against the persisted per-flow fingerprint/RTT history so a change WITHIN a
    fixed flow over successive runs registers as real routing churn.

    traces        : list[TraceResult] (one per ECMP flow)
    prior         : persisted state for this target (mutated copy returned as new)
    asn_of        : callable ip -> Optional[int] for AS-path fingerprinting
    named_ribs    : {carrier_name: bgp_speaker.RIB} for control-plane confirmation
    floor_rtts    : list[float] latency-floor RTT samples (ms) for the step chart
    loss_burst    : consecutive floor-probe losses observed

    Returns (result_dict, new_state)."""
    prior = dict(prior or {})
    flows_state = dict(prior.get('flows') or {})
    asn_of = asn_of or (lambda ip: None)

    any_as_change = any_ip_change = any_loop = any_flap = any_osc = False
    per_flow = []
    best_fwd = None
    best_reply_ttl = None

    for tr in traces:
        ip_list = tr.ip_path()
        ip_fp = ip_path_fingerprint(ip_list)
        as_fp = as_path_fingerprint([asn_of(ip) for ip in ip_list])
        loop = has_loop(ip_list)
        fkey = str(tr.flow)
        fs = dict(flows_state.get(fkey) or {})
        fp_hist = list(fs.get('fp_history') or [])
        prev_fp = tuple(fp_hist[-1]) if fp_hist else None
        # AS-path fingerprint is the churn signal when we can resolve it; else the
        # IP-path fingerprint is the (weaker, intra-AS) fallback.
        cur_fp = as_fp if as_fp else ip_fp
        changed = prev_fp is not None and tuple(cur_fp) != prev_fp
        as_changed = bool(as_fp) and changed
        ip_changed = (not as_fp) and changed

        ft = FlapTracker(window=_CONV_FP_HISTORY)
        for h in fp_hist:
            ft.update(tuple(h))
        fl = ft.update(tuple(cur_fp))

        fp_hist.append(list(cur_fp))
        fp_hist = fp_hist[-_CONV_FP_HISTORY:]
        fs['fp_history'] = fp_hist
        flows_state[fkey] = fs

        any_as_change = any_as_change or as_changed
        any_ip_change = any_ip_change or ip_changed
        any_loop = any_loop or loop
        any_flap = any_flap or fl['flapping']
        any_osc = any_osc or fl['oscillating']
        if tr.reached and (best_fwd is None or tr.forward_hops < best_fwd):
            best_fwd = tr.forward_hops
            best_reply_ttl = tr.target_reply_ttl

        per_flow.append({
            'flow': tr.flow, 'method': tr.method, 'reached': tr.reached,
            'forward_hops': tr.forward_hops, 'hops': ip_list,
            'as_path': [a for a in (asn_of(ip) for ip in ip_list) if a],
            'loop': loop, 'changed': changed, 'as_path_changed': as_changed,
            'ip_path_changed': ip_changed, 'flapping': fl['flapping'],
            'oscillating': fl['oscillating'], 'transitions': fl['transitions'],
        })

    # RTT step-change over the floor samples (prior history + this run's).
    rtt_hist = list(prior.get('rtt_history') or [])
    chart = EwmaChart()
    rtt_step = False
    rtt_z = 0.0
    for x in rtt_hist:
        chart.update(x)
    for x in (floor_rtts or []):
        step, z = chart.update(x)
        if step:
            rtt_step = True
            rtt_z = z
    rtt_hist = (rtt_hist + list(floor_rtts or []))[-_CONV_RTT_HISTORY:]

    # Hop-count asymmetry (independent axis, reported alongside).
    asym = assess_asymmetry(best_fwd, best_reply_ttl)

    # Control-plane confirmation from the receive-only collector's RIB(s).
    rib_confirmed = False
    rib_cause = ""
    carriers = []
    if named_ribs:
        stub = {'kind': 'convergence', 'target': target}
        mc = correlate_multi(stub, named_ribs, window_s=correlate_window_s)
        carriers = mc.get('carriers', [])
        if mc.get('carriers_confirmed'):
            rib_confirmed = True
            rib_cause = mc.get('attribution', '')

    ev = ConvergenceEvidence(
        loss_burst=loss_burst, rtt_step=rtt_step, rtt_z=rtt_z,
        as_path_changed=any_as_change, ip_path_changed=any_ip_change,
        loop=any_loop, oscillating=any_osc, flapping=any_flap,
        rib_confirmed=rib_confirmed, rib_cause=rib_cause)
    verdict = score_convergence(ev, loss_burst_min=loss_burst_min,
                                suspect_at=suspect_at)

    new_state = {'flows': flows_state, 'rtt_history': rtt_hist,
                 'last_ts': time.time()}
    result = {
        'target': target,
        'score': verdict.score,
        'severity': verdict.severity,
        'suspected': verdict.suspected,
        'reasons': verdict.reasons,
        'evidence': {
            'loss_burst': ev.loss_burst, 'rtt_step': ev.rtt_step,
            'rtt_z': round(ev.rtt_z, 2), 'as_path_changed': ev.as_path_changed,
            'ip_path_changed': ev.ip_path_changed, 'loop': ev.loop,
            'oscillating': ev.oscillating, 'flapping': ev.flapping,
            'rib_confirmed': ev.rib_confirmed, 'rib_cause': ev.rib_cause,
        },
        'asymmetry': {
            'forward_hops': asym.forward_hops, 'reverse_hops': asym.reverse_hops,
            'delta': asym.delta, 'asymmetric': asym.asymmetric,
            'confidence': asym.confidence, 'note': asym.note,
        },
        'flows': per_flow,
        'carriers': carriers,
    }
    return result, new_state


# --- self-test (no network for the detector; loopback for the wire) --------
def selftest():
    scen = []

    def check(name, ok, detail=''):
        scen.append({'name': name, 'pass': bool(ok), 'detail': str(detail)})

    # 1. offset removal + step-asymmetry event. Inject a CONSTANT clock offset
    #    theta=20ms and a STEP: forward path gains +12ms after sample 40. The
    #    detector must (a) not fire on the constant offset, (b) fire at the step.
    det = AsymmetryDetector(window=64, threshold_ms=5.0, enter_n=3, target='198.51.100.7')
    theta = 0.020                      # 20 ms clock offset (prober ahead)
    base_fwd, base_rev = 0.010, 0.010  # symmetric 10ms each way at baseline
    fired_before = fired_after = None
    t = 1000.0
    for i in range(90):
        extra = 0.012 if i >= 45 else 0.0          # forward path shift at i=45
        fwd = base_fwd + extra
        rev = base_rev
        # build timestamps with the offset: reflector clock = prober clock - theta
        t1 = t
        t2 = t1 + fwd - theta                       # reflector recv (its clock)
        t3 = t2 + 0.0002                            # reflector send
        t4 = t3 + rev + theta                       # prober recv (its clock)
        ev = det.add(t1, t2, t3, t4)
        if ev and i < 45:
            fired_before = ev
        if ev and i >= 45 and ev['kind'] == 'asymmetry_detected':
            fired_after = fired_after or ev
        t += 0.05
    theta_ok = abs(abs(det.theta_ms()) - 20.0) < 3.0   # recovered ~20ms offset (sign is convention)
    mag_ok = fired_after and abs(fired_after['asymmetry_ms'] - 12.0) < 3.0
    check('owd-offset-removed-no-false-event', theta_ok and fired_before is None,
          'theta=%.1f fired_before=%s' % (det.theta_ms(), fired_before))
    check('owd-step-event-measured-magnitude', bool(mag_ok),
          'event=%s' % (fired_after,))

    # 2. reflector <-> prober loopback: symmetric, ~0 asymmetry, no event
    refl = Reflector(bind='127.0.0.1', port=33500)
    refl.start()
    time.sleep(0.2)
    samples = probe_series('127.0.0.1', port=33500, count=20, interval=0.01)
    refl.stop()
    ld = AsymmetryDetector(threshold_ms=5.0, target='127.0.0.1')
    loop_events = [e for s in samples for e in [ld.add(*s)] if e]
    check('loopback-wire', len(samples) >= 15 and ld.state == 'symmetric'
          and not loop_events, 'n=%d state=%s' % (len(samples), ld.state))

    # 3. correlator ties an event to a flapping RIB route
    import bgp_speaker
    rib = bgp_speaker.RIB(flap_window_s=60, flap_threshold=3)
    now = time.time()
    for k in range(4):
        rib.apply_update({'announced': ['198.51.100.0/24'], 'withdrawn': [],
                          'as_path': [65001, 65002 + k], 'next_hop': '10.0.0.2',
                          'communities': []}, now=now + k)
    ev = {'kind': 'asymmetry_detected', 'target': '198.51.100.7', 'asymmetry_ms': 12.0}
    ann = correlate(ev, rib)
    check('correlator-attributes-flap',
          ann['control_plane'] and ann['control_plane']['flapping']
          and 'route-churn' in ann['attribution'], ann.get('attribution'))

    # 4. passive TTL fallback parses hop counts
    txt = ("IP 8.8.8.8 > 10.0.0.1: ICMP echo reply, ttl 57\n"
           "IP 1.1.1.1 > 10.0.0.1: tcp, ttl 250\n")
    hc = passive_hopcount_asymmetry(txt)
    check('passive-hopcount', hc['per_peer_hops'].get('8.8.8.8') == 7
          and hc['per_peer_hops'].get('1.1.1.1') == 5, hc['per_peer_hops'])

    # 5. multi-carrier correlator: Carrier-A's covering prefix just changed its
    #    AS-path while Carrier-B and Carrier-C stay stable — the event must be
    #    upgraded to `confirmed` and name Carrier-A as the mover.
    t0 = time.time()
    rib_a = bgp_speaker.RIB()
    rib_a.apply_update({'announced': ['9.9.9.0/24'], 'as_path': [64512, 64520],
                        'next_hop': '10.0.0.1', 'communities': []}, now=t0 - 300)
    rib_a.apply_update({'announced': ['9.9.9.0/24'], 'as_path': [64512, 64530],
                        'next_hop': '10.0.0.1', 'communities': []}, now=t0 - 2)
    rib_b = bgp_speaker.RIB()
    rib_b.apply_update({'announced': ['9.9.9.0/24'], 'as_path': [64513, 64540],
                        'next_hop': '10.0.0.2', 'communities': []}, now=t0 - 3600)
    rib_c = bgp_speaker.RIB()
    rib_c.apply_update({'announced': ['9.9.9.0/24'], 'as_path': [64514, 64550],
                        'next_hop': '10.0.0.3', 'communities': []}, now=t0 - 3600)
    ev = {'kind': 'asymmetry_detected', 'target': '9.9.9.9', 'asymmetry_ms': 10.0}
    mc = correlate_multi(ev, {'Carrier-A': rib_a, 'Carrier-B': rib_b, 'Carrier-C': rib_c})
    check('multi-carrier-confirm',
          mc['verdict'] == 'confirmed' and mc['carriers_confirmed'] == ['Carrier-A']
          and set(mc['carriers_stable']) == {'Carrier-B', 'Carrier-C'},
          '%s conf=%s stable=%s' % (mc.get('verdict'), mc.get('carriers_confirmed'),
                                    mc.get('carriers_stable')))
    check('multi-carrier-old-new-path',
          '[64512, 64520] -> [64512, 64530]' in mc['attribution'], mc['attribution'])
    check('multi-carrier-scope-single',
          'single-carrier' in mc.get('scope', ''), mc.get('scope'))
    # all carriers stable -> not upgraded (data-plane), no false confirm
    for r in (rib_a, rib_b, rib_c):
        r.apply_update({'announced': ['9.9.9.0/24'], 'as_path': [1, 2],
                        'next_hop': '10.0.0.1', 'communities': []}, now=t0 - 3600)
    stable_ev = correlate_multi(dict(ev), {'Carrier-A': rib_a, 'Carrier-B': rib_b})
    check('multi-carrier-all-stable-no-confirm',
          stable_ev.get('verdict') != 'confirmed' and 'all carriers stable' in stable_ev['attribution'],
          stable_ev.get('attribution'))

    # ---- convergence engine (ported from pathwatch v2) --------------------
    # 6. hop-count asymmetry: fwd 5 hops, reply TTL 50 => reverse 14 hops.
    a = assess_asymmetry(5, 50)
    check('assess-asymmetry-hopcount',
          a.asymmetric and a.reverse_hops == 14 and a.delta == 9 and a.confidence == 'high',
          '%s' % (a,))

    # 7. path fingerprints + loop + oscillation primitives.
    # None is dropped first, so the two 65002 become consecutive and collapse.
    check('as-path-fingerprint-collapse',
          as_path_fingerprint([65001, 65001, 65002, None, 65002]) == (65001, 65002),
          as_path_fingerprint([65001, 65001, 65002, None, 65002]))
    check('has-loop', has_loop(['10.0.0.1', '10.0.0.2', '10.0.0.1']) and
          not has_loop(['10.0.0.1', '*', '10.0.0.2']), '')
    ft = FlapTracker(window=8)
    for fp in [('A',), ('B',), ('A',), ('B',), ('A',)]:
        r = ft.update(fp)
    check('flap-oscillation', r['oscillating'], r)

    # 8. score_convergence tiers: RIB confirmation => 'confirmed'; loss + AS-path
    #    change happening now => 'active'; jitter alone stays sub-suspect.
    v_conf = score_convergence(ConvergenceEvidence(rib_confirmed=True,
                                                   rib_cause='prefix churn'))
    v_active = score_convergence(ConvergenceEvidence(as_path_changed=True, loss_burst=3))
    v_watch = score_convergence(ConvergenceEvidence(rtt_step=True, rtt_z=5.0))
    check('score-convergence-tiers',
          v_conf.severity == 'confirmed' and v_active.severity == 'active'
          and v_watch.severity == 'watch',
          '%s/%s/%s' % (v_conf.severity, v_active.severity, v_watch.severity))

    # 9. assess_convergence over two snapshots of the SAME flow: the AS-path
    #    changes within the fixed flow between run 1 and run 2 => real churn.
    def _trace(flow, ips, reply_ttl=50):
        hops = [HopResult(i + 1, ip, 1.0, reply_ttl if ip == ips[-1] else 250,
                          ip == ips[-1], 'echo-reply' if ip == ips[-1] else 'time-exceeded')
                for i, ip in enumerate(ips)]
        return TraceResult('9.9.9.9', flow, 'icmp', hops, True, len(ips), reply_ttl)

    asn_map = {'10.0.0.1': 65001, '10.0.0.2': 65002, '10.0.0.9': 65009,
               '9.9.9.9': None}
    asn_of = lambda ip: asn_map.get(ip)
    r1, st1 = assess_convergence('9.9.9.9',
                                 [_trace(1, ['10.0.0.1', '10.0.0.2', '9.9.9.9'])],
                                 prior=None, asn_of=asn_of)
    r2, st2 = assess_convergence('9.9.9.9',
                                 [_trace(1, ['10.0.0.1', '10.0.0.9', '9.9.9.9'])],
                                 prior=st1, asn_of=asn_of, loss_burst=3)
    check('assess-convergence-first-run-baseline',
          not r1['evidence']['as_path_changed'] and r1['severity'] in ('none', 'watch'),
          r1['severity'])
    check('assess-convergence-detects-as-path-change',
          r2['evidence']['as_path_changed'] and r2['severity'] in ('suspected', 'active'),
          '%s reasons=%s' % (r2['severity'], r2['reasons']))

    # 10. assess_convergence upgraded to 'confirmed' by a flapping RIB route.
    rib_x = bgp_speaker.RIB(flap_window_s=60, flap_threshold=3)
    tnow = time.time()
    for k in range(4):
        rib_x.apply_update({'announced': ['9.9.9.0/24'], 'withdrawn': [],
                            'as_path': [65001, 65002 + k], 'next_hop': '10.0.0.2',
                            'communities': []}, now=tnow + k)
    r3, _ = assess_convergence('9.9.9.9',
                               [_trace(1, ['10.0.0.1', '10.0.0.2', '9.9.9.9'])],
                               prior=None, asn_of=asn_of, named_ribs={'Carrier-A': rib_x})
    check('assess-convergence-rib-confirmed',
          r3['severity'] == 'confirmed' and r3['evidence']['rib_confirmed'],
          '%s cause=%s' % (r3['severity'], r3['evidence']['rib_cause'][:60]))

    return {'success': all(s['pass'] for s in scen), 'scenarios': scen}


if __name__ == '__main__':
    import json
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'reflector':
        port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
        r = Reflector(port=port)
        r.start()
        print('OWD reflector on udp/%d — Ctrl-C to stop' % port)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            r.stop()
        sys.exit(0)
    res = selftest()
    for s in res['scenarios']:
        print('  [%s] %s%s' % ('PASS' if s['pass'] else 'FAIL', s['name'],
                               '' if s['pass'] else '  -> ' + s['detail']))
    print('Path-asymmetry self-test:', 'OK' if res['success'] else 'FAILED')
    if '--json' in sys.argv:
        print(json.dumps(res, indent=2, default=str))
    sys.exit(0 if res['success'] else 1)
