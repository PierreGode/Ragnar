"""oamwatch detection engine.

Consumes parsed OAMPDUs and emits findings. Pure logic: no sockets, no
transmit, no scapy. Session state is learned from the link itself within one
discovery exchange - there is no operator-supplied baseline and no learn mode.
"""

from collections import deque

from . import registry as reg
from .config import Config
from .parser import (
    CODE_EVENT_NOTIFICATION, CODE_INFORMATION, CODE_LOOPBACK_CONTROL,
    CODE_VARIABLE_REQUEST, CODE_VARIABLE_RESPONSE, LOOPBACK_ENABLE,
    LOOPBACK_DISABLE, PARSER_LOOPBACK, PARSER_NAMES, MUX_DISCARD, MUX_NAMES,
    CFG_RESERVED_MASK, _mac,
)

SEQ_HALF = 0x8000


class Finding:
    __slots__ = ("code", "name", "klass", "severity", "ts", "src", "detail",
                 "evidence")

    def __init__(self, code, ts, src, detail, evidence=None):
        self.code = code
        self.name = reg.name_of(code)
        self.klass = reg.class_of(code)
        self.severity = reg.severity_of(code)
        self.ts = ts
        self.src = src
        self.detail = detail
        self.evidence = evidence or {}

    def __repr__(self):
        return "Finding(%s %s %s)" % (self.code, self.severity, self.detail)

    def as_dict(self):
        return {
            "code": self.code,
            "name": self.name,
            "class": self.klass,
            "severity": self.severity,
            "ts": self.ts,
            "src": self.src,
            "detail": self.detail,
            "evidence": dict(self.evidence),
        }


class PeerState:
    __slots__ = ("mac", "identity", "config", "operational", "last_flags",
                 "posture_emitted", "flag_events", "last_event_seq",
                 "loopback_reported", "in_remote_loopback", "first_seen",
                 "pdu_count")

    def __init__(self, mac, ts):
        self.mac = mac
        self.identity = None
        self.config = None
        self.operational = False
        self.last_flags = None
        self.posture_emitted = set()
        self.flag_events = {}       # flag name -> deque of assertion ts
        self.last_event_seq = None
        self.loopback_reported = False
        self.in_remote_loopback = False
        self.first_seen = ts
        self.pdu_count = 0


_FAILURE_FLAGS = (
    ("link_fault", "OAM-065", "Link Fault"),
    ("dying_gasp", "OAM-063", "Dying Gasp"),
    ("critical_event", "OAM-064", "Critical Event"),
)

_POSTURE_BITS = (
    ("loopback_supported", "OAM-020", "remote loopback"),
    ("variable_retrieval", "OAM-021", "variable retrieval"),
    ("mode_active", "OAM-022", "active mode"),
    ("unidirectional", "OAM-023", "unidirectional operation"),
)


class Engine:
    """Stateful detector for one tapped segment."""

    def __init__(self, config=None):
        self.cfg = config or Config()
        self.peers = {}
        self.rate_window = deque()
        self._last_rate_report = None
        self._multi_peer_reported = False
        self.findings = []
        self.frames_seen = 0

    # -- emission ---------------------------------------------------------
    def _emit(self, out, code, ts, src, detail, evidence=None):
        if code in self.cfg.suppress:
            return
        if reg.class_of(code) == reg.POSTURE and not self.cfg.posture_enabled:
            return
        f = Finding(code, ts, src, detail, evidence)
        out.append(f)
        self.findings.append(f)

    # -- main entry -------------------------------------------------------
    def observe(self, pdu):
        """Process one parsed OAMPDU. Returns the findings it produced."""
        out = []
        ts = pdu.ts if pdu.ts is not None else 0.0
        src = _mac(pdu.src) if pdu.src else "??"
        self.frames_seen += 1

        # structural defects straight from the parser
        for d in pdu.defects:
            self._emit(out, d.code, ts, src, d.detail,
                       {"offset": d.offset, "code_name": pdu.code_name})

        self._check_rate(out, ts, src)

        peer = self.peers.get(src)
        if peer is None:
            peer = PeerState(src, ts)
            self.peers[src] = peer
            if len(self.peers) > 1 and not self._multi_peer_reported:
                self._multi_peer_reported = True
                self._emit(out, "OAM-074", ts, src,
                           "OAM speakers on this segment: %s. Link OAM is "
                           "point-to-point; a second source address is an "
                           "injector or a mis-patched span."
                           % ", ".join(sorted(self.peers)),
                           {"peers": sorted(self.peers)})
        peer.pdu_count += 1

        if pdu.flags is not None:
            self._check_flags(out, pdu, peer, ts, src)

        if pdu.code == CODE_INFORMATION:
            self._check_information(out, pdu, peer, ts, src)
        elif pdu.code == CODE_LOOPBACK_CONTROL:
            self._check_loopback(out, pdu, peer, ts, src)
        elif pdu.code == CODE_VARIABLE_REQUEST:
            self._check_var_request(out, pdu, ts, src)
        elif pdu.code == CODE_VARIABLE_RESPONSE:
            self._check_var_response(out, pdu, ts, src)
        elif pdu.code == CODE_EVENT_NOTIFICATION:
            self._check_event(out, pdu, peer, ts, src)

        return out

    # -- rate -------------------------------------------------------------
    def _check_rate(self, out, ts, src):
        w = self.rate_window
        w.append(ts)
        while w and ts - w[0] > 1.0:
            w.popleft()
        if len(w) <= self.cfg.rate_limit_pdus_per_sec:
            return
        if (self._last_rate_report is not None
                and ts - self._last_rate_report < self.cfg.rate_report_cooldown_sec):
            return
        self._last_rate_report = ts
        self._emit(out, "OAM-070", ts, src,
                   "%d OAMPDUs in the trailing second; the standard caps the "
                   "slow-protocol plane at %d/second"
                   % (len(w), self.cfg.rate_limit_pdus_per_sec),
                   {"observed_rate": len(w),
                    "cap": self.cfg.rate_limit_pdus_per_sec})

    # -- flags ------------------------------------------------------------
    def _check_flags(self, out, pdu, peer, ts, src):
        prev = peer.last_flags
        for attr, code, label in _FAILURE_FLAGS:
            now = bool(getattr(pdu, attr))
            was = None if prev is None else bool(prev & _FLAG_BIT[attr])
            if now and not was:
                self._emit(out, code, ts, src,
                           "%s asserted by peer %s" % (label, src),
                           {"flags": "0x%04x" % pdu.flags})
                hist = peer.flag_events.setdefault(attr, deque())
                hist.append(ts)
                while hist and ts - hist[0] > self.cfg.flap_window_sec:
                    hist.popleft()
                if len(hist) >= self.cfg.flap_threshold:
                    self._emit(out, "OAM-066", ts, src,
                               "%s asserted %d times in %.0fs while the OAM "
                               "session stayed up. A genuine %s means the peer "
                               "lost power; this peer kept transmitting."
                               % (label, len(hist), self.cfg.flap_window_sec,
                                  label),
                               {"flag": label, "assertions": len(hist)})
                    hist.clear()

        # discovery restart: a peer that was operational drops its stable bit
        if peer.operational and pdu.local_stable is False and pdu.local_evaluating:
            self._emit(out, "OAM-067", ts, src,
                       "peer %s returned to discovery (Local Stable cleared, "
                       "Local Evaluating set) with the session already "
                       "established" % src,
                       {"flags": "0x%04x" % pdu.flags})
            peer.operational = False
        if pdu.local_stable:
            peer.operational = True
        peer.last_flags = pdu.flags

    # -- information ------------------------------------------------------
    def _check_information(self, out, pdu, peer, ts, src):
        tlv = pdu.local_info
        if tlv is None:
            return

        ident = tlv.identity()
        if peer.identity is None:
            peer.identity = ident
        elif ident != peer.identity:
            self._emit(out, "OAM-068", ts, src,
                       "peer %s changed identity: OUI %s->%s, vendor info "
                       "%s->%s" % (src, peer.identity[0].hex(), ident[0].hex(),
                                   peer.identity[1].hex(), ident[1].hex()),
                       {"old_oui": peer.identity[0].hex(),
                        "new_oui": ident[0].hex()})
            peer.identity = ident
            peer.posture_emitted.clear()

        if peer.config is None:
            peer.config = tlv.config
        elif tlv.config != peer.config:
            self._emit(out, "OAM-069", ts, src,
                       "peer %s changed its OAM Configuration mid-session: "
                       "0x%02x -> 0x%02x" % (src, peer.config, tlv.config),
                       {"old_config": "0x%02x" % peer.config,
                        "new_config": "0x%02x" % tlv.config,
                        "gained": _config_delta(peer.config, tlv.config)})
            peer.config = tlv.config
            peer.posture_emitted.clear()

        # posture: once per peer per identity
        for attr, code, label in _POSTURE_BITS:
            if getattr(tlv, attr) and code not in peer.posture_emitted:
                peer.posture_emitted.add(code)
                self._emit(out, code, ts, src,
                           "peer %s advertises %s" % (src, label),
                           {"oam_config": "0x%02x" % tlv.config})

        if tlv.max_pdu_size is not None and not (64 <= tlv.max_pdu_size <= 1518):
            if "OAM-024" not in peer.posture_emitted:
                peer.posture_emitted.add("OAM-024")
                self._emit(out, "OAM-024", ts, src,
                           "peer %s advertises a maximum OAMPDU size of %d "
                           "octets, outside the 64..1518 range the standard "
                           "permits" % (src, tlv.max_pdu_size),
                           {"max_pdu_size": tlv.max_pdu_size})

        # loopback state confirmation, from either information TLV
        for which in ("local_info", "remote_info"):
            t = getattr(pdu, which)
            if t is None or t.state is None:
                continue
            pa, ma = t.parser_action, t.mux_action
            if pa == PARSER_LOOPBACK or ma == MUX_DISCARD:
                if not peer.in_remote_loopback:
                    peer.in_remote_loopback = True
                    self._emit(out, "OAM-062", ts, src,
                               "%s Information TLV from %s reports "
                               "parser=%s multiplexer=%s: the link is in "
                               "remote loopback and higher-layer traffic is "
                               "being discarded"
                               % (t.kind, src, PARSER_NAMES.get(pa),
                                  MUX_NAMES.get(ma)),
                               {"state": "0x%02x" % t.state,
                                "parser": PARSER_NAMES.get(pa),
                                "mux": MUX_NAMES.get(ma)})
            elif which == "local_info":
                peer.in_remote_loopback = False

    # -- loopback control -------------------------------------------------
    def _check_loopback(self, out, pdu, peer, ts, src):
        if pdu.loopback_cmd == LOOPBACK_ENABLE:
            if peer.loopback_reported and not self.cfg.report_every_loopback:
                return
            peer.loopback_reported = True
            self._emit(out, "OAM-060", ts, src,
                       "Loopback Control enable from %s. In steady state this "
                       "PDU should not exist: it places the peer in remote "
                       "loopback, sending its higher-layer egress to DISCARD "
                       "and blackholing the link." % src,
                       {"command": "0x%02x" % pdu.loopback_cmd})
        elif pdu.loopback_cmd == LOOPBACK_DISABLE:
            self._emit(out, "OAM-061", ts, src,
                       "Loopback Control disable from %s" % src,
                       {"command": "0x%02x" % pdu.loopback_cmd})

    # -- variables --------------------------------------------------------
    def _check_var_request(self, out, pdu, ts, src):
        if not pdu.var_descriptors:
            return
        want = ", ".join("branch 0x%02x leaf 0x%04x" % (b, l)
                         for b, l in pdu.var_descriptors[:8])
        self._emit(out, "OAM-071", ts, src,
                   "Variable Request from %s for %d Clause 30 variable(s): %s. "
                   "Link OAM variable retrieval is unauthenticated and in "
                   "cleartext." % (src, len(pdu.var_descriptors), want),
                   {"descriptors": [[b, l] for b, l in pdu.var_descriptors]})

    def _check_var_response(self, out, pdu, ts, src):
        returned = [c for c in pdu.var_containers if isinstance(c[2], int)]
        if not returned:
            return
        octets = sum(c[2] for c in returned)
        self._emit(out, "OAM-072", ts, src,
                   "Variable Response from %s returned %d Clause 30 "
                   "variable(s), %d octets of MIB contents, in cleartext on "
                   "the wire" % (src, len(returned), octets),
                   {"variables": [[c[0], c[1], c[2]] for c in returned],
                    "octets": octets})

    # -- events -----------------------------------------------------------
    def _check_event(self, out, pdu, peer, ts, src):
        seq = pdu.event_seq
        if seq is None:
            return
        last = peer.last_event_seq
        if last is not None:
            delta = (seq - last) & 0xFFFF
            if delta == 0 or delta > SEQ_HALF:
                self._emit(out, "OAM-073", ts, src,
                           "Event Notification sequence from %s went %d -> %d "
                           "(no forward progress); replayed or forged link-event "
                           "telemetry" % (src, last, seq),
                           {"previous": last, "observed": seq,
                            "events": [e[1] for e in pdu.events]})
        peer.last_event_seq = seq


_FLAG_BIT = {"link_fault": 0x0001, "dying_gasp": 0x0002, "critical_event": 0x0004}


def _config_delta(old, new):
    names = {0x01: "active_mode", 0x02: "unidirectional", 0x04: "loopback",
             0x08: "link_events", 0x10: "variable_retrieval"}
    gained = [n for b, n in names.items() if (new & b) and not (old & b)]
    lost = [n for b, n in names.items() if (old & b) and not (new & b)]
    out = []
    if gained:
        out.append("gained " + "/".join(sorted(gained)))
    if lost:
        out.append("lost " + "/".join(sorted(lost)))
    if new & CFG_RESERVED_MASK:
        out.append("reserved bits set")
    return "; ".join(out) or "no capability bits changed"
