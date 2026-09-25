#!/usr/bin/env python3
"""siem_forwarder.py — outbound SIEM / log-forwarding for Ragnar alerts.

Ragnar's detectors are excellent, but until now every finding died inside the
box: the Watchtower pane and a Pushover message were the only exits. Enterprises
run a SIEM (Splunk, QRadar, Elastic, Sentinel, Graylog, …) and will not adopt a
sensor that cannot feed it. This module is that exit.

It consumes the *same normalized alert dicts* that ``watchtower.normalize()``
produces and ``_watchtower_check_once()`` already pages to Pushover, and ships
each one to one or more external collectors:

  * **syslog**      — RFC 5424 or RFC 3164 framing over UDP or TCP (optionally
                      TLS), carrying a **CEF** (ArcSight / Splunk / Microsoft
                      Sentinel), **LEEF** (IBM QRadar), or plain-text payload.
  * **splunk_hec**  — Splunk HTTP Event Collector (JSON over HTTPS, token auth).
  * **elastic**     — Elasticsearch / OpenSearch ``_bulk`` index (ECS-shaped
                      JSON over HTTP(S), optional basic/API-key auth).
  * **webhook**     — generic JSON POST; a ``slack`` flavour emits a text block
                      so it drops straight into a Slack/Mattermost/Teams hook.

Design rules
------------
* **Best-effort, time-bounded, never fatal.** A dead or slow collector must not
  block the monitor loop or raise into it — every delivery is wrapped, socket
  and HTTP calls carry a short timeout, and the result is a small stats dict.
* **Stdlib only.** ``socket``, ``ssl``, ``urllib`` — nothing to ``pip install``,
  so it runs on a Pi Zero 2 W the same as on a rack server.
* **Config-agnostic core.** Targets are plain dicts (``type`` + fields); the web
  layer owns where those live. Secrets are redacted in every ``describe()``.

Self-test (no network needed for formatting; loops a local UDP socket for the
wire path):  ``python3 siem_forwarder.py --self-test``
"""

import json
import socket
import ssl
import sys
import time
from datetime import datetime, timezone

MODULE = 'siem_forwarder'
PRODUCT_VENDOR = 'Ragnar'
PRODUCT_NAME = 'Ragnar'
PRODUCT_VERSION = '1.0'

# --------------------------------------------------------------------------
# Severity maps.  Ragnar's canonical ladder is watchtower.SEVERITIES:
#   critical / high / medium / low / info
# --------------------------------------------------------------------------

# Ragnar severity -> syslog numeric severity (RFC 5424 §6.2.1)
#   emerg0 alert1 crit2 err3 warn4 notice5 info6 debug7
_SYSLOG_SEVERITY = {
    'critical': 2, 'high': 3, 'medium': 4, 'low': 5, 'info': 6,
}
# Ragnar severity -> CEF/LEEF severity (integer 0..10)
_CEF_SEVERITY = {
    'critical': 10, 'high': 8, 'medium': 5, 'low': 3, 'info': 1,
}
# Syslog facilities by name (numeric part; the *8 happens at PRI time)
_SYSLOG_FACILITY = {
    'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3, 'auth': 4, 'syslog': 5,
    'lpr': 6, 'news': 7, 'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
    'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19, 'local4': 20,
    'local5': 21, 'local6': 22, 'local7': 23,
}

_SECRET_KEYS = ('token', 'password', 'api_key', 'apikey', 'secret',
                'auth', 'authorization', 'hec_token')

# canonical rank, kept local so this module doesn't hard-depend on watchtower
_SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def _s(v):
    """Coerce anything to a clean single-line string."""
    if v is None:
        return ''
    return str(v).replace('\r', ' ').replace('\n', ' ').strip()


def _alert_ts(alert):
    """Epoch seconds for an alert, tolerating missing/odd ts."""
    ts = alert.get('ts')
    if isinstance(ts, (int, float)) and ts > 0:
        return float(ts)
    return time.time()


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def _codes_str(alert):
    codes = alert.get('codes') or []
    if isinstance(codes, list):
        return ','.join(_s(c) for c in codes if _s(c))
    return _s(codes)


def _signature_id(alert):
    """A stable-ish signature id for CEF/LEEF: source + first code."""
    codes = alert.get('codes') or []
    first = _s(codes[0]) if isinstance(codes, list) and codes else ''
    src = _s(alert.get('source') or alert.get('module') or 'alert')
    return (src + ':' + first) if first else src


def _redact(cfg):
    """Copy a target config with secret values masked, for logs/UI."""
    out = {}
    for k, v in (cfg or {}).items():
        if k.lower() in _SECRET_KEYS and v:
            out[k] = '***'
        else:
            out[k] = v
    return out


# --------------------------------------------------------------------------
# Payload formatters
# --------------------------------------------------------------------------

def _cef_escape_header(v):
    return _s(v).replace('\\', '\\\\').replace('|', '\\|')


def _cef_escape_ext(v):
    return _s(v).replace('\\', '\\\\').replace('=', '\\=')


def to_cef(alert, hostname=None):
    """ArcSight Common Event Format (also ingested by Splunk & Sentinel).

    CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
    """
    sev = alert.get('severity', 'info')
    header = 'CEF:0|%s|%s|%s|%s|%s|%d|' % (
        _cef_escape_header(PRODUCT_VENDOR),
        _cef_escape_header(PRODUCT_NAME),
        _cef_escape_header(PRODUCT_VERSION),
        _cef_escape_header(_signature_id(alert)),
        _cef_escape_header(alert.get('title') or _signature_id(alert)),
        _CEF_SEVERITY.get(sev, 1),
    )
    ext = []

    def add(key, value):
        value = _s(value)
        if value:
            ext.append('%s=%s' % (key, _cef_escape_ext(value)))

    add('rt', str(int(_alert_ts(alert) * 1000)))     # ms epoch, CEF standard
    add('cat', alert.get('source'))
    add('deviceExternalId', alert.get('module'))
    add('src', alert.get('src'))
    add('dst', alert.get('target'))
    add('cs1Label', 'codes')
    add('cs1', _codes_str(alert))
    add('cs2Label', 'ragnarSeverity')
    add('cs2', sev)
    add('msg', alert.get('title'))
    if hostname:
        add('dvchost', hostname)
    return header + ' '.join(ext)


def to_leef(alert, hostname=None):
    """IBM QRadar Log Event Extended Format 2.0 (tab-delimited attributes)."""
    header = 'LEEF:2.0|%s|%s|%s|%s|' % (
        _s(PRODUCT_VENDOR), _s(PRODUCT_NAME), _s(PRODUCT_VERSION),
        _s(_signature_id(alert)),
    )
    sev = alert.get('severity', 'info')
    attrs = []

    def add(key, value):
        value = _s(value).replace('\t', ' ')
        if value:
            attrs.append('%s=%s' % (key, value))

    add('devTime', _iso(_alert_ts(alert)))
    add('devTimeFormat', "yyyy-MM-dd'T'HH:mm:ssXXX")
    add('sev', str(_CEF_SEVERITY.get(sev, 1)))
    add('cat', alert.get('source'))
    add('src', alert.get('src'))
    add('dst', alert.get('target'))
    add('policy', _codes_str(alert))
    add('msg', alert.get('title'))
    add('ragnarSeverity', sev)
    if hostname:
        add('identHostName', hostname)
    return header + '\t'.join(attrs)


def to_plain(alert, hostname=None):
    """Human-readable single line for plain syslog / text webhooks."""
    codes = _codes_str(alert)
    return 'ragnar %s [%s] %s%s%s%s' % (
        _s(alert.get('severity')).upper(),
        _s(alert.get('source')),
        ('(%s) ' % codes) if codes else '',
        _s(alert.get('title')),
        (' src=%s' % _s(alert.get('src'))) if alert.get('src') else '',
        (' dst=%s' % _s(alert.get('target'))) if alert.get('target') else '',
    )


def to_ecs(alert, hostname=None):
    """Elastic Common Schema-shaped JSON dict (also fine for HEC/webhook)."""
    ts = _alert_ts(alert)
    sev = alert.get('severity', 'info')
    doc = {
        '@timestamp': _iso(ts),
        'event': {
            'kind': 'alert',
            'category': ['network', 'intrusion_detection'],
            'module': _s(alert.get('module') or alert.get('source')),
            'dataset': 'ragnar.' + _s(alert.get('source') or 'alert'),
            'severity': _CEF_SEVERITY.get(sev, 1),
            'provider': 'ragnar',
        },
        'message': _s(alert.get('title')),
        'rule': {
            'name': _s(alert.get('title')),
            'id': _codes_str(alert),
            'ruleset': _s(alert.get('source')),
        },
        'ragnar': {
            'severity': sev,
            'source': _s(alert.get('source')),
            'codes': alert.get('codes') or [],
            'label': _s(alert.get('label')),
        },
        'observer': {
            'vendor': PRODUCT_VENDOR, 'product': PRODUCT_NAME,
            'hostname': _s(hostname) or None,
        },
        'tags': ['ragnar', _s(alert.get('source'))],
    }
    src = _s(alert.get('src'))
    dst = _s(alert.get('target'))
    if src:
        doc['source'] = {'address': src, 'ip': src}
    if dst:
        doc['destination'] = {'address': dst}
    return doc


_FORMATTERS = {
    'cef': to_cef, 'leef': to_leef, 'plain': to_plain, 'text': to_plain,
}


# --------------------------------------------------------------------------
# Syslog framing (RFC 5424 / RFC 3164)
# --------------------------------------------------------------------------

_RFC3164_MONTHS = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                   'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')


def syslog_pri(facility, severity_name):
    fac = _SYSLOG_FACILITY.get(str(facility).lower(), 16)
    sev = _SYSLOG_SEVERITY.get(severity_name, 6)
    return fac * 8 + sev


def frame_syslog(alert, payload, hostname, facility='local0', rfc='5424'):
    """Wrap an already-formatted payload string in a syslog line."""
    pri = syslog_pri(facility, alert.get('severity', 'info'))
    host = _s(hostname) or 'ragnar'
    ts = _alert_ts(alert)
    if str(rfc) == '3164':
        dt = datetime.fromtimestamp(ts)
        stamp = '%s %2d %02d:%02d:%02d' % (_RFC3164_MONTHS[dt.month - 1],
                                           dt.day, dt.hour, dt.minute, dt.second)
        return '<%d>%s %s ragnar: %s' % (pri, stamp, host, payload)
    # RFC 5424: <PRI>1 TIMESTAMP HOST APP-NAME PROCID MSGID SD MSG
    # APP-NAME=ragnar, PROCID=-, MSGID=alert, STRUCTURED-DATA=- (none).
    stamp = datetime.fromtimestamp(ts, timezone.utc).isoformat()
    return '<%d>1 %s %s ragnar - alert - %s' % (pri, stamp, host, payload)


# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------

class SiemTarget:
    """Base class. A target turns a list of normalized alerts into zero or more
    network deliveries and returns a small stats dict; it never raises."""

    type = 'base'

    def __init__(self, cfg, hostname=None):
        self.cfg = dict(cfg or {})
        self.hostname = hostname or _default_hostname()
        self.name = _s(self.cfg.get('name')) or self.type
        try:
            self.timeout = float(self.cfg.get('timeout', 5.0))
        except (TypeError, ValueError):
            self.timeout = 5.0

    def deliver(self, alerts):
        sent = 0
        errors = []
        for a in alerts:
            try:
                self._send_one(a)
                sent += 1
            except Exception as exc:                        # noqa: BLE001
                errors.append(str(exc))
                break        # collector is down; don't hammer it this cycle
        return {'target': self.name, 'type': self.type,
                'sent': sent, 'failed': len(alerts) - sent,
                'error': errors[0] if errors else None}

    def _send_one(self, alert):
        raise NotImplementedError

    def describe(self):
        return {'name': self.name, 'type': self.type,
                'config': _redact(self.cfg)}


class SyslogTarget(SiemTarget):
    """Syslog over UDP or TCP(+TLS), payload = CEF / LEEF / plain."""

    type = 'syslog'

    def __init__(self, cfg, hostname=None):
        super().__init__(cfg, hostname)
        self.host = _s(self.cfg.get('host')) or '127.0.0.1'
        try:
            self.port = int(self.cfg.get('port', 514))
        except (TypeError, ValueError):
            self.port = 514
        self.proto = _s(self.cfg.get('protocol') or 'udp').lower()
        self.tls = bool(self.cfg.get('tls', False))
        self.facility = _s(self.cfg.get('facility') or 'local0')
        self.rfc = _s(self.cfg.get('rfc') or '5424')
        self.fmt = _s(self.cfg.get('format') or 'cef').lower()
        self._sock = None

    def _payload(self, alert):
        formatter = _FORMATTERS.get(self.fmt, to_cef)
        body = formatter(alert, self.hostname)
        return frame_syslog(alert, body, self.hostname,
                            facility=self.facility, rfc=self.rfc)

    def _send_one(self, alert):
        line = self._payload(alert)
        data = line.encode('utf-8', 'replace')
        if self.proto == 'tcp':
            self._send_tcp(data)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(data, (self.host, self.port))

    def _connect_tcp(self):
        raw = socket.create_connection((self.host, self.port), self.timeout)
        if self.tls:
            ctx = ssl.create_default_context()
            if self.cfg.get('insecure_skip_verify'):
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=self.host)
        raw.settimeout(self.timeout)
        return raw

    def _send_tcp(self, data):
        # RFC 6587 octet-counting framing — unambiguous over a stream.
        frame = str(len(data)).encode('ascii') + b' ' + data
        if self._sock is None:
            self._sock = self._connect_tcp()
        try:
            self._sock.sendall(frame)
        except (OSError, ssl.SSLError):
            # reconnect once — collectors drop idle TCP sessions
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = self._connect_tcp()
            self._sock.sendall(frame)


class HttpTarget(SiemTarget):
    """Shared HTTP(S) POST plumbing for HEC / Elastic / webhook targets."""

    type = 'http'

    def __init__(self, cfg, hostname=None):
        super().__init__(cfg, hostname)
        self.url = _s(self.cfg.get('url'))
        self.verify = not bool(self.cfg.get('insecure_skip_verify', False))

    def _post(self, url, body_bytes, headers):
        import urllib.request
        import urllib.error
        req = urllib.request.Request(url, data=body_bytes, headers=headers,
                                     method='POST')
        ctx = None
        if url.lower().startswith('https') and not self.verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=ctx) as resp:
                if resp.status >= 300:
                    raise RuntimeError('HTTP %s' % resp.status)
                return resp.read()
        except urllib.error.HTTPError as exc:
            raise RuntimeError('HTTP %s: %s' % (exc.code, exc.reason))


class SplunkHecTarget(HttpTarget):
    """Splunk HTTP Event Collector. One request per delivery batch."""

    type = 'splunk_hec'

    def deliver(self, alerts):
        if not alerts:
            return {'target': self.name, 'type': self.type, 'sent': 0,
                    'failed': 0, 'error': None}
        token = _s(self.cfg.get('token') or self.cfg.get('hec_token'))
        index = _s(self.cfg.get('index'))
        source_type = _s(self.cfg.get('sourcetype') or 'ragnar:alert')
        lines = []
        for a in alerts:
            evt = {'time': _alert_ts(a), 'host': self.hostname,
                   'source': 'ragnar', 'sourcetype': source_type,
                   'event': to_ecs(a, self.hostname)}
            if index:
                evt['index'] = index
            lines.append(json.dumps(evt, separators=(',', ':')))
        body = ('\n'.join(lines)).encode('utf-8', 'replace')
        headers = {'Authorization': 'Splunk %s' % token,
                   'Content-Type': 'application/json'}
        try:
            self._post(self.url, body, headers)
            return {'target': self.name, 'type': self.type,
                    'sent': len(alerts), 'failed': 0, 'error': None}
        except Exception as exc:                            # noqa: BLE001
            return {'target': self.name, 'type': self.type, 'sent': 0,
                    'failed': len(alerts), 'error': str(exc)}


class ElasticTarget(HttpTarget):
    """Elasticsearch / OpenSearch _bulk index of ECS documents."""

    type = 'elastic'

    def deliver(self, alerts):
        if not alerts:
            return {'target': self.name, 'type': self.type, 'sent': 0,
                    'failed': 0, 'error': None}
        index = _s(self.cfg.get('index') or 'ragnar-alerts')
        url = self.url.rstrip('/')
        if not url.endswith('_bulk'):
            url = url + '/_bulk'
        action = json.dumps({'index': {'_index': index}}, separators=(',', ':'))
        lines = []
        for a in alerts:
            lines.append(action)
            lines.append(json.dumps(to_ecs(a, self.hostname),
                                    separators=(',', ':')))
        body = ('\n'.join(lines) + '\n').encode('utf-8', 'replace')
        headers = {'Content-Type': 'application/x-ndjson'}
        auth = self._auth_header()
        if auth:
            headers['Authorization'] = auth
        try:
            self._post(url, body, headers)
            return {'target': self.name, 'type': self.type,
                    'sent': len(alerts), 'failed': 0, 'error': None}
        except Exception as exc:                            # noqa: BLE001
            return {'target': self.name, 'type': self.type, 'sent': 0,
                    'failed': len(alerts), 'error': str(exc)}

    def _auth_header(self):
        api_key = _s(self.cfg.get('api_key'))
        if api_key:
            return 'ApiKey %s' % api_key
        user = _s(self.cfg.get('username'))
        pw = _s(self.cfg.get('password'))
        if user:
            import base64
            raw = ('%s:%s' % (user, pw)).encode('utf-8')
            return 'Basic %s' % base64.b64encode(raw).decode('ascii')
        return None


class WebhookTarget(HttpTarget):
    """Generic JSON webhook. flavour='slack' posts a {text: ...} block instead."""

    type = 'webhook'

    def deliver(self, alerts):
        if not alerts:
            return {'target': self.name, 'type': self.type, 'sent': 0,
                    'failed': 0, 'error': None}
        flavour = _s(self.cfg.get('flavour') or self.cfg.get('flavor')).lower()
        headers = {'Content-Type': 'application/json'}
        for k, v in (self.cfg.get('headers') or {}).items():
            headers[_s(k)] = _s(v)
        try:
            if flavour == 'slack':
                text = '\n'.join('• ' + to_plain(a, self.hostname)
                                 for a in alerts)
                body = json.dumps({'text': text}).encode('utf-8')
                self._post(self.url, body, headers)
            else:
                docs = [to_ecs(a, self.hostname) for a in alerts]
                body = json.dumps({'source': 'ragnar', 'count': len(docs),
                                   'alerts': docs}).encode('utf-8')
                self._post(self.url, body, headers)
            return {'target': self.name, 'type': self.type,
                    'sent': len(alerts), 'failed': 0, 'error': None}
        except Exception as exc:                            # noqa: BLE001
            return {'target': self.name, 'type': self.type, 'sent': 0,
                    'failed': len(alerts), 'error': str(exc)}


_TARGET_TYPES = {
    'syslog': SyslogTarget,
    'splunk_hec': SplunkHecTarget,
    'splunk': SplunkHecTarget,
    'elastic': ElasticTarget,
    'elasticsearch': ElasticTarget,
    'opensearch': ElasticTarget,
    'webhook': WebhookTarget,
    'slack': WebhookTarget,
}


def _default_hostname():
    try:
        return socket.gethostname() or 'ragnar'
    except OSError:
        return 'ragnar'


def make_target(cfg, hostname=None):
    """Build a target from a config dict, or None for unknown/disabled types."""
    if not isinstance(cfg, dict):
        return None
    t = _s(cfg.get('type')).lower()
    cls = _TARGET_TYPES.get(t)
    if cls is None:
        return None
    if t == 'slack':
        cfg = dict(cfg, flavour='slack')
    return cls(cfg, hostname=hostname)


# --------------------------------------------------------------------------
# Forwarder
# --------------------------------------------------------------------------

class SiemForwarder:
    """Fan a list of normalized alerts out to every enabled target.

    ``targets_cfg`` is a list of dicts. ``min_severity`` (canonical name) floors
    what is forwarded, independent of Watchtower's own notify floor."""

    def __init__(self, targets_cfg, hostname=None, min_severity=None):
        self.hostname = hostname or _default_hostname()
        self.min_rank = _SEV_RANK.get(min_severity, 0) if min_severity else 0
        self.targets = []
        for tc in (targets_cfg or []):
            if not isinstance(tc, dict) or not tc.get('enabled', True):
                continue
            tgt = make_target(tc, hostname=self.hostname)
            if tgt is not None:
                self.targets.append(tgt)
        self.last_results = []

    def _floor(self, alerts):
        if not self.min_rank:
            return list(alerts)
        return [a for a in alerts
                if _SEV_RANK.get(a.get('severity'), 0) >= self.min_rank]

    def forward(self, alerts):
        """Deliver ``alerts`` to every target. Returns per-target stats; never
        raises. A target's own failure is captured, not propagated."""
        selected = self._floor(alerts or [])
        results = []
        if not selected:
            return results
        for tgt in self.targets:
            try:
                results.append(tgt.deliver(selected))
            except Exception as exc:                        # noqa: BLE001
                results.append({'target': tgt.name, 'type': tgt.type,
                                'sent': 0, 'failed': len(selected),
                                'error': str(exc)})
        self.last_results = results
        return results

    def describe(self):
        return [t.describe() for t in self.targets]

    @property
    def enabled_count(self):
        return len(self.targets)


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

def _self_test():
    checks = []

    def ck(name, cond):
        checks.append((name, bool(cond)))

    alert = {
        'ts': 1_700_000_000.0, 'source': 'ndpwatch', 'module': 'ndpwatch',
        'severity': 'critical', 'rank': 4, 'title': 'router advert spoof',
        'codes': ['NDP-001', 'NDP-003'], 'src': 'fe80::66', 'target': '2001:db8::5',
        'label': 'NDP Watch (IPv6)',
    }
    low = dict(alert, severity='low', rank=1, codes=['X'], title='minor thing')

    # --- CEF -------------------------------------------------------------
    cef = to_cef(alert, 'ragnar-pi')
    ck('cef prefix', cef.startswith('CEF:0|Ragnar|Ragnar|'))
    ck('cef severity 10', '|10|' in cef)
    ck('cef carries src', 'src=fe80::66' in cef)
    ck('cef carries codes', 'cs1=NDP-001,NDP-003' in cef)
    ck('cef rt is ms epoch', 'rt=1700000000000' in cef)
    pipe = to_cef(dict(alert, title='a|b\\c'), 'h')
    ck('cef escapes header pipe/backslash', 'a\\|b\\\\c' in pipe)

    # --- LEEF ------------------------------------------------------------
    leef = to_leef(alert, 'ragnar-pi')
    ck('leef prefix', leef.startswith('LEEF:2.0|Ragnar|Ragnar|'))
    ck('leef tab-delimited', '\t' in leef)
    ck('leef sev', 'sev=10' in leef)

    # --- ECS -------------------------------------------------------------
    doc = to_ecs(alert, 'ragnar-pi')
    ck('ecs @timestamp', doc['@timestamp'].startswith('2023-'))
    ck('ecs event.module', doc['event']['module'] == 'ndpwatch')
    ck('ecs source.ip', doc.get('source', {}).get('ip') == 'fe80::66')
    ck('ecs rule.id codes', doc['rule']['id'] == 'NDP-001,NDP-003')
    ck('ecs json-serializable', bool(json.dumps(doc)))

    # --- plain -----------------------------------------------------------
    plain = to_plain(alert)
    ck('plain has severity', 'CRITICAL' in plain)
    ck('plain has codes', '(NDP-001,NDP-003)' in plain)

    # --- syslog framing --------------------------------------------------
    pri = syslog_pri('local0', 'critical')
    ck('pri local0/critical = 130', pri == 16 * 8 + 2)
    line5 = frame_syslog(alert, to_cef(alert, 'h'), 'ragnar-pi', rfc='5424')
    ck('rfc5424 pri+version', line5.startswith('<130>1 '))
    ck('rfc5424 embeds cef', 'CEF:0' in line5)
    line3 = frame_syslog(alert, to_plain(alert), 'ragnar-pi', rfc='3164')
    ck('rfc3164 pri', line3.startswith('<130>'))
    ck('rfc3164 has ragnar tag', 'ragnar:' in line3)

    # --- factory ---------------------------------------------------------
    ck('make_target syslog', isinstance(make_target({'type': 'syslog'}),
                                        SyslogTarget))
    ck('make_target splunk', isinstance(make_target({'type': 'splunk_hec'}),
                                        SplunkHecTarget))
    ck('make_target elastic', isinstance(make_target({'type': 'elastic'}),
                                         ElasticTarget))
    ck('make_target slack->webhook flavour',
       make_target({'type': 'slack'}).cfg.get('flavour') == 'slack')
    ck('make_target unknown -> None', make_target({'type': 'nope'}) is None)

    # --- redaction -------------------------------------------------------
    tgt = make_target({'type': 'splunk_hec', 'url': 'https://x', 'token': 'SEKRET'})
    ck('describe redacts token', tgt.describe()['config']['token'] == '***')

    # --- forwarder severity floor ---------------------------------------
    fwd = SiemForwarder([{'type': 'webhook', 'url': 'http://127.0.0.1:0'}],
                        min_severity='high')
    ck('forwarder built one target', fwd.enabled_count == 1)
    ck('floor drops low alerts', fwd._floor([low]) == [])
    ck('floor keeps critical', len(fwd._floor([alert])) == 1)
    ck('forward empty is no-op', fwd.forward([]) == [])
    ck('disabled target skipped',
       SiemForwarder([{'type': 'webhook', 'url': 'x', 'enabled': False}])
       .enabled_count == 0)

    # --- real UDP syslog over a loopback socket --------------------------
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(('127.0.0.1', 0))
    rx.settimeout(2.0)
    port = rx.getsockname()[1]
    st = SyslogTarget({'type': 'syslog', 'host': '127.0.0.1', 'port': port,
                       'protocol': 'udp', 'format': 'cef'})
    res = st.deliver([alert])
    ck('udp deliver reports sent', res['sent'] == 1 and res['error'] is None)
    try:
        got = rx.recvfrom(65535)[0].decode('utf-8', 'replace')
        ck('udp packet received', 'CEF:0' in got and 'router advert spoof' in got)
    except socket.timeout:
        ck('udp packet received', False)
    finally:
        rx.close()

    # --- dead collector never raises ------------------------------------
    dead = SyslogTarget({'type': 'syslog', 'host': '127.0.0.1', 'port': 9,
                         'protocol': 'tcp', 'timeout': 0.3})
    r2 = dead.deliver([alert])
    ck('dead tcp target fails soft', r2['sent'] == 0 and r2['error'] is not None)

    passed = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        if not ok:
            print('  [FAIL] %s' % name)
    print('siem_forwarder self-test: %d/%d %s'
          % (passed, len(checks), 'OK' if passed == len(checks) else 'FAILED'))
    return 0 if passed == len(checks) else 1


def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description='Ragnar SIEM/outbound forwarder')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--send-test', action='store_true',
                    help='send one synthetic alert to a target given by flags')
    ap.add_argument('--type', default='syslog')
    ap.add_argument('--host')
    ap.add_argument('--port', type=int, default=514)
    ap.add_argument('--url')
    ap.add_argument('--format', default='cef')
    ap.add_argument('--protocol', default='udp')
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.send_test:
        cfg = {'type': args.type, 'host': args.host, 'port': args.port,
               'url': args.url, 'format': args.format, 'protocol': args.protocol}
        tgt = make_target({k: v for k, v in cfg.items() if v is not None})
        if tgt is None:
            print('unknown target type: %s' % args.type)
            return 2
        demo = {'ts': time.time(), 'source': 'siem_test', 'module': 'siem_test',
                'severity': 'high', 'rank': 3, 'title': 'Ragnar SIEM test event',
                'codes': ['TEST-001'], 'src': '10.0.0.1', 'target': '10.0.0.2',
                'label': 'SIEM Test'}
        print(json.dumps(tgt.deliver([demo]), indent=2))
        return 0
    ap.print_help()
    return 0


if __name__ == '__main__':
    raise SystemExit(_main(sys.argv[1:]))
