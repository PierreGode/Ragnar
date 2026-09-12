#!/usr/bin/env python3
"""cyd_node.py — registry + auth for Ragnar CYD hybrid nodes.

A CYD hybrid node (ESP32-2432S028R "Cheap Yellow Display" running the
cyd_firmware/ragnar_cyd firmware) is a 2.4 GHz companion to a Ragnar Pi. It is
NOT a mesh peer — it reaches Ragnar over plain WiFi/HTTP, authenticated purely
by an operator-issued Bearer token (the same shape as mesh share tokens). This
module owns:

  * token issuance / constant-time validation (tokens live in
    shared_data.config['cyd_device_tokens']);
  * an in-memory registry of the nodes that have reported in, with the latest
    2.4 GHz sensor counts, a short history ring, and a log of operator actions
    requested from a node's touch screen.

Scope is deliberately narrow — the webapp exposes exactly three device-facing
routes (/api/cyd/status, /api/cyd/ingest, /api/cyd/action) behind the token
role, plus operator-only token management. Nothing here drives the radio or
runs a scan; the node does its own sensing and reports counts.
"""

import time
import secrets
import threading
from collections import deque

_LOCK = threading.RLock()

# node_name -> dict(ip, last_seen, counts{}, history deque, actions deque)
_NODES = {}

_MAX_HISTORY = 120      # sensor samples kept per node (~ a few minutes at duty-cycle)
_MAX_ACTIONS = 40       # requested-action log kept per node
_STALE_AFTER = 90       # seconds without a report -> node shown "stale"

# Actions a node's touch screen may request. Kept as an allowlist so a
# compromised or spoofed node can only ever ask for these, never arbitrary ops.
# The webapp dispatches these to the live subsystems (_cyd_dispatch_action) and
# records the outcome via record_action(status=...).
ALLOWED_ACTIONS = {
    'wifi_defense_scan': 'Run a WiFi Defense (WIDS) scan',
    'ble_scan':          'Start a Bluetooth scan',
    'watchtower_clear':  'Clear the Watchtower alert pane',
}


# ── Tokens ─────────────────────────────────────────────────────────────────────
def _tokens(config):
    toks = config.get('cyd_device_tokens')
    return toks if isinstance(toks, list) else []


def list_tokens(config):
    """Operator view of issued tokens — never returns the raw secret."""
    out = []
    for t in _tokens(config):
        if not isinstance(t, dict):
            continue
        raw = str(t.get('token', ''))
        out.append({
            'id': t.get('id'),
            'name': t.get('name'),
            'created': t.get('created'),
            'preview': (raw[:6] + '…' + raw[-4:]) if len(raw) > 12 else 'set',
        })
    return out


def generate_token(config, name):
    """Issue a new device token. Caller persists config afterwards.

    Returns (entry, raw_token). The raw token is shown to the operator ONCE
    (it must be pasted into the firmware's config.h); only a copy is stored.
    """
    raw = secrets.token_urlsafe(24)
    entry = {
        'id': secrets.token_hex(4),
        'name': (name or 'cyd-node').strip()[:32],
        'token': raw,
        'created': int(time.time()),
    }
    with _LOCK:
        toks = _tokens(config)
        toks.append(entry)
        config['cyd_device_tokens'] = toks
    public = {k: v for k, v in entry.items() if k != 'token'}
    return public, raw


def revoke_token(config, token_id):
    with _LOCK:
        toks = [t for t in _tokens(config)
                if not (isinstance(t, dict) and t.get('id') == token_id)]
        changed = len(toks) != len(_tokens(config))
        config['cyd_device_tokens'] = toks
    return changed


def valid_token(config, presented):
    """Constant-time match of a presented Bearer token. Returns the node name
    bound to the matching token (or None). The name is advisory — the node also
    self-identifies in its payload — but binding it lets the operator see which
    token a device is using."""
    import hmac
    if not presented:
        return None
    for t in _tokens(config):
        stored = t.get('token') if isinstance(t, dict) else None
        if stored and hmac.compare_digest(str(stored), str(presented)):
            return t.get('name') or 'cyd-node'
    return None


# ── Registry ────────────────────────────────────────────────────────────────────
def _node(name):
    n = _NODES.get(name)
    if n is None:
        n = {
            'name': name,
            'ip': None,
            'first_seen': time.time(),
            'last_seen': 0,
            'counts': {},
            'history': deque(maxlen=_MAX_HISTORY),
            'actions': deque(maxlen=_MAX_ACTIONS),
        }
        _NODES[name] = n
    return n


def _clean_counts(payload):
    """Coerce an ingest payload to non-negative ints, dropping unknown keys."""
    fields = ('beacons', 'probes', 'deauths', 'frames', 'bssids', 'ble_adv')
    out = {}
    for f in fields:
        try:
            out[f] = max(0, int(payload.get(f, 0)))
        except (TypeError, ValueError):
            out[f] = 0
    try:
        out['rssi'] = int(payload.get('rssi', 0))
    except (TypeError, ValueError):
        out['rssi'] = 0
    return out


def record_ingest(payload, remote_ip):
    """Store a sensor report from a node. Returns the node's public summary."""
    name = str(payload.get('node') or 'cyd-node')[:32]
    counts = _clean_counts(payload)
    now = time.time()
    with _LOCK:
        n = _node(name)
        n['ip'] = remote_ip
        n['last_seen'] = now
        n['counts'] = counts
        n['history'].append({'t': int(now), **counts})
    return summarize_node(name)


def record_action(node_name, action, remote_ip, status='requested'):
    """Log an operator action requested from a node's touch screen.

    `status` tracks the dispatch outcome ('requested', 'started', 'done',
    'error', 'no-monitor-iface', ...) so the operator can see what happened to a
    tap. A background job updates the same node's log with its final status."""
    name = str(node_name or 'cyd-node')[:32]
    with _LOCK:
        n = _node(name)
        if remote_ip:
            n['ip'] = remote_ip
        n['actions'].append({'t': int(time.time()), 'action': action, 'status': status})


def summarize_node(name):
    with _LOCK:
        n = _NODES.get(name)
        if not n:
            return None
        age = time.time() - n['last_seen'] if n['last_seen'] else None
        return {
            'name': n['name'],
            'ip': n['ip'],
            'last_seen': int(n['last_seen']) if n['last_seen'] else None,
            'age_sec': int(age) if age is not None else None,
            'stale': (age is None) or (age > _STALE_AFTER),
            'counts': dict(n['counts']),
            'recent_actions': list(n['actions'])[-5:],
        }


def list_nodes():
    with _LOCK:
        return [summarize_node(name) for name in list(_NODES.keys())]
