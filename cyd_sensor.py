#!/usr/bin/env python3
"""cyd_sensor.py — turn a CYD node's 2.4 GHz reports into WiFi-Defense alerts.

A CYD hybrid node reports what its own radio sees (deauth counts, AP sightings,
BLE sightings). This module folds those into Ragnar's EXISTING alert plumbing by
writing JSON-lines to /var/log/ragnar/cydsensor.jsonl — which Watchtower already
tails (any *.jsonl in /var/log/ragnar is picked up), so the detections show up in
the unified WiFi-Defense / Watchtower feed and the Pushover path with no parallel
system. It is a coarse 2.4 GHz vantage point, not a replacement for the Pi's
monitor-mode WIDS.

Records use the schema watchtower.normalize expects: `ts`, `severity`, `code`,
`summary`, `src`, `module`. An OK/clean record is simply not written.

Two detections in Stage 1:
  * deauth flood   — from the deauth count the node already sends (no firmware
                     change); ≥ threshold in a report window is an alert.
  * new/rogue AP   — from an optional `aps` list the firmware sends; a BSSID not
                     in the node's learned baseline is an alert. The first report
                     from a node seeds the baseline silently (no startup flood).
"""

import os
import json
import time
import threading

# Watchtower tails /var/log/ragnar/*.jsonl; the basename is the source name.
_PRIMARY_LOG = '/var/log/ragnar/cydsensor.jsonl'

_LOCK = threading.RLock()

# Per-node learned state.
#   node -> {'baseline': bool, 'aps': set(bssid), 'deauth_until': epoch}
_STATE = {}

# Defaults; overridable via the config getter passed to configure().
_DEFAULTS = {
    'deauth_flood_threshold': 15,    # deauth/disassoc frames in one report window
    'deauth_realert_sec': 60,        # don't re-alert the same flood more often
    'rogue_ap_enabled': False,       # OFF: a channel-hopping ESP32 sees every neighbour
                                     # AP as 'new' -> pure noise in Watchtower. Opt in via
                                     # config cyd_rogue_ap_enabled if you really want it.
}
_get_cfg = None


def configure(get_cfg):
    """Wire a config getter: get_cfg(key, default) -> value. Optional."""
    global _get_cfg
    _get_cfg = get_cfg


def _cfg(key):
    if _get_cfg:
        try:
            v = _get_cfg('cyd_' + key, _DEFAULTS[key])
            return v if v is not None else _DEFAULTS[key]
        except Exception:
            return _DEFAULTS[key]
    return _DEFAULTS[key]


def _log_path():
    """Prefer /var/log/ragnar (what Watchtower tails); fall back to a writable
    local path only so dev boxes don't crash — there it won't reach Watchtower."""
    d = os.path.dirname(_PRIMARY_LOG)
    if os.path.isdir(d) and os.access(d, os.W_OK):
        return _PRIMARY_LOG
    try:
        os.makedirs(d, exist_ok=True)
        return _PRIMARY_LOG
    except Exception:
        alt = os.path.join(os.getcwd(), 'data', 'logs')
        try:
            os.makedirs(alt, exist_ok=True)
        except Exception:
            pass
        return os.path.join(alt, 'cydsensor.jsonl')


def _write(record):
    line = json.dumps(record, separators=(',', ':'))
    path = _log_path()
    with _LOCK:
        with open(path, 'a') as fh:
            fh.write(line + '\n')


def _emit(node, severity, code, summary, src=None):
    _write({
        'ts': time.time(),
        'severity': severity,
        'code': code,
        'summary': summary,
        'src': src,
        'module': 'cyd:' + str(node),
    })


def _node(node):
    st = _STATE.get(node)
    if st is None:
        st = {'baseline': False, 'aps': set(), 'deauth_until': 0.0}
        _STATE[node] = st
    return st


def process_report(node, payload):
    """Fold one CYD report into WiFi-Defense alerts. Returns the list of alert
    codes emitted (for logging/tests). Safe to call from the ingest handlers."""
    node = str(node or 'cyd-node')[:32]
    emitted = []
    now = time.time()
    with _LOCK:
        st = _node(node)

        # ── deauth flood ─────────────────────────────────────────────────────
        try:
            deauths = int(payload.get('deauths', 0))
        except (TypeError, ValueError):
            deauths = 0
        thr = int(_cfg('deauth_flood_threshold'))
        if deauths >= thr and now >= st['deauth_until']:
            st['deauth_until'] = now + int(_cfg('deauth_realert_sec'))
            _emit(node, 'high', 'CYD-DEAUTH-FLOOD',
                  f'Deauth/disassoc flood: {deauths} frames in a report window '
                  f'(2.4 GHz sensor {node})')
            emitted.append('CYD-DEAUTH-FLOOD')

        # ── new / rogue AP ───────────────────────────────────────────────────
        aps = payload.get('aps')
        if isinstance(aps, list) and _cfg('rogue_ap_enabled'):
            seen_now = []
            for ap in aps:
                if not isinstance(ap, dict):
                    continue
                bssid = str(ap.get('bssid') or '').lower()
                if not bssid:
                    continue
                seen_now.append((bssid, ap))
            if not st['baseline']:
                # First report seeds the baseline silently.
                st['aps'] = {b for b, _ in seen_now}
                st['baseline'] = True
            else:
                for bssid, ap in seen_now:
                    if bssid in st['aps']:
                        continue
                    st['aps'].add(bssid)
                    ssid = str(ap.get('ssid') or '').strip() or '<hidden>'
                    ch = ap.get('ch')
                    rssi = ap.get('rssi')
                    detail = f"New AP '{ssid}'"
                    if ch not in (None, ''):
                        detail += f' ch{ch}'
                    if rssi not in (None, ''):
                        detail += f' {rssi}dBm'
                    detail += f' (2.4 GHz sensor {node})'
                    # New APs are routine (neighbours come and go) -> info, not medium.
                    _emit(node, 'info', 'CYD-NEW-AP', detail, src=bssid)
                    emitted.append('CYD-NEW-AP')
    return emitted


def reset_baseline(node=None):
    """Forget the learned AP baseline (all nodes, or one) so the next report
    re-seeds it — e.g. after moving the sensor."""
    with _LOCK:
        if node is None:
            _STATE.clear()
        else:
            _STATE.pop(str(node), None)
