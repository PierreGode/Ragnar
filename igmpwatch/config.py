"""YAML config loader with defaults. pyyaml is optional — absent, built-in
defaults are used and a note is returned."""

from . import detectors as _det
from . import dataplane as _dp
from . import snmp as _snmp

DEFAULTS = {
    'iface': None,
    'mode': 'learn',
    'dedup_window': 60.0,
    'db': '/var/lib/igmpwatch/igmpwatch.db',
    'detectors': dict(_det.DEFAULTS),
    'dataplane': dict(_dp.DEFAULTS),
    'snmp': dict(_snmp.DEFAULTS),
}


def _deep_merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path=None):
    """Return (config_dict, note). note is None on success or an advisory string."""
    cfg = _deep_merge({}, DEFAULTS)
    note = None
    if path:
        try:
            import yaml
        except ImportError:
            return cfg, 'pyyaml not installed; using defaults (pip install pyyaml)'
        try:
            with open(path) as f:
                user = yaml.safe_load(f) or {}
            cfg = _deep_merge(cfg, user)
        except OSError as e:
            note = 'config unreadable ({}); using defaults'.format(e)
    # Mode is authoritative at the top level; mirror into the detector config.
    cfg['detectors']['mode'] = cfg.get('mode', 'learn')
    return cfg, note
