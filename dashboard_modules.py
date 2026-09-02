"""Customizable e-paper dashboard — the module catalog behind Display-tab "edit
mode".

The main Ragnar screen is a set of slots: a grid of stat boxes (icon + number),
one block of rolling/insight text, and the character sprite. Out of the box each
slot shows a fixed thing. This catalog lets the web UI remap them:

  * STAT_MODULES    — what a numbered box can show. Each value is resolved through
                      `resolve_stat_value` from one of three sources: a SharedData
                      counter ('attr'), a cached system metric ('sys'), or the
                      Watchtower feed ('wt').
  * TEXT_MODES      — what the text block shows: the rolling speech, a custom
                      string, a single live fact, or a multi-fact "bundle".
  * CHARACTER_MODES — how the sprite is drawn (normal, hidden, or enlarged).
  * STAT_STYLES     — draw each box with its icon (default) or as a compact text
                      label, which frees up room for the number.

Everything is resolved cheaply (system metrics + the Watchtower summary are
cached by the render loop), so the render path stays light. When no
dashboard_config is stored, callers fall back to the built-in defaults, so an
un-customized unit renders exactly as before — the feature is purely additive.
"""

# id -> {label, abbr, icon, src}
#   label : shown in the web editor
#   abbr  : short tag drawn in "label" box style (icons off) — keep to ~4 chars
#   icon  : SharedData attribute holding the 18px BMP drawn as the box icon
#   src   : (kind, key) resolved by resolve_stat_value():
#             ('attr', <SharedData attr>)  – live counter
#             ('sys',  <metric key>)       – cached system metric
#             ('wt',   <summary key>)      – Watchtower feed
STAT_MODULES = {
    # Gameplay / recon counters (SharedData)
    'targets':  {'label': 'Targets',   'abbr': 'TGT',  'icon': 'target',    'src': ('attr', 'targetnbr')},
    'ports':    {'label': 'Ports',     'abbr': 'PRT',  'icon': 'port',      'src': ('attr', 'portnbr')},
    'vulns':    {'label': 'Vulns',     'abbr': 'VUL',  'icon': 'vuln',      'src': ('attr', 'vulnnbr')},
    'creds':    {'label': 'Creds',     'abbr': 'CRD',  'icon': 'cred',      'src': ('attr', 'crednbr')},
    'zombies':  {'label': 'Zombies',   'abbr': 'ZMB',  'icon': 'zombie',    'src': ('attr', 'zombiesnbr')},
    'data':     {'label': 'Data',      'abbr': 'DAT',  'icon': 'data',      'src': ('attr', 'datanbr')},
    'coins':    {'label': 'Coins',     'abbr': 'CON',  'icon': 'money',     'src': ('attr', 'coinnbr')},
    'level':    {'label': 'Level',     'abbr': 'LVL',  'icon': 'level',     'src': ('attr', 'levelnbr')},
    'netkb':    {'label': 'Net KB',    'abbr': 'KB',   'icon': 'networkkb', 'src': ('attr', 'networkkbnbr')},
    'attacks':  {'label': 'Attacks',   'abbr': 'ATK',  'icon': 'attacks',   'src': ('attr', 'attacksnbr')},
    # Live network / host counters (SharedData)
    'hosts':    {'label': 'Hosts',     'abbr': 'HST',  'icon': 'target',    'src': ('attr', 'total_targetnbr')},
    'offline':  {'label': 'Offline',   'abbr': 'OFF',  'icon': 'target',    'src': ('attr', 'inactive_targetnbr')},
    'newhosts': {'label': 'New Hosts', 'abbr': 'NEW',  'icon': 'target',    'src': ('attr', 'new_targets')},
    'atrisk':   {'label': 'At Risk',   'abbr': 'RSK',  'icon': 'vuln',      'src': ('attr', 'vulnerable_host_count')},
    # System health (cached snapshot)
    'cputemp':  {'label': 'CPU °C',    'abbr': 'C°', 'icon': 'attack', 'src': ('sys', 'cpu_temp')},
    'cpuuse':   {'label': 'CPU %',     'abbr': 'CPU',  'icon': 'attack',    'src': ('sys', 'cpu_pct')},
    'ram':      {'label': 'RAM %',     'abbr': 'RAM',  'icon': 'data',      'src': ('sys', 'ram_pct')},
    'disk':     {'label': 'Disk %',    'abbr': 'DSK',  'icon': 'data',      'src': ('sys', 'disk_pct')},
    'uptimeh':  {'label': 'Uptime h',  'abbr': 'UP',   'icon': 'level',     'src': ('sys', 'uptime_h')},
    # Watchtower feed (cached summary)
    'wtalerts': {'label': 'WT Alerts', 'abbr': 'WT',   'icon': 'vuln',      'src': ('wt', 'total')},
    'wtcrit':   {'label': 'WT Critical','abbr': 'WT!', 'icon': 'attacks',   'src': ('wt', 'critical')},
}

# The 10 stat slots of the main dashboard, in canonical order. Slot i on every
# layout shows STAT config index i (or this default when unconfigured). This
# order matches the built-in portrait dashboard's boxes, so the default render is
# byte-for-byte what it was before the editor existed.
DEFAULT_STAT_ORDER = [
    'targets', 'ports', 'vulns', 'creds', 'coins',
    'level', 'zombies', 'netkb', 'data', 'attacks',
]

STAT_SLOTS = 10

# Box drawing style.
STAT_STYLES = {
    'icon':  'Icons (default)',
    'label': 'Text labels (more room, no icons)',
}
DEFAULT_STAT_STYLE = 'icon'

# Text block modes. 'value' in the stored config is only used by 'custom'.
# The 'bundle' group packs several live facts into one wrapped block.
TEXT_MODES = {
    'speech':     'Rolling speech (default)',
    'custom':     'Custom text',
    'ip':         'Device IP address',
    'ssid':       'Wi-Fi network (SSID)',
    'hostname':   'Hostname',
    'clock':      'Clock (HH:MM)',
    'uptime':     'System uptime',
    'status':     'Orchestrator status',
    'cputemp':    'CPU temperature',
    'watchtower': 'Watchtower — latest alert',
    'sys_bundle': 'Bundle · System (temp / CPU / RAM / uptime)',
    'net_bundle': 'Bundle · Network (IP / SSID / hosts)',
    'sec_bundle': 'Bundle · Security (vulns / at-risk / Watchtower)',
}
DEFAULT_TEXT_MODE = 'speech'

# Character sprite modes.
CHARACTER_MODES = {
    'viking': 'Character sprite (default)',
    'none':   'Hidden (more room for text)',
    'big':    'Enlarged character',
}
DEFAULT_CHARACTER = 'viking'


def resolve_stat_value(mid, sd, sysm=None, wt=None):
    """Numeric value for stat module `mid`. `sysm` is the cached system-metric
    dict, `wt` the cached Watchtower summary dict; both optional (missing → 0)."""
    spec = STAT_MODULES.get(mid)
    if not spec:
        return 0
    kind, key = spec['src']
    try:
        if kind == 'attr':
            return int(getattr(sd, key, 0) or 0)
        if kind == 'sys':
            return int(round(float((sysm or {}).get(key, 0) or 0)))
        if kind == 'wt':
            return int((wt or {}).get(key, 0) or 0)
    except Exception:
        return 0
    return 0


def normalize_config(cfg):
    """Coerce a stored/posted dashboard_config into a safe, complete dict, or
    None when empty so callers fall back to built-in behaviour. Unknown ids are
    dropped; the stats list is padded to STAT_SLOTS from DEFAULT_STAT_ORDER."""
    if not cfg or not isinstance(cfg, dict):
        return None

    raw_stats = cfg.get('stats')
    stats = []
    if isinstance(raw_stats, list):
        for sid in raw_stats:
            stats.append(sid if sid in STAT_MODULES else None)
    while len(stats) < STAT_SLOTS:
        stats.append(None)
    stats = stats[:STAT_SLOTS]
    for i, sid in enumerate(stats):
        if sid is None:
            stats[i] = DEFAULT_STAT_ORDER[i % len(DEFAULT_STAT_ORDER)]

    style = cfg.get('stat_style')
    if style not in STAT_STYLES:
        style = DEFAULT_STAT_STYLE

    text = cfg.get('text')
    if not isinstance(text, dict):
        text = {}
    mode = text.get('mode')
    if mode not in TEXT_MODES:
        mode = DEFAULT_TEXT_MODE
    value = str(text.get('value', ''))[:280]

    character = cfg.get('character')
    if character not in CHARACTER_MODES:
        character = DEFAULT_CHARACTER

    return {
        'stats': stats,
        'stat_style': style,
        'text': {'mode': mode, 'value': value},
        'character': character,
    }


def catalog():
    """JSON-serialisable description of every choosable module, for the web editor."""
    return {
        'stat_slots': STAT_SLOTS,
        'stat_modules': [
            {'id': mid, 'label': spec['label'], 'abbr': spec['abbr']}
            for mid, spec in STAT_MODULES.items()
        ],
        'default_stats': list(DEFAULT_STAT_ORDER),
        'stat_styles': [{'id': k, 'label': v} for k, v in STAT_STYLES.items()],
        'default_stat_style': DEFAULT_STAT_STYLE,
        'text_modes': [{'id': k, 'label': v} for k, v in TEXT_MODES.items()],
        'default_text_mode': DEFAULT_TEXT_MODE,
        'character_modes': [{'id': k, 'label': v} for k, v in CHARACTER_MODES.items()],
        'default_character': DEFAULT_CHARACTER,
    }
