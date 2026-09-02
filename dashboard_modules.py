"""Customizable e-paper dashboard — the module catalog behind Display-tab "edit
mode".

The main Ragnar screen is a set of slots: a grid of stat boxes (icon + number),
one block of rolling/insight text, and the character sprite. Out of the box each
slot shows a fixed thing. This catalog lets the web UI remap them:

  * STAT_MODULES  — what a numbered box can show. Each entry is
                    (label, icon_attr, sd_attr): a short label for the editor, the
                    SharedData image attribute used as the box icon, and the
                    SharedData counter read for the value.
  * TEXT_MODES    — what the text block shows (the rolling speech, a custom
                    string, the IP, the SSID, a clock, uptime, or the status).
  * CHARACTER_MODES — how the sprite is drawn (normal, hidden, or enlarged).

Everything is resolved against attributes that already live on SharedData and are
refreshed by the normal update loop, so the render path stays cheap and never
touches the database. When no dashboard_config is stored, callers fall back to
DEFAULT_STAT_ORDER / 'speech' / 'viking', which reproduces the built-in dashboard
exactly — so an un-customized unit behaves precisely as before.
"""

# id -> (label, icon_attr, sd_attr)
# label      : shown in the web editor (keep it short; boxes are tiny on e-paper)
# icon_attr  : SharedData attribute holding the 18px BMP drawn as the box icon
# sd_attr    : SharedData attribute read for the numeric value (via getattr, 0 default)
STAT_MODULES = {
    'targets':  ('Targets',   'target',    'targetnbr'),
    'ports':    ('Ports',     'port',      'portnbr'),
    'vulns':    ('Vulns',     'vuln',      'vulnnbr'),
    'creds':    ('Creds',     'cred',      'crednbr'),
    'zombies':  ('Zombies',   'zombie',    'zombiesnbr'),
    'data':     ('Data',      'data',      'datanbr'),
    'coins':    ('Coins',     'money',     'coinnbr'),
    'level':    ('Level',     'level',     'levelnbr'),
    'netkb':    ('Net KB',    'networkkb', 'networkkbnbr'),
    'attacks':  ('Attacks',   'attacks',   'attacksnbr'),
    # Derived / live counters (all already maintained on SharedData)
    'hosts':    ('Hosts',     'target',    'total_targetnbr'),
    'offline':  ('Offline',   'target',    'inactive_targetnbr'),
    'newhosts': ('New Hosts', 'target',    'new_targets'),
    'atrisk':   ('At Risk',   'vuln',      'vulnerable_host_count'),
}

# The 10 stat slots of the main dashboard, in canonical order. Slot i on every
# layout shows STAT config index i (or this default when unconfigured). This
# order matches the built-in portrait dashboard's boxes, so the default render is
# byte-for-byte what it was before the editor existed.
DEFAULT_STAT_ORDER = [
    'targets', 'ports', 'vulns', 'creds', 'coins',
    'level', 'zombies', 'netkb', 'data', 'attacks',
]

# Number of stat slots the editor exposes / the main dashboard renders.
STAT_SLOTS = 10

# Text block modes. 'value' in the stored config is only used by 'custom'.
TEXT_MODES = {
    'speech':  'Rolling speech (default)',
    'custom':  'Custom text',
    'ip':      'Device IP address',
    'ssid':    'Wi-Fi network (SSID)',
    'clock':   'Clock (HH:MM)',
    'uptime':  'System uptime',
    'status':  'Orchestrator status',
}
DEFAULT_TEXT_MODE = 'speech'

# Character sprite modes.
CHARACTER_MODES = {
    'viking': 'Character sprite (default)',
    'none':   'Hidden (more room for text)',
    'big':    'Enlarged character',
}
DEFAULT_CHARACTER = 'viking'


def normalize_config(cfg):
    """Coerce a stored/posted dashboard_config into a safe, complete dict.

    Returns None when the input is empty/None so callers can cleanly fall back to
    built-in behaviour. Unknown ids are dropped; the stats list is padded to
    STAT_SLOTS from DEFAULT_STAT_ORDER so a short/partial list never leaves a slot
    undefined.
    """
    if not cfg or not isinstance(cfg, dict):
        return None

    raw_stats = cfg.get('stats')
    stats = []
    if isinstance(raw_stats, list):
        for sid in raw_stats:
            stats.append(sid if sid in STAT_MODULES else None)
    # Pad / fill missing slots with the canonical default for that slot.
    while len(stats) < STAT_SLOTS:
        stats.append(None)
    stats = stats[:STAT_SLOTS]
    for i, sid in enumerate(stats):
        if sid is None:
            stats[i] = DEFAULT_STAT_ORDER[i % len(DEFAULT_STAT_ORDER)]

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
        'text': {'mode': mode, 'value': value},
        'character': character,
    }


def catalog():
    """JSON-serialisable description of every choosable module, for the web editor."""
    return {
        'stat_slots': STAT_SLOTS,
        'stat_modules': [
            {'id': mid, 'label': spec[0]} for mid, spec in STAT_MODULES.items()
        ],
        'default_stats': list(DEFAULT_STAT_ORDER),
        'text_modes': [{'id': k, 'label': v} for k, v in TEXT_MODES.items()],
        'default_text_mode': DEFAULT_TEXT_MODE,
        'character_modes': [{'id': k, 'label': v} for k, v in CHARACTER_MODES.items()],
        'default_character': DEFAULT_CHARACTER,
    }
