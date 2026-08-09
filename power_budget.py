"""Power assessment for the dashboard's power-warning badge.

Two jobs, kept honest and separate:

1. **The warning itself** comes only from the SoC's throttle register
   (``vcgencmd get_throttled``). That register is the *measured* truth: the
   firmware sets the under-voltage bit when the 5 V rail actually sags below
   spec, and the throttling/ARM-capped bits when it has actually reduced the
   clock in response. We never raise a warning from a guess — the badge lights
   because the hardware said so.

2. **The "what's eating the power" breakdown** is an *estimate*. There is no
   per-port current meter on a Pi (and on a Zero/Pi 3 the whole HAT is one USB
   hub, so the board only ever sees one aggregate draw). USB ``bMaxPower``
   descriptors are close to useless — a LAN9514 declares 2 mA, an Alfa declares
   500 mA while it can pull ~900 mA on transmit. So we recognise the devices
   that are actually plugged in and attribute a realistic 5 V current to each,
   add the board's own draw, and show the sum against what the supply can give.
   Everything on that side is labelled as an estimate, because it is one.

The module never raises; off-Pi (no ``vcgencmd``) it degrades to "unsupported".
"""

import re
import time

try:
    import wardrive_diagnostics as _wd
except Exception:          # pragma: no cover - module should always import
    _wd = None


# --------------------------------------------------------------------------
# Realistic 5 V current for the peripherals Ragnar actually uses.
#
# These are measured/datasheet figures for the real hardware, NOT the USB
# descriptor's bMaxPower (which lies). typ = steady draw, peak = transmit /
# burst. Matched by USB vendor id first, refined by the product string.
# --------------------------------------------------------------------------
_ETH_HINT = re.compile(r'ethernet|rtl8153|rtl8152|ax88|lan95|rndis|network',
                       re.I)
_WIFI_HINT = re.compile(r'802\.11|wlan|wi-?fi|awus|alfa|rtl88|mt7|rt2|rt3|8814'
                        r'|8812|8188|8821|network adapter', re.I)

# vendor_id -> (role, typ_ma, peak_ma). A callable disambiguator may override.
_KNOWN_VENDORS = {
    '1546': ('GPS receiver', 90, 120),                 # u-blox
    '303a': ('ESP32 companion', 200, 350),             # Espressif
    '0e8d': ('USB Wi-Fi adapter (Alfa-class)', 550, 900),   # MediaTek
    '148f': ('USB Wi-Fi adapter (Alfa-class)', 500, 800),   # Ralink
    '0cf3': ('USB Wi-Fi adapter (Alfa-class)', 500, 800),   # Atheros/Qualcomm
    '13b1': ('USB Wi-Fi adapter', 450, 700),           # Linksys
    '0b95': ('USB Ethernet', 200, 300),                # ASIX
    '0424': ('USB Ethernet/hub (onboard on Pi 3B)', 150, 250),  # Microchip/SMSC
}

# Peak draw for the named reference configs, so the two "max power" profiles
# the operator asked about are computed from the same figures as the live view.
_ALFA_PEAK = 900
_GPS_PEAK = 120
_ESP_PEAK = 350
_ETH_PEAK = 300


def _classify(dev):
    """Attribute a realistic (role, typ_ma, peak_ma) to one USB device.

    Order matters: the product string wins over the vendor default because a
    few vendors (Realtek 0bda especially) ship both Wi-Fi radios and Ethernet
    dongles under one id.
    """
    vid = (dev.get('vendor_id') or '').lower()
    product = ' '.join(str(dev.get(k) or '') for k in ('product', 'manufacturer'))
    cls = dev.get('class')

    # Product-string overrides first — most specific signal we have.
    if _ETH_HINT.search(product):
        return ('USB Ethernet', 200, 300)
    if _WIFI_HINT.search(product):
        return ('USB Wi-Fi adapter (Alfa-class)', 550, 900)

    # Realtek 0bda with no hint: assume the common case (a Wi-Fi dongle), but
    # only mildly — a bare hub reports class 09 and is caught below.
    if vid == '0bda' and cls != '09':
        return ('USB Wi-Fi/Ethernet adapter', 300, 600)

    if vid in _KNOWN_VENDORS:
        return _KNOWN_VENDORS[vid]

    if cls == '09':
        return ('USB hub', 50, 100)

    # Unknown device: fall back to its declared draw so it still counts for
    # something, but flag it as unmatched so the UI can say "declared".
    declared = dev.get('max_power_ma') or 0
    return ('USB device', declared, declared)


# Board base draw (the Pi itself, no peripherals) and supply context. load_ma
# is a busy-CPU figure; psu_ma is the official recommended supply. The real
# field limiter on a Zero/Pi 3 is usually the micro-USB connector and cable
# voltage drop, not the PSU's nameplate rating — hence supply_note.
_BOARDS = (
    ('Zero 2', {'name': 'Pi Zero 2 W', 'base_ma': 350, 'load_ma': 700,
                'psu_ma': 2500,
                'supply_note': 'Single micro-USB port; thin/long cables drop '
                               'voltage under load, so a nominal 2.5 A supply '
                               'can still under-volt with an Alfa attached.'}),
    ('Pi 3', {'name': 'Pi 3 Model B', 'base_ma': 400, 'load_ma': 900,
              'psu_ma': 2500,
              'supply_note': 'Micro-USB input; needs a genuine 2.5 A supply. '
                             'Phone chargers that sag under load are the usual '
                             'cause of under-voltage here.'}),
    ('Pi 4', {'name': 'Pi 4', 'base_ma': 500, 'load_ma': 1100, 'psu_ma': 3000,
              'supply_note': 'USB-C input; use a 3 A supply.'}),
    ('Pi 5', {'name': 'Pi 5', 'base_ma': 600, 'load_ma': 1200, 'psu_ma': 5000,
              'supply_note': 'USB-C PD. USB peripheral current is capped to '
                             '600 mA total unless a 5 A PD supply is detected '
                             'or usb_max_current_enable=1 is set.'}),
)


def _board_profile(model):
    for needle, prof in _BOARDS:
        if needle in (model or ''):
            return prof
    return {'name': model or 'Unknown board', 'base_ma': 400, 'load_ma': 900,
            'psu_ma': 2500, 'supply_note': None}


def _severity(thr):
    """Map the throttle register to ok/warning/critical.

    Present-tense bits (under-voltage now, throttled now) are critical: the
    board is being starved *right now*. The sticky "since boot" bits are a
    warning: it happened, the headroom is gone, but it is not happening this
    instant.
    """
    if not thr:
        return 'unknown'
    now = thr.get('now') or []
    occurred = thr.get('occurred') or []
    if any('under-voltage' in x or 'throttled' in x for x in now):
        return 'critical'
    if any('under-voltage' in x or 'throttling' in x for x in occurred):
        return 'warning'
    if now or occurred:            # temperature-only flags
        return 'warning'
    return 'ok'


def _effects(thr, sev):
    """Plain-language 'what this does to Ragnar' — the honest mechanism, so the
    operator knows a warning is real and what it costs, not just that a light
    is on."""
    if not thr:
        return []
    now = set(thr.get('now') or [])
    occurred = set(thr.get('occurred') or [])
    out = []
    if 'under-voltage' in now:
        out.append('Under-voltage right now: the 5 V rail is below spec. The '
                   'firmware caps the ARM clock to cut current draw, so the CPU '
                   'is running slower until the supply recovers.')
        out.append('A deeper dip browns out and resets the whole board. The OS '
                   'never gets to write a log line, so it looks like an '
                   'unexplained crash — this is that cause, made visible.')
    elif 'under-voltage' in occurred:
        out.append('Under-voltage has occurred since boot: the supply had no '
                   'headroom at some point. Expect resets under load — adding a '
                   'USB Wi-Fi adapter (an Alfa pulls ~0.5–0.9 A) can push it '
                   'over the edge.')
    if 'ARM frequency capped' in now and 'under-voltage' not in now:
        out.append('The ARM clock is capped right now (power or thermal), so '
                   'scans and analysis run slower than normal.')
    if 'currently throttled' in now and 'under-voltage' not in now:
        out.append('The SoC is actively throttling right now.')
    if ('soft temperature limit' in now or 'soft temperature limit' in occurred):
        out.append('A soft temperature limit was hit — that is heat, not power; '
                   'improve airflow rather than the PSU.')
    if sev == 'ok':
        out.append('Supply is healthy: no under-voltage or throttling recorded '
                   'since boot.')
    return out


def _cache():
    # Module-level single-slot cache; assess() is polled from /api/status.
    if not hasattr(_cache, 'slot'):
        _cache.slot = {'ts': 0.0, 'data': None}
    return _cache.slot


def assess(ttl=15.0, force=False):
    """Full power assessment. Cached ``ttl`` seconds because it shells out to
    vcgencmd and walks sysfs; the dashboard polls it via /api/status."""
    slot = _cache()
    now = time.time()
    if not force and slot['data'] is not None and now - slot['ts'] < ttl:
        return slot['data']

    data = _build()
    slot['data'] = data
    slot['ts'] = now
    return data


def _build():
    if _wd is None:
        return {'supported': False, 'level': 'unknown',
                'summary': {'level': 'unknown', 'undervoltage': False,
                            'throttled': False, 'headline': None}}
    try:
        raw = _wd.power()
    except Exception as e:            # never let this take down /api/status
        return {'supported': False, 'level': 'unknown', 'error': str(e),
                'summary': {'level': 'unknown', 'undervoltage': False,
                            'throttled': False, 'headline': None}}

    thr = raw.get('throttled')
    supported = thr is not None
    sev = _severity(thr)
    model = raw.get('model')
    board = _board_profile(model)

    # Attribute a realistic draw to each enumerated USB device.
    devices = []
    peripherals_typ = peripherals_peak = 0
    for d in (raw.get('usb_devices') or []):
        role, typ_ma, peak_ma = _classify(d)
        matched = role not in ('USB device',)
        devices.append({
            'label': d.get('product') or d.get('manufacturer')
                     or d.get('usb_id') or d.get('id'),
            'role': role,
            'usb_id': d.get('usb_id'),
            'interfaces': d.get('interfaces') or [],
            'declared_ma': d.get('max_power_ma'),
            'est_typ_ma': typ_ma,
            'est_peak_ma': peak_ma,
            'matched': matched,
        })
        peripherals_typ += typ_ma or 0
        peripherals_peak += peak_ma or 0

    est_typ = board['base_ma'] + peripherals_typ
    est_peak = board['load_ma'] + peripherals_peak
    headroom = board['psu_ma'] - est_peak
    tight = headroom < board['psu_ma'] * 0.15   # <15% margin at peak

    # Reference maxima for the two named field configs, on this board.
    profiles = {
        'stationary': {
            'label': 'Stationary / recon',
            'devices': ['Alfa', 'USB Ethernet'],
            'peak_ma': board['load_ma'] + _ALFA_PEAK + _ETH_PEAK,
        },
        'roaming': {
            'label': 'Roaming / wardrive',
            'devices': ['Alfa', 'GPS', 'ESP32'],
            'peak_ma': board['load_ma'] + _ALFA_PEAK + _GPS_PEAK + _ESP_PEAK,
        },
    }
    for p in profiles.values():
        p['fits'] = p['peak_ma'] <= board['psu_ma']

    headline = None
    if sev == 'critical':
        headline = ('Under-voltage now' if thr and 'under-voltage' in
                    (thr.get('now') or []) else 'Throttled now')
    elif sev == 'warning':
        occ = thr.get('occurred') if thr else []
        if 'under-voltage' in (occ or []):
            headline = 'Under-voltage since boot'
        elif 'throttling' in (occ or []):
            headline = 'Throttled since boot'
        else:
            headline = 'Power warning'

    return {
        'supported': supported,
        'level': sev,
        'model': model,
        'throttle': thr,
        'temp_c': raw.get('temp_c'),
        'core_volts': raw.get('core_volts'),
        'pmic': raw.get('pmic'),
        'usb_max_current_enabled': raw.get('usb_max_current_enabled'),
        'board': board,
        'devices': devices,
        'estimate': {
            'base_ma': board['base_ma'],
            'load_ma': board['load_ma'],
            'peripherals_typ_ma': peripherals_typ,
            'peripherals_peak_ma': peripherals_peak,
            'total_typ_ma': est_typ,
            'total_peak_ma': est_peak,
            'psu_ma': board['psu_ma'],
            'headroom_ma': headroom,
            'tight': tight,
        },
        'profiles': profiles,
        'effects': _effects(thr, sev),
        # Compact summary the dashboard badge reads from /api/status — cheap to
        # embed, so the badge needs no separate poll to know whether to show.
        'summary': {
            'level': sev,
            'supported': supported,
            'undervoltage': bool(thr and (
                'under-voltage' in (thr.get('now') or [])
                or 'under-voltage' in (thr.get('occurred') or []))),
            'undervoltage_now': bool(thr and 'under-voltage' in (thr.get('now') or [])),
            'throttled_now': bool(thr and (
                'currently throttled' in (thr.get('now') or [])
                or 'ARM frequency capped' in (thr.get('now') or []))),
            'headline': headline,
        },
    }


def summary(ttl=15.0):
    """Just the compact badge summary (for /api/status)."""
    return assess(ttl=ttl).get('summary') or {
        'level': 'unknown', 'undervoltage': False, 'throttled': False,
        'headline': None}
