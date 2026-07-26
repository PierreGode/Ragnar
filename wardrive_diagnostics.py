# wardrive_diagnostics.py — deep diagnostics for the wardriving panel.
#
# Backs GET /api/wardriving/diagnostics, which the Diagnostics panel fetches
# only while it is expanded (the 3 s status poll stays cheap). Everything here
# is best-effort and read-only: a missing tool or sysfs node degrades one field,
# never the payload.
#
# It answers three field questions the plain status object could not:
#
#   "why is only wlan0 scanning?"  -> radios(): every wireless netdev, whether
#       it is in the live scan set, and when it is not, WHY (rfkill-blocked,
#       held as the uplink/management radio, lent to the phone AP, a monitor
#       child, or simply never detected).
#   "what is each device drawing?" -> power(): per-USB-device bMaxPower, which
#       netdev each adapter backs, and the summed budget.
#   "is the Pi browning out?"      -> power(): throttled/undervoltage flags,
#       core voltage, temperature, and Pi 5 PMIC rails when present.
#
# bMaxPower is the *declared* draw from the USB descriptor, not a measurement —
# no Pi can meter per-port current. It is still the number that matters, because
# it is what the host budgets against.

import glob
import logging
import os
import re
import subprocess
import time

logger = logging.getLogger(__name__)

# Whole-payload cache. The panel polls while open; sysfs walks and vcgencmd
# shell-outs are cheap but not free.
_CACHE = {'ts': 0.0, 'data': None}
_CACHE_TTL = 5.0

# A live receiver emits NMEA every second or so, and the scan loop turns over
# every few seconds. These thresholds are deliberately generous — they should
# only fire on a genuine stall, never on a slow cycle.
GPS_STALE_S = 30
SCAN_STALE_S = 60

# vcgencmd get_throttled bit meanings. Low nibble = happening now, bits 16-19 =
# has happened since boot. The "occurred" bits are the ones that catch a
# brownout that already passed — exactly the case where a GPS cold start dies
# but everything looks healthy by the time you go looking.
_THROTTLE_BITS = (
    (0,  'now',      'under-voltage'),
    (1,  'now',      'ARM frequency capped'),
    (2,  'now',      'currently throttled'),
    (3,  'now',      'soft temperature limit'),
    (16, 'occurred', 'under-voltage'),
    (17, 'occurred', 'ARM frequency capped'),
    (18, 'occurred', 'throttling'),
    (19, 'occurred', 'soft temperature limit'),
)


def _run(cmd, timeout=4):
    """Run a command, returning stdout or None. Never raises."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def _int(val):
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------
# USB / power
# --------------------------------------------------------------------------

def _usb_devices():
    """Every USB device with its declared power draw, newest sysfs first.

    Skips root hubs (they are the host controller, not a peripheral) but keeps
    external hubs, since a bus-powered hub's own draw counts against the budget.
    """
    out = []
    for path in sorted(glob.glob('/sys/bus/usb/devices/*')):
        base = os.path.basename(path)
        # usbN = root hub; 'N-M:X.Y' = an interface, not a device.
        if base.startswith('usb') or ':' in base:
            continue
        max_power = _read(f'{path}/bMaxPower')          # e.g. "500mA"
        ma = _int((max_power or '').replace('mA', '').strip())
        vid = _read(f'{path}/idVendor')
        pid = _read(f'{path}/idProduct')
        dev = {
            'id': base,
            'vendor_id': vid,
            'product_id': pid,
            'usb_id': f'{vid}:{pid}' if vid and pid else None,
            'manufacturer': _read(f'{path}/manufacturer'),
            'product': _read(f'{path}/product'),
            'serial': None,      # deliberately not reported (identifying)
            'max_power_ma': ma,
            'speed_mbps': _int(_read(f'{path}/speed')),
            'bus': _int(_read(f'{path}/busnum')),
            'device': _int(_read(f'{path}/devnum')),
            'class': _read(f'{path}/bDeviceClass'),
            'interfaces': [],    # netdev / tty names this device backs
        }
        # Which kernel interfaces does this USB device provide? That is what
        # turns "500mA device" into "wlan1 draws 500mA".
        #
        # Scope this to the device's OWN interface directories ("<dev>:<cfg>.<n>").
        # In sysfs a hub's downstream devices are nested underneath it, so a
        # loose "{path}/*/*/tty/*" walks into them and credits the hub with its
        # children's ports — a bus-powered hub showed up owning the GPS's
        # ttyACM0. Child devices are enumerated separately in their own right.
        for iface_dir in glob.glob(f'{path}/{base}:*'):
            for node in (glob.glob(f'{iface_dir}/net/*')
                         + glob.glob(f'{iface_dir}/tty/*')
                         # usb-serial bridges nest one deeper: :1.0/ttyUSB0/tty/ttyUSB0
                         + glob.glob(f'{iface_dir}/*/tty/*')):
                dev['interfaces'].append(os.path.basename(node))
        dev['interfaces'] = sorted(set(dev['interfaces']))
        out.append(dev)
    return out


def _throttled():
    """Decode vcgencmd get_throttled into readable now/occurred flag lists."""
    raw = _run(['vcgencmd', 'get_throttled'])
    if not raw:
        return None
    m = re.search(r'0x([0-9a-fA-F]+)', raw)
    if not m:
        return None
    val = int(m.group(1), 16)
    now, occurred = [], []
    for bit, when, label in _THROTTLE_BITS:
        if val & (1 << bit):
            (now if when == 'now' else occurred).append(label)
    return {
        'raw': f'0x{val:X}',
        'now': now,
        'occurred': occurred,
        'healthy': val == 0,
    }


def _pmic_rails():
    """Pi 5 PMIC per-rail volts/amps. Absent on earlier Pis (incl. Zero 2 W)."""
    raw = _run(['vcgencmd', 'pmic_read_adc'])
    if not raw:
        return None
    # Lines look like "  VDD_CORE_A current(7)=2.85760000A" and
    # "  VDD_CORE_V volt(15)=0.83875000V" — the same rail appears twice with an
    # _A / _V suffix, so strip that to pair current with voltage.
    volts, amps = {}, {}
    for m in re.finditer(r'(\S+)\s+(current|volt)\(\d+\)=([\d.]+)([AV])', raw):
        name, _kind, value, unit = m.groups()
        rail = re.sub(r'_[AV]$', '', name)
        try:
            fval = float(value)
        except ValueError:
            continue
        (amps if unit == 'A' else volts)[rail] = fval
    rails = []
    for rail in sorted(set(volts) | set(amps)):
        v, a = volts.get(rail), amps.get(rail)
        rails.append({
            'rail': rail, 'volts': v, 'amps': a,
            'watts': round(v * a, 3) if (v is not None and a is not None) else None,
        })
    total = sum(r['watts'] for r in rails if r['watts'] is not None)
    return {'rails': rails, 'total_watts': round(total, 2) if rails else None}


def power():
    """USB power budget + Pi supply health."""
    devices = _usb_devices()
    known = [d['max_power_ma'] for d in devices if d['max_power_ma']]
    info = {
        'usb_devices': devices,
        'usb_count': len(devices),
        'usb_declared_ma': sum(known) if known else 0,
        'throttled': _throttled(),
        'pmic': _pmic_rails(),
        'core_volts': None,
        'temp_c': None,
        'model': _read('/proc/device-tree/model'),
        'usb_max_current_enabled': None,
    }
    if info['model']:
        info['model'] = info['model'].replace('\x00', '').strip()

    volts = _run(['vcgencmd', 'measure_volts'])
    if volts:
        m = re.search(r'([\d.]+)V', volts)
        if m:
            info['core_volts'] = float(m.group(1))
    temp = _run(['vcgencmd', 'measure_temp'])
    if temp:
        m = re.search(r'([\d.]+)', temp)
        if m:
            info['temp_c'] = float(m.group(1))

    # Pi 5 caps *total* USB peripheral current at 600mA unless it detects a 5A
    # PD supply or this flag is set. Only meaningful on Pi 5 — reporting "not
    # set" on a Zero 2 W or Pi 4 reads as a problem when the setting does not
    # apply to that board at all, so leave it None (the UI then omits the row).
    if (info['model'] or '').startswith('Raspberry Pi 5'):
        for cfg in ('/boot/firmware/config.txt', '/boot/config.txt'):
            txt = _read(cfg)
            if txt is None:
                continue
            enabled = False
            for line in txt.splitlines():
                line = line.strip()
                if line.startswith('usb_max_current_enable'):
                    enabled = line.split('=')[-1].strip() in ('1', 'true')
            info['usb_max_current_enabled'] = enabled
            break
    return info


# --------------------------------------------------------------------------
# Radios
# --------------------------------------------------------------------------

def _all_wireless_ifaces():
    """Every wireless netdev present, from sysfs (the authority on existence)."""
    found = set()
    try:
        for name in os.listdir('/sys/class/net'):
            if os.path.isdir(f'/sys/class/net/{name}/wireless') \
                    or os.path.isdir(f'/sys/class/net/{name}/phy80211'):
                found.add(name)
    except OSError:
        pass
    return sorted(found)


def _iface_mode(iface):
    """managed / monitor / AP, via iw."""
    out = _run(['iw', 'dev', iface, 'info'])
    if not out:
        return None
    m = re.search(r'^\s*type\s+(\S+)', out, re.M)
    return m.group(1) if m else None


def _usb_owner(iface, usb_devices):
    """The USB device backing this interface, if it is a dongle."""
    for d in usb_devices:
        if iface in d['interfaces']:
            return d
    return None


def radios(engine, usb_devices=None):
    """Every wireless radio and whether wardriving is scanning it — with the
    reason when it is not. This is the answer to "why is only wlan0 listed?".
    """
    usb_devices = usb_devices if usb_devices is not None else _usb_devices()
    scanning = set(getattr(engine, 'interfaces', None) or [])

    try:
        protected = engine._management_ifaces()
    except Exception as e:
        logger.debug(f"management iface lookup failed: {e}")
        protected = set()

    lent = getattr(engine, '_ap_lent_iface', None)

    out = []
    for name in _all_wireless_ifaces():
        blocked = False
        try:
            blocked = engine._iface_rfkill_blocked(name)
        except Exception:
            pass
        mode = _iface_mode(name)
        operstate = _read(f'/sys/class/net/{name}/operstate')
        usb = _usb_owner(name, usb_devices)

        in_scan = name in scanning
        reason = None
        if not in_scan:
            # Ordered by how decisive each cause is.
            if name.endswith('mon') or name.startswith('mon'):
                reason = 'monitor child interface (skipped by design)'
            elif blocked:
                reason = 'rfkill-blocked — run: sudo rfkill unblock all'
            elif name in protected:
                reason = 'held as the uplink / management radio'
            elif mode == 'AP':
                reason = 'in AP mode (lent to the phone-access AP)'
            elif lent == name:
                reason = 'lent to the phone-access AP'
            else:
                reason = 'not claimed — present but not in the scan set'

        out.append({
            'name': name,
            'scanning': in_scan,
            'excluded_reason': reason,
            'rfkill_blocked': blocked,
            'mode': mode,
            'operstate': operstate,
            'is_management': name in protected,
            'driver': _driver_of(name),
            'usb': {
                'product': usb['product'],
                'manufacturer': usb['manufacturer'],
                'usb_id': usb['usb_id'],
                'max_power_ma': usb['max_power_ma'],
            } if usb else None,
        })
    return out


def _driver_of(iface):
    try:
        return os.path.basename(os.path.realpath(f'/sys/class/net/{iface}/device/driver'))
    except OSError:
        return None


# --------------------------------------------------------------------------
# GPS
# --------------------------------------------------------------------------

def gps_extra(engine):
    """GPS detail the summary card has no room for.

    Notably the per-constellation GSV breakdown: 7 satellites in view split
    across GPS/GLONASS/Galileo tells a very different story from 7 on one
    constellation, and the per-talker SNR is what shows an antenna being
    desensed rather than simply blocked.
    """
    gps = getattr(engine, '_gps', None)
    if gps is None:
        return {'present': False}

    info = {'present': True}
    try:
        info['status'] = gps.get_status()
    except Exception as e:
        info['status_error'] = str(e)

    # Per-constellation view, straight off the GSV bookkeeping.
    talkers = {
        'GP': 'GPS', 'GL': 'GLONASS', 'GA': 'Galileo', 'GB': 'BeiDou',
        'BD': 'BeiDou', 'GQ': 'QZSS', 'GI': 'NavIC', 'GN': 'combined',
    }
    try:
        now = time.time()
        rows = []
        for talker, val in (getattr(gps, '_gsv_by_talker', None) or {}).items():
            in_view, snr, ts = val
            rows.append({
                'talker': talker,
                'constellation': talkers.get(talker, talker),
                'in_view': in_view,
                'snr_max': snr,
                'age_s': round(now - ts, 1) if ts else None,
            })
        info['constellations'] = sorted(rows, key=lambda r: r['constellation'])
    except Exception as e:
        logger.debug(f"GSV breakdown failed: {e}")
        info['constellations'] = []

    # Per-satellite sky view (azimuth/elevation/SNR) for a polar plot — the
    # graphical half of the same GSV data u-center draws. Only satellites with
    # both azimuth and elevation are plottable.
    try:
        now = time.time()
        sky = []
        for talker, val in (getattr(gps, '_sats_by_talker', None) or {}).items():
            sats, ts = val
            if ts and now - ts > 30:
                continue
            cons = talkers.get(talker, talker)
            for s in sats:
                if s.get('az') is None or s.get('elev') is None:
                    continue
                sky.append({
                    'constellation': cons,
                    'talker': talker,
                    'prn': s.get('prn'),
                    'az': s.get('az'),
                    'elev': s.get('elev'),
                    'snr': s.get('snr'),
                })
        info['sky'] = sky
    except Exception as e:
        logger.debug(f"sky view failed: {e}")
        info['sky'] = []

    # Serial/gpsd plumbing worth seeing when nothing is arriving at all.
    info['port'] = getattr(gps, 'port', None)
    info['use_gpsd'] = bool(getattr(gps, '_use_gpsd', False))
    info['baudrate'] = getattr(gps, 'baudrate', None)
    info['ttff_s'] = getattr(gps, 'ttff_seconds', None)
    return info


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

def errors(engine, shared_data=None):
    """Anything currently complaining, gathered into one list."""
    out = []

    def add(source, message, severity='error'):
        if message:
            out.append({'source': source, 'message': str(message),
                        'severity': severity})

    add('engine', getattr(engine, 'error', None))
    gps = getattr(engine, '_gps', None)
    if gps is not None:
        add('gps', getattr(gps, 'error', None))
    if not (getattr(engine, 'interfaces', None) or []):
        add('radios', 'No WiFi interface is scanning — see the Radios group '
                      'for why each radio was excluded.')

    # --- Staleness -------------------------------------------------------
    # A feed that has simply STOPPED looks identical to a weak one in the
    # summary numbers: the last-known satellite count and SNR just sit there.
    # Call it out explicitly, and when both feeds die together, say so — that
    # pattern points at the shared USB bus (a hub dropping, a bus reset) rather
    # than at reception or at either device individually.
    now = time.time()
    gps_stale = scan_stale = None

    if gps is not None and getattr(gps, 'connected', False):
        last = getattr(gps, 'last_sentence', 0) or 0
        if last and now - last > GPS_STALE_S:
            gps_stale = now - last
            add('gps', f'No NMEA sentence for {int(gps_stale)}s although the '
                       f'receiver still reports connected — the port is open '
                       f'but nothing is arriving.')

    # Tracking satellites but still no fix after a long search. The receiver
    # SEES satellites (carrier lock) but can't decode a position, which means
    # the signal is too weak to demodulate the 50 bps nav message — an antenna
    # placement / sky-view problem (a GPS puck sat right next to the Pi or a USB
    # hub gets desensed), or a cold start on a u-blox with no battery-backed
    # almanac. It is NOT a Ragnar fault, so say so explicitly — otherwise a live
    # feed with a healthy supply and N satellites "in view" looks like a bug.
    if gps is not None:
        try:
            s = gps.get_status()
            searching = s.get('searching_seconds') or 0
            in_view = s.get('satellites_in_view') or 0
            if not s.get('has_fix') and searching > 180 and in_view >= 4:
                add('gps',
                    f'Tracking {in_view} satellites for {int(searching)}s but no '
                    f'fix: the receiver sees satellites but the signal is too weak '
                    f'to decode a position. This is antenna placement / sky view '
                    f'(a GPS puck next to the Pi or a USB hub gets desensed) or a '
                    f'cold start on a receiver with no battery-backed almanac — '
                    f'not a Ragnar fault. Move the antenna to open sky, away from '
                    f'the Pi and USB.', 'warn')
        except Exception as e:
            logger.debug(f"no-fix hint failed: {e}")

    if getattr(engine, '_running', False):
        last = getattr(engine, 'last_scan_time', 0) or 0
        if last and now - last > SCAN_STALE_S:
            scan_stale = now - last
            add('engine', f'No scan completed for {int(scan_stale)}s although '
                          f'the engine reports running — the scan loop is '
                          f'stalled or its radios stopped responding.')

    if gps_stale and scan_stale and abs(gps_stale - scan_stale) < 60:
        add('usb', 'GPS and WiFi scanning went quiet within a minute of each '
                   'other. Both hang off USB, so a bus/hub glitch or a power '
                   'dip on the USB rail fits better than an RF or per-device '
                   'fault. Check dmesg for USB resets/disconnects.')
    for c in (getattr(engine, '_companions', None) or {}).values():
        try:
            if not c.connected:
                add('companion', f'{c.name or c.port}: disconnected', 'warn')
            for alert in (c.esp_alerts or [])[-5:]:
                add('companion', alert, 'warn')
        except Exception:
            pass

    thr = _throttled()
    if thr and not thr['healthy']:
        if thr['now']:
            add('power', 'Right now: ' + ', '.join(thr['now']))
        if thr['occurred']:
            add('power', 'Since boot: ' + ', '.join(thr['occurred']), 'warn')
    return out


# --------------------------------------------------------------------------

def collect(engine, shared_data=None, force=False):
    """Full diagnostics payload (cached ~5 s)."""
    now = time.time()
    if not force and _CACHE['data'] is not None and now - _CACHE['ts'] < _CACHE_TTL:
        return _CACHE['data']

    usb_devices = _usb_devices()
    data = {
        'generated_at': now,
        'power': None,
        'radios': [],
        'gps': {'present': False},
        'errors': [],
    }
    try:
        data['power'] = power()
    except Exception as e:
        logger.error(f"power diagnostics failed: {e}")
        data['power_error'] = str(e)
    try:
        data['radios'] = radios(engine, usb_devices)
    except Exception as e:
        logger.error(f"radio diagnostics failed: {e}")
        data['radios_error'] = str(e)
    try:
        data['gps'] = gps_extra(engine)
    except Exception as e:
        logger.error(f"gps diagnostics failed: {e}")
        data['gps_error'] = str(e)
    try:
        data['errors'] = errors(engine, shared_data)
    except Exception as e:
        logger.error(f"error collection failed: {e}")

    _CACHE['ts'] = now
    _CACHE['data'] = data
    return data
