#!/usr/bin/env python3
"""Cooling fan status and control for the System tab.

Reads the fan straight from the kernel; no daemon, no extra packages.

* **Pi 5** (official Case Fan / Active Cooler on the 4-pin FAN header): the
  ``pwm-fan`` driver exposes a hwmon with the tachometer (``fan1_input``, RPM)
  and the duty cycle (``pwm1``, 0-255). The CPU thermal zone drives it through
  cooling device ``pwm-fan`` in 5 steps (off / 30 / 50 / 70 / 100 %), switching
  at the zone's ``active`` trip points (50 / 60 / 67.5 / 75 °C by default).
* **Pi 4 / others** with ``dtoverlay=gpio-fan``: an on/off cooling device, no
  tachometer, so "connected" can't be measured, only the commanded state.
* A 2-wire fan on the 5 V pins is invisible to software.

The Pi 5 driver is present whether or not a fan is plugged in, so presence is
inferred from the tachometer: turning while commanded on means connected; 0 RPM
while commanded on means absent or stalled. While the fan is idle nothing can
be told, so :func:`spin_test` briefly runs it at full speed and reads the RPM.

Control, all at runtime (lost on reboot unless noted):

* **Manual speed** — the thermal zone is switched to ``mode=disabled`` so the
  step_wise governor stops overriding us, then ``pwm1`` (or the cooling state)
  is written. A watchdog thread returns to automatic at ``FAILSAFE_C`` and the
  firmware still throttles the CPU at 85 °C regardless.
* **Fan curve** — the four ``active`` trip temperatures are writable on the
  Pi 5 kernel; optionally persisted as ``dtparam=fan_tempN=`` in config.txt.

Stdlib only; never raises into the caller. Assumes root (the Ragnar service).
"""

import glob
import os
import re
import shutil
import threading
import time

FAILSAFE_C = 75.0            # manual mode hands back to the kernel at this SoC temp
_WATCH_S = 3
_SPIN_S = 3.5
_MARKER = '/run/ragnar-fan-manual'   # tmpfs: survives a service crash, not a reboot
_BOOT_CFGS = ('/boot/firmware/config.txt', '/boot/config.txt')
_CFG_MARK = '# Ragnar: fan curve (System tab)'
# Pi 5 firmware defaults (bcm2712 dts), used when resetting the curve.
PI5_DEFAULT_TRIPS = [(50.0, 5.0), (60.0, 5.0), (67.5, 5.0), (75.0, 5.0)]
_TRIP_MIN_C, _TRIP_MAX_C = 30.0, 85.0

_lock = threading.Lock()
_state = {'manual': None, 'failsafe': None, 'spin': None, 'max_rpm': None}
_watch_thread = None


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def _read_int(path):
    v = _read(path)
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _write(path, value):
    try:
        with open(path, 'w') as f:
            f.write(str(value))
        return True
    except OSError:
        return False


def _model():
    m = _read('/proc/device-tree/model') or ''
    return m.replace('\x00', '').strip()


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def _find_hwmon():
    """The hwmon dir of the fan driver (pwmfan / gpio-fan), or one with a tach."""
    fallback = None
    for h in sorted(glob.glob('/sys/class/hwmon/hwmon*')):
        name = _read(f'{h}/name') or ''
        if name in ('pwmfan', 'gpio_fan', 'gpiofan', 'gpio-fan'):
            return h, name
        if fallback is None and os.path.exists(f'{h}/fan1_input'):
            fallback = (h, name)
    return fallback or (None, None)


def _find_cdev():
    for c in sorted(glob.glob('/sys/class/thermal/cooling_device*')):
        t = _read(f'{c}/type') or ''
        if 'fan' in t.lower():
            return c, t
    return None, None


def _cpu_zone():
    zones = sorted(glob.glob('/sys/class/thermal/thermal_zone*'))
    for z in zones:
        if (_read(f'{z}/type') or '').startswith('cpu'):
            return z
    return zones[0] if zones else None


def _zone_bindings(zone, cdev):
    """Trip indices of ``zone`` that drive ``cdev``."""
    if not zone or not cdev:
        return []
    cdev_name = os.path.basename(cdev)
    trips = []
    for link in glob.glob(f'{zone}/cdev[0-9]*'):
        if '_' in os.path.basename(link):
            continue
        try:
            if os.path.basename(os.path.realpath(link)) != cdev_name:
                continue
        except OSError:
            continue
        t = _read_int(f'{link}_trip_point')
        if t is not None:
            trips.append(t)
    return sorted(set(trips))


def _trips(zone, idx=None):
    out = []
    if not zone:
        return out
    for p in sorted(glob.glob(f'{zone}/trip_point_*_temp'),
                    key=lambda s: int(re.search(r'_(\d+)_temp', s).group(1))):
        i = int(re.search(r'_(\d+)_temp', p).group(1))
        typ = _read(f'{zone}/trip_point_{i}_type')
        temp = _read_int(p)
        if temp is None:
            continue
        if idx is not None and i not in idx:
            continue
        if idx is None and typ != 'active':
            continue
        hyst = _read_int(f'{zone}/trip_point_{i}_hyst')
        out.append({'index': i, 'type': typ, 'temp_c': temp / 1000.0,
                    'hyst_c': None if hyst is None else hyst / 1000.0,
                    'writable': os.access(p, os.W_OK)})
    return out


def _cooling_levels():
    """Pi 5 DT ``cooling-levels``: the pwm (0-255) for each cooling state."""
    try:
        with open('/proc/device-tree/cooling_fan/cooling-levels', 'rb') as f:
            raw = f.read()
        return [int.from_bytes(raw[i:i + 4], 'big') for i in range(0, len(raw), 4)]
    except OSError:
        return None


def _fan_header_present():
    s = _read('/proc/device-tree/cooling_fan/status')
    return s is not None and s.replace('\x00', '') == 'okay'


def _hw():
    hw, hw_name = _find_hwmon()
    cdev, cdev_type = _find_cdev()
    zone = _cpu_zone()
    return {'hwmon': hw, 'hwmon_name': hw_name, 'cdev': cdev,
            'cdev_type': cdev_type, 'zone': zone}


# --------------------------------------------------------------------------
# Status
# --------------------------------------------------------------------------

def _presence(pwm, rpm, has_tach, cur_state):
    """connected: True / False / None (can't tell) + a short reason."""
    if not has_tach:
        return None, 'No tachometer — speed and presence can’t be measured.'
    if rpm and rpm > 0:
        return True, 'Tachometer reports the fan turning.'
    on = (pwm or 0) > 0 if pwm is not None else (cur_state or 0) > 0
    if on:
        return False, 'Commanded on but 0 RPM — no fan on the header, or it has stalled.'
    return None, 'Fan is idle (below the first trip). Run a spin test to check it.'


def status():
    hw = _hw()
    h, cdev, zone = hw['hwmon'], hw['cdev'], hw['zone']
    model = _model()
    if not h and not cdev:
        return {'supported': False, 'model': model,
                'reason': 'No fan driver found. On a Pi 5 plug the fan into the '
                          'FAN header; on a Pi 4 add dtoverlay=gpio-fan to '
                          'config.txt. A 2-wire fan on the 5 V pins can’t be '
                          'seen by software.'}

    rpm = _read_int(f'{h}/fan1_input') if h else None
    has_tach = rpm is not None
    pwm = _read_int(f'{h}/pwm1') if h else None
    cur = _read_int(f'{cdev}/cur_state') if cdev else None
    mx = _read_int(f'{cdev}/max_state') if cdev else None
    temp = _read_int(f'{zone}/temp') if zone else None
    zone_mode = _read(f'{zone}/mode') if zone else None
    policy = _read(f'{zone}/policy') if zone else None

    bound = _zone_bindings(zone, cdev)
    trips = _trips(zone, set(bound) if bound else None)
    trips = [t for t in trips if t['type'] == 'active'] or trips
    levels = _cooling_levels()

    # Map each trip to the fan speed it switches to (state i+1).
    for i, t in enumerate(trips):
        st = i + 1
        if levels and st < len(levels):
            t['pwm'] = levels[st]
            t['percent'] = round(levels[st] * 100 / 255)
        elif mx:
            t['percent'] = round(st * 100 / mx)
        t['active'] = cur is not None and cur >= st

    with _lock:
        if rpm and pwm and pwm >= 250:
            _state['max_rpm'] = max(_state['max_rpm'] or 0, rpm)
        manual = dict(_state['manual']) if _state['manual'] else None
        failsafe = _state['failsafe']
        spin = _state['spin']
        max_rpm = _state['max_rpm']

    connected, why = _presence(pwm, rpm, has_tach, cur)
    if connected is None and spin and time.time() - spin['at'] < 600:
        connected = spin['connected']
        why = 'From the spin test ' + _ago(spin['at']) + '.'

    percent = None
    if pwm is not None:
        percent = round(pwm * 100 / 255)
    elif cur is not None and mx:
        percent = round(cur * 100 / mx)

    # Health: a fan that turns much slower than it did at full speed is wearing out.
    health = None
    if connected and pwm and pwm >= 250 and max_rpm and rpm:
        health = round(rpm * 100 / max_rpm)

    mode = 'manual' if (manual or zone_mode == 'disabled') else 'auto'
    return {
        'supported': True,
        'model': model,
        'driver': hw['hwmon_name'] or hw['cdev_type'],
        'fan_header': _fan_header_present(),
        'has_tach': has_tach,
        'connected': connected,
        'connected_reason': why,
        'rpm': rpm,
        'max_rpm': max_rpm,
        'health_percent': health,
        'pwm': pwm,
        'percent': percent,
        'state': cur,
        'max_state': mx,
        'levels': levels,
        'temp_c': None if temp is None else round(temp / 1000.0, 1),
        'mode': mode,
        'manual': manual,
        'zone_mode': zone_mode,
        'policy': policy,
        'trips': trips,
        'curve_writable': bool(trips) and all(t['writable'] for t in trips),
        'failsafe_c': FAILSAFE_C,
        'last_failsafe': failsafe,
        'spin_test': spin,
        'persisted_curve': persisted_curve(),
        'can_persist': _fan_header_present(),
        'can_control': bool(zone and (pwm is not None or cdev)),
    }


def _ago(ts):
    s = int(time.time() - ts)
    return f'{s} s ago' if s < 90 else f'{s // 60} min ago'


# --------------------------------------------------------------------------
# Control: manual speed / automatic
# --------------------------------------------------------------------------

def _apply_speed(hw, percent):
    percent = max(0, min(100, int(percent)))
    h, cdev = hw['hwmon'], hw['cdev']
    if h and os.path.exists(f'{h}/pwm1'):
        return _write(f'{h}/pwm1', round(percent * 255 / 100))
    mx = _read_int(f'{cdev}/max_state') if cdev else None
    if cdev and mx:
        return _write(f'{cdev}/cur_state', round(percent * mx / 100))
    return False


def _curve_state(hw):
    """The cooling state the trip curve calls for at the current temperature."""
    zone, cdev = hw['zone'], hw['cdev']
    temp = _read_int(f'{zone}/temp') if zone else None
    if temp is None or not cdev:
        return None
    bound = _zone_bindings(zone, cdev)
    trips = [t for t in _trips(zone, set(bound) if bound else None) if t['type'] == 'active']
    return sum(1 for t in trips if temp / 1000.0 >= t['temp_c'])


def _restore_auto(hw, reason=None):
    # step_wise only moves on a trip crossing, so handing back a fan pinned at
    # 100 % in a cool room would leave it there. Start from what the curve says.
    want = _curve_state(hw)
    if want is not None:
        _write(f"{hw['cdev']}/cur_state", want)
        # pwm-fan skips a cur_state write equal to its cached state, even
        # when pwm1 was changed behind its back — set the duty too.
        levels = _cooling_levels()
        if hw['hwmon'] and levels and want < len(levels):
            _write(f"{hw['hwmon']}/pwm1", levels[want])
    ok = _write(f"{hw['zone']}/mode", 'enabled') if hw['zone'] else False
    try:
        os.remove(_MARKER)
    except OSError:
        pass
    with _lock:
        _state['manual'] = None
        if reason:
            _state['failsafe'] = {'at': time.time(), 'reason': reason}
    return ok


def set_manual(percent):
    hw = _hw()
    if not hw['zone'] or not (hw['hwmon'] or hw['cdev']):
        return {'success': False, 'error': 'No controllable fan found.'}
    temp = _read_int(f"{hw['zone']}/temp")
    if temp is not None and temp / 1000.0 >= FAILSAFE_C and int(percent) < 100:
        return {'success': False,
                'error': f'SoC is at {temp / 1000.0:.1f} °C (≥ {FAILSAFE_C:g} °C); '
                         'manual speed below 100 % is refused.'}
    if not _write(f"{hw['zone']}/mode", 'disabled'):
        return {'success': False, 'error': 'Cannot take over the thermal zone (not root?).'}
    if not _apply_speed(hw, percent):
        _restore_auto(hw)
        return {'success': False, 'error': 'Writing the fan speed failed.'}
    _write(_MARKER, str(int(percent)))
    with _lock:
        _state['manual'] = {'percent': max(0, min(100, int(percent))), 'since': time.time()}
        _state['failsafe'] = None
    _ensure_watchdog()
    st = status()
    st['success'] = True
    return st


def set_auto():
    hw = _hw()
    if not hw['zone']:
        return {'success': False, 'error': 'No thermal zone.'}
    ok = _restore_auto(hw)
    st = status()
    st['success'] = ok
    if not ok:
        st['error'] = 'Could not re-enable the thermal zone.'
    return st


def _watchdog():
    global _watch_thread
    while True:
        time.sleep(_WATCH_S)
        with _lock:
            manual = _state['manual']
        if not manual:
            break
        hw = _hw()
        temp = _read_int(f"{hw['zone']}/temp") if hw['zone'] else None
        if temp is not None and temp / 1000.0 >= FAILSAFE_C:
            _restore_auto(hw, reason=f'SoC reached {temp / 1000.0:.1f} °C — '
                                     'handed back to automatic control.')
            # step_wise ramps one state per poll; jump straight to full speed.
            _apply_speed(hw, 100)
            break
        # Something else re-enabled the zone (another tool, a reboot of the
        # driver): our manual setting is gone, so stop claiming it.
        if hw['zone'] and _read(f"{hw['zone']}/mode") == 'enabled':
            with _lock:
                _state['manual'] = None
            break
    with _lock:
        _watch_thread = None


def _ensure_watchdog():
    global _watch_thread
    with _lock:
        if _watch_thread and _watch_thread.is_alive():
            return
        _watch_thread = threading.Thread(target=_watchdog, name='fan-watchdog', daemon=True)
        _watch_thread.start()


def recover():
    """At startup: a crashed Ragnar must not leave the fan pinned by hand."""
    if os.path.exists(_MARKER):
        hw = _hw()
        if hw['zone']:
            _restore_auto(hw)


# --------------------------------------------------------------------------
# Spin test
# --------------------------------------------------------------------------

def spin_test():
    """Run the fan at 100 % for a few seconds and read the tachometer."""
    hw = _hw()
    h = hw['hwmon']
    if not h or _read_int(f'{h}/fan1_input') is None:
        return {'success': False, 'error': 'This fan has no tachometer to read.'}
    if not hw['zone']:
        return {'success': False, 'error': 'No thermal zone.'}
    prev_mode = _read(f"{hw['zone']}/mode")
    prev_pwm = _read_int(f'{h}/pwm1')
    if not _write(f"{hw['zone']}/mode", 'disabled'):
        return {'success': False, 'error': 'Cannot take over the thermal zone (not root?).'}
    try:
        _write(f'{h}/pwm1', 255)
        time.sleep(_SPIN_S)
        rpm = _read_int(f'{h}/fan1_input') or 0
    finally:
        if prev_pwm is not None:
            _write(f'{h}/pwm1', prev_pwm)
        if prev_mode != 'disabled':
            _write(f"{hw['zone']}/mode", 'enabled')
    res = {'at': time.time(), 'rpm': rpm, 'connected': rpm > 0}
    with _lock:
        _state['spin'] = res
        if rpm:
            _state['max_rpm'] = max(_state['max_rpm'] or 0, rpm)
    st = status()
    st['success'] = True
    return st


# --------------------------------------------------------------------------
# Fan curve (trip temperatures)
# --------------------------------------------------------------------------

def _validate_curve(temps):
    temps = [float(t) for t in temps]
    for t in temps:
        if not _TRIP_MIN_C <= t <= _TRIP_MAX_C:
            raise ValueError(f'Trip temperatures must be {_TRIP_MIN_C:g}–{_TRIP_MAX_C:g} °C.')
    if any(b <= a for a, b in zip(temps, temps[1:])):
        raise ValueError('Each step must be warmer than the one before.')
    return temps


def set_curve(temps, persist=False):
    """Write the active trip temperatures (°C, ascending) at runtime."""
    st = status()
    if not st.get('supported'):
        return {'success': False, 'error': st.get('reason')}
    trips = st['trips']
    if not st['curve_writable']:
        return {'success': False, 'error': 'This kernel does not allow changing trip points.'}
    try:
        temps = _validate_curve(temps)
    except (TypeError, ValueError) as e:
        return {'success': False, 'error': str(e)}
    if len(temps) != len(trips):
        return {'success': False, 'error': f'Expected {len(trips)} temperatures.'}
    zone = _cpu_zone()
    for t, new in zip(trips, temps):
        if not _write(f"{zone}/trip_point_{t['index']}_temp", int(new * 1000)):
            return {'success': False, 'error': f"Writing trip {t['index']} failed."}
    out = status()
    out['success'] = True
    if persist:
        out['persist'] = persist_curve(temps, [t.get('hyst_c') for t in trips])
    return out


def reset_curve():
    st = status()
    if not st.get('supported'):
        return {'success': False, 'error': st.get('reason')}
    defaults = [t for t, _ in PI5_DEFAULT_TRIPS] if st['can_persist'] else None
    if not defaults or len(defaults) != len(st['trips']):
        return {'success': False, 'error': 'No known defaults for this board.'}
    res = set_curve(defaults)
    if res.get('success') and st['persisted_curve']:
        res['persist'] = persist_curve(None)
    return res


def _boot_cfg():
    for c in _BOOT_CFGS:
        if os.path.isfile(c):
            return c
    return None


_DTP_RE = re.compile(r'^\s*dtparam\s*=\s*(fan_temp[0-3](?:_hyst|_speed)?)\s*=\s*(\d+)\s*$')


def persisted_curve():
    """fan_tempN values config.txt sets (millidegrees → °C), or None."""
    cfg = _boot_cfg()
    text = _read(cfg) if cfg else None
    if not text:
        return None
    found = {}
    for line in text.splitlines():
        m = _DTP_RE.match(line)
        if m and not m.group(1).endswith(('_hyst', '_speed')):
            found[m.group(1)] = int(m.group(2)) / 1000.0
    return found or None


def persist_curve(temps, hysts=None):
    """Write (or with ``temps=None`` remove) dtparam=fan_tempN lines.

    Pi 5 only. Takes a timestamped backup of config.txt first; takes effect on
    the next boot. Only lines Ragnar wrote (under its marker) are replaced.
    """
    if not _fan_header_present():
        return {'success': False, 'error': 'Only the Pi 5 fan header takes fan_temp dtparams.'}
    cfg = _boot_cfg()
    text = _read(cfg) if cfg else None
    if text is None:
        return {'success': False, 'error': 'config.txt not found'}
    backup = f'{cfg}.ragnar-{time.strftime("%Y%m%d-%H%M%S")}'
    try:
        shutil.copy2(cfg, backup)
    except OSError as e:
        return {'success': False, 'error': f'backup failed: {e}'}
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        s = line.strip()
        if _DTP_RE.match(line) or s == _CFG_MARK:
            continue
        if s == '[all]' and i + 1 < len(lines) and lines[i + 1].strip() == _CFG_MARK:
            continue
        out.append(line)
    while out and not out[-1].strip():
        out.pop()
    if temps:
        out += ['', '[all]', _CFG_MARK]
        for n, t in enumerate(temps):
            out.append(f'dtparam=fan_temp{n}={int(round(t * 1000))}')
            h = (hysts or [None] * len(temps))[n]
            if h is not None:
                out.append(f'dtparam=fan_temp{n}_hyst={int(round(h * 1000))}')
    tmp = f'{cfg}.ragnar-tmp'
    try:
        with open(tmp, 'w') as f:
            f.write('\n'.join(out) + '\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, cfg)
        os.sync()
    except OSError as e:
        return {'success': False, 'error': f'write failed: {e}'}
    return {'success': True, 'backup': backup, 'config_path': cfg}


if __name__ == '__main__':
    import json
    print(json.dumps(status(), indent=2))
