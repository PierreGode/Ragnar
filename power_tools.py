"""Power tools for the System tab: Pi 5 USB current limit, USB dropouts, load test.

Three things power_budget.py deliberately does not do, because they are either
*actions* or *time series* rather than a one-shot assessment:

1. **Pi 5 USB current limit.** The Pi 5 firmware caps the *total* current of all
   USB ports at 600 mA unless it negotiated a 5 V / 5 A USB-PD supply. Almost no
   third-party PD charger or power bank offers 5 A at 5 V, so a Pi 5 running a
   USB Wi-Fi adapter plus an SDR/GPS silently hits that cap: the rail stays
   fine, but the port switch drops the device and it re-enumerates in a loop.
   ``usb_max_current_enable=1`` in config.txt raises the cap to 1.6 A. It tells
   the Pi what it may draw — it does not make the supply stronger. Only the
   Pi 5 family has this limiter; Pi 3/4/Zero have no equivalent setting.

2. **USB dropouts** from the kernel log. A device that disconnects and
   re-enumerates several times a minute is the fingerprint of the cap above
   (or of a sagging supply), so we surface it instead of leaving it in dmesg.

3. **Power test.** An idle phase then a load phase (CPU / SDR streaming / Wi-Fi
   scanning), sampling the input rail, throttle register and temperature every
   second and counting USB dropouts; a USB GPS can be watched for data gaps,
   signal loss and a lost fix at the same time. It turns "is my supply good enough for this
   rig?" into a measured answer.

Stdlib only; never raises into the caller. Every privileged step assumes the
Ragnar service runs as root (it does).
"""

import glob
import os
import re
import shutil
import struct
import subprocess
import threading
import time

_BOOT_CFGS = ('/boot/firmware/config.txt', '/boot/config.txt')
_DT_POWER = '/proc/device-tree/chosen/power'
_CFG_KEY = 'usb_max_current_enable'
_CFG_MARK = '# Ragnar: Pi 5 USB current limit (600 mA default, 1.6 A when =1)'


def _run(cmd, timeout=4):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None


def _read(path, binary=False):
    try:
        with open(path, 'rb' if binary else 'r') as f:
            return f.read()
    except OSError:
        return None


def _dt_u32(name):
    raw = _read(f'{_DT_POWER}/{name}', binary=True)
    if not raw or len(raw) < 4:
        return None
    return struct.unpack('>I', raw[:4])[0]


def _model():
    m = _read('/proc/device-tree/model') or ''
    return m.replace('\x00', '').strip()


def _boot_cfg():
    for c in _BOOT_CFGS:
        if os.path.isfile(c):
            return c
    return None


# --------------------------------------------------------------------------
# 1. Pi 5 USB current limit
# --------------------------------------------------------------------------

def _is_pi5_family(model):
    # Pi 5 and Pi 500 share the BCM2712 firmware that enforces the cap. The
    # firmware also publishes the flag in the device tree, which is the most
    # direct sign the setting exists on this board.
    return (model.startswith('Raspberry Pi 5')
            or model.startswith('Raspberry Pi 500')
            or os.path.exists(f'{_DT_POWER}/{_CFG_KEY}'))


def _configured_value(text):
    """The value config.txt sets for Pi 5, honouring [section] filters.

    Returns True / False when a line applies, None when the key is absent (the
    firmware default, 0). Lines under filters that don't match a Pi 5
    ([pi4], [cm4], [none] …) are ignored; the last applicable line wins, the
    same way the firmware reads it.
    """
    section = 'all'
    value = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith('['):
            section = s.strip('[]').strip().lower()
            continue
        if section not in ('all', 'pi5'):
            continue
        m = re.match(rf'{_CFG_KEY}\s*=\s*(\S+)', s)
        if m:
            value = m.group(1).lower() in ('1', 'true', 'on')
    return value


def usb_current_status():
    """Everything the UI needs to show and fix the Pi 5 USB cap."""
    model = _model()
    if not _is_pi5_family(model):
        return {'applies': False, 'model': model,
                'reason': 'Only the Raspberry Pi 5 family limits USB current '
                          'in firmware. Pi 3, Pi 4 and Zero boards have no '
                          'equivalent setting.'}
    cfg = _boot_cfg()
    configured = _configured_value(_read(cfg) or '') if cfg else None
    live = _dt_u32(_CFG_KEY)
    psu_ma = _dt_u32('max_current')
    pd_5a = bool(psu_ma and psu_ma >= 5000)
    active = bool(live) or pd_5a
    return {
        'applies': True,
        'model': model,
        'config_path': cfg,
        'configured': configured,           # True / False / None (absent = 0)
        'live': None if live is None else bool(live),
        'psu_max_ma': psu_ma,               # what the firmware believes the PSU gives
        'pd_5a_supply': pd_5a,
        'usb_limit_ma': 1600 if active else 600,
        'pending_reboot': (live is not None
                           and bool(configured) != bool(live)),
    }


def set_usb_max_current(enable):
    """Write usb_max_current_enable=1 (or an explicit =0) to config.txt.

    Disabling writes ``=0`` rather than deleting the line so the installer's
    Pi 5 step sees an explicit choice and never re-enables it behind the
    operator's back. A timestamped backup is taken first. Takes effect on the
    next reboot.
    """
    st = usb_current_status()
    if not st.get('applies'):
        return {'success': False, 'error': st.get('reason')}
    cfg = st.get('config_path')
    if not cfg:
        return {'success': False, 'error': 'config.txt not found'}
    text = _read(cfg)
    if text is None:
        return {'success': False, 'error': f'cannot read {cfg}'}

    backup = f'{cfg}.ragnar-{time.strftime("%Y%m%d-%H%M%S")}'
    try:
        shutil.copy2(cfg, backup)
    except OSError as e:
        return {'success': False, 'error': f'backup failed: {e}'}

    # Drop every existing setting of the key plus the block we added last
    # time ("[all]" + marker comment), so toggling never piles up lines.
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        s = line.strip()
        if re.match(rf'{_CFG_KEY}\s*=', s) or s == _CFG_MARK:
            continue
        if (s == '[all]' and i + 1 < len(lines)
                and lines[i + 1].strip() == _CFG_MARK):
            continue
        out.append(line)
    while out and not out[-1].strip():
        out.pop()
    # Always under an explicit [all] — appending after a trailing [cm4]/[pi4]
    # filter would silently scope the line away from the Pi 5.
    out += ['', '[all]', _CFG_MARK, f'{_CFG_KEY}={1 if enable else 0}']
    new = '\n'.join(out) + '\n'

    tmp = f'{cfg}.ragnar-tmp'
    try:
        with open(tmp, 'w') as f:
            f.write(new)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, cfg)
        os.sync()
    except OSError as e:
        return {'success': False, 'error': f'write failed: {e}'}
    st = usb_current_status()
    st.update({'success': True, 'backup': backup})
    return st


# --------------------------------------------------------------------------
# 2. USB dropouts from the kernel log
# --------------------------------------------------------------------------

_DISC_RE = re.compile(r'^\[\s*([\d.]+)\]\s+usb (\d+-[\d.]+): USB disconnect')
_LOOP_WINDOW_S = 60
_LOOP_MIN = 3


def _kernel_log():
    return _run(['dmesg'], timeout=5) or ''


def usb_dropouts(log=None):
    """USB disconnects since boot, per port, flagging re-enumeration loops.

    One disconnect is usually a person unplugging something. Three or more on
    the same port inside a minute is a device being dropped by power.
    """
    events = {}
    for line in (log if log is not None else _kernel_log()).splitlines():
        m = _DISC_RE.match(line)
        if m:
            events.setdefault(m.group(2), []).append(float(m.group(1)))
    ports = []
    for port, ts in sorted(events.items()):
        ts.sort()
        worst = max(sum(1 for u in ts if t <= u < t + _LOOP_WINDOW_S)
                    for t in ts)
        product = (_read(f'/sys/bus/usb/devices/{port}/product') or '').strip()
        ports.append({'port': port, 'count': len(ts), 'last_s': ts[-1],
                      'loop': worst >= _LOOP_MIN, 'device': product or None})
    return {'total': sum(p['count'] for p in ports), 'ports': ports,
            'looping': any(p['loop'] for p in ports)}


def _disconnect_count():
    return sum(1 for ln in _kernel_log().splitlines() if _DISC_RE.match(ln))


# --------------------------------------------------------------------------
# 3. Power test
# --------------------------------------------------------------------------

_THROTTLE = ((0, 'under-voltage'), (1, 'ARM frequency capped'),
             (2, 'throttled'), (3, 'soft temperature limit'))
_lock = threading.Lock()
_state = {'running': False, 'result': None}
_GPS_GAP_S = 3          # no NMEA for this long = the receiver stopped talking
# Set by the webapp: gps_provider(start=bool) returns Ragnar's GPSManager
# (starting it when start=True and a receiver is present) or None. The test
# reads that manager rather than opening a serial port Ragnar or gpsd owns.
gps_provider = None


def _sample():
    s = {'t': time.time(), 'input_v': None, 'board_w': None,
         'temp_c': None, 'throttled': None}
    pmic = _run(['vcgencmd', 'pmic_read_adc'])
    if pmic:
        volts, amps = {}, {}
        for m in re.finditer(r'(\S+)_([AV])\s+(?:current|volt)\(\d+\)=([\d.]+)',
                             pmic):
            (amps if m.group(2) == 'A' else volts)[m.group(1)] = float(m.group(3))
        s['input_v'] = volts.get('EXT5V')
        w = sum(volts[r] * amps[r] for r in volts if r in amps)
        s['board_w'] = round(w, 2) if w else None
    t = _run(['vcgencmd', 'measure_temp'])
    m = re.search(r'([\d.]+)', t or '')
    if m:
        s['temp_c'] = float(m.group(1))
    t = _run(['vcgencmd', 'get_throttled'])
    m = re.search(r'0x([0-9a-fA-F]+)', t or '')
    if m:
        s['throttled'] = int(m.group(1), 16)
    return s


def _usb_wifi_ifaces():
    out = []
    for p in glob.glob('/sys/class/net/*'):
        dev = os.path.realpath(f'{p}/device')
        if os.path.isdir(f'{p}/wireless') and '/usb' in dev:
            out.append(os.path.basename(p))
    return sorted(out)


def _gps_ports():
    """USB serial ports that could be a GPS (ESP32 companions excluded)."""
    out = []
    for p in sorted(glob.glob('/dev/ttyACM*') + glob.glob('/dev/ttyUSB*')):
        dev = os.path.realpath(f'/sys/class/tty/{os.path.basename(p)}/device')
        vid = None
        for _ in range(4):                      # walk up to the USB device
            vid = (_read(f'{dev}/idVendor') or '').strip()
            if vid:
                break
            dev = os.path.dirname(dev)
        if vid != '303a':                       # Espressif
            out.append(p)
    return out


def _gps_sample(gps):
    if gps is None:
        return None
    try:
        st = gps.get_status()
    except Exception:
        return None
    last = st.get('last_sentence') or 0
    return {'age_s': round(time.time() - last, 1) if last else None,
            'fix': bool(st.get('has_fix')),
            'sats_used': st.get('satellites') or 0,
            'sats_view': st.get('satellites_in_view') or 0,
            'snr_max': st.get('snr_max')}


def _gps_connected():
    try:
        gps = gps_provider(start=False) if gps_provider else None
        return bool(gps and gps.get_status().get('connected'))
    except Exception:
        return False


def available_loads():
    gps_ports = _gps_ports()
    return {
        'cpu': {'available': True, 'label': f'CPU ({os.cpu_count() or 1} cores)'},
        'sdr': {'available': bool(shutil.which('rtl_sdr')),
                'label': 'RTL-SDR streaming 2.4 MS/s'},
        'wifi': {'available': bool(_usb_wifi_ifaces()),
                 'label': 'USB Wi-Fi scanning ('
                          + (', '.join(_usb_wifi_ifaces()) or 'none') + ')'},
        # Not a load generator: the receiver is watched through both phases
        # so a GPS that goes silent or loses signal under load shows up.
        'gps': {'available': bool(gps_ports) or _gps_connected(),
                'label': 'USB GPS ('
                         + (', '.join(os.path.basename(p) for p in gps_ports)
                            or 'none') + ')'},
    }


class _Loads:
    """Start/stop the selected load generators; records what each achieved."""

    def __init__(self, loads):
        self.loads = loads
        self.procs = []
        self.stop = threading.Event()
        self.threads = []
        self.sdr_bytes = 0
        self.sdr_error = None
        self.scans_ok = 0
        self.scans_failed = 0
        self.raised = []

    def start(self):
        if 'cpu' in self.loads:
            for _ in range(os.cpu_count() or 1):
                self.procs.append(subprocess.Popen(
                    ['yes'], stdout=subprocess.DEVNULL))
        if 'sdr' in self.loads and shutil.which('rtl_sdr'):
            p = subprocess.Popen(['rtl_sdr', '-f', '100000000', '-s', '2400000', '-'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.procs.append(p)
            self.threads.append(threading.Thread(
                target=self._drain_sdr, args=(p,), daemon=True))
        if 'wifi' in self.loads:
            for iface in _usb_wifi_ifaces():
                # A downed adapter draws almost nothing — bring it up for the
                # test and put it back afterwards.
                if (_read(f'/sys/class/net/{iface}/operstate') or '').strip() == 'down':
                    if _run(['ip', 'link', 'set', iface, 'up']) is not None:
                        self.raised.append(iface)
                self.threads.append(threading.Thread(
                    target=self._scan_loop, args=(iface,), daemon=True))
        for t in self.threads:
            t.start()

    def _drain_sdr(self, p):
        while not self.stop.is_set():
            chunk = p.stdout.read(65536)
            if not chunk:
                err = (p.stderr.read() or b'').decode(errors='replace')
                if 'usb_claim_interface' in err or 'busy' in err.lower():
                    self.sdr_error = 'SDR is in use by another program'
                elif 'No supported devices' in err:
                    self.sdr_error = 'no RTL-SDR connected'
                elif not self.stop.is_set():
                    self.sdr_error = 'rtl_sdr stopped early'
                return
            self.sdr_bytes += len(chunk)

    def _scan_loop(self, iface):
        while not self.stop.is_set():
            try:
                r = subprocess.run(['iw', 'dev', iface, 'scan'],
                                   capture_output=True, timeout=20)
                rc = r.returncode
            except Exception:
                rc = 1
            if rc == 0:
                self.scans_ok += 1
            else:
                self.scans_failed += 1
                self.stop.wait(1)

    def close(self):
        self.stop.set()
        for p in self.procs:
            try:
                p.kill()
                p.wait(timeout=3)
            except Exception:
                pass
        for t in self.threads:
            t.join(timeout=5)
        for iface in self.raised:
            _run(['ip', 'link', 'set', iface, 'down'])


def _summarise_gps(samples):
    g = [s['gps'] for s in samples if s.get('gps')]
    if not g:
        return None
    ages = [x['age_s'] for x in g if x['age_s'] is not None]
    snr = [x['snr_max'] for x in g if x['snr_max'] is not None]
    return {
        'samples': len(g),
        # seconds in which the receiver had sent nothing for > _GPS_GAP_S
        'silent_s': sum(1 for x in g
                        if x['age_s'] is None or x['age_s'] > _GPS_GAP_S),
        'max_age_s': max(ages) if ages else None,
        'fix_pct': round(100 * sum(1 for x in g if x['fix']) / len(g)),
        'sats_used_avg': round(sum(x['sats_used'] for x in g) / len(g), 1),
        'sats_view_avg': round(sum(x['sats_view'] for x in g) / len(g), 1),
        'snr_max_avg': round(sum(snr) / len(snr), 1) if snr else None,
    }


def _summarise(samples, disc):
    v = [s['input_v'] for s in samples if s['input_v'] is not None]
    w = [s['board_w'] for s in samples if s['board_w'] is not None]
    t = [s['temp_c'] for s in samples if s['temp_c'] is not None]
    now_bits = 0
    for s in samples:
        now_bits |= (s['throttled'] or 0) & 0xF
    return {
        'samples': len(samples),
        'input_v_avg': round(sum(v) / len(v), 3) if v else None,
        'input_v_min': round(min(v), 3) if v else None,
        'board_w_avg': round(sum(w) / len(w), 2) if w else None,
        'board_w_max': round(max(w), 2) if w else None,
        'temp_max': max(t) if t else None,
        'flags': [label for bit, label in _THROTTLE if now_bits & (1 << bit)],
        'usb_disconnects': disc,
        'gps': _summarise_gps(samples),
    }


def _verdict(idle, load, loads_info, usb):
    issues, advice = [], []
    if 'under-voltage' in load['flags'] or 'under-voltage' in idle['flags']:
        issues.append('Under-voltage: the supply or cable cannot hold 5 V.')
        advice.append('Use a stronger supply and a short, thick cable.')
    if load['usb_disconnects'] or idle['usb_disconnects']:
        issues.append('USB devices dropped off during the test.')
        if usb.get('applies') and usb.get('usb_limit_ma') == 600:
            advice.append('Raise the Pi 5 USB limit to 1.6 A (button above) '
                          'and reboot, then run the test again.')
        else:
            advice.append('Put the Wi-Fi adapter on a powered USB hub.')
    if 'soft temperature limit' in load['flags']:
        issues.append('Heat throttling under load.')
        advice.append('Add a fan or heatsink; this is heat, not power.')
    gi, gl = idle.get('gps'), load.get('gps')
    if loads_info.get('gps_error'):
        issues.append(f"GPS not monitored: {loads_info['gps_error']}.")
    elif gi and gl:
        if gi['silent_s'] >= gi['samples'] and gl['silent_s'] >= gl['samples']:
            issues.append('GPS is not sending any data.')
        elif gl['silent_s'] > gi['silent_s'] + 1:
            issues.append(f"GPS went silent for {gl['silent_s']} s under load.")
            advice.append('A GPS that goes silent together with USB dropouts '
                          'is losing power; otherwise check its cable.')
        if (gi['snr_max_avg'] is not None and gl['snr_max_avg'] is not None
                and gi['snr_max_avg'] - gl['snr_max_avg'] >= 4):
            issues.append(f"GPS signal fell {gi['snr_max_avg'] - gl['snr_max_avg']:.0f} dB "
                          'under load (RF interference).')
            advice.append('Move the GPS away from the Wi-Fi adapter and SDR, '
                          'e.g. on a USB extension cable.')
        if gi['fix_pct'] >= 90 and gl['fix_pct'] < 50:
            issues.append('GPS lost its fix under load.')
    if loads_info.get('sdr_error'):
        issues.append(f"SDR load not applied: {loads_info['sdr_error']}.")
    lv, iv = load['input_v_min'], idle['input_v_avg']
    if lv is not None and lv < 4.9 and not issues:
        issues.append(f'Input dipped to {lv:.2f} V — close to the 4.63 V '
                      'under-voltage threshold.')
    ok = not issues
    sag = round(iv - lv, 3) if (iv is not None and lv is not None) else None
    return {'ok': ok, 'sag_v': sag,
            'headline': 'Stable under load' if ok else issues[0],
            'issues': issues, 'advice': advice}


def _run_test(duration, loads):
    half = max(5, duration // 2)
    result = {'started': time.time(), 'duration': half * 2, 'loads': loads,
              'phase': 'idle', 'progress': 0}
    _state['result'] = result
    usb = usb_current_status()
    load_gen = None
    gps, gps_error = None, None
    if 'gps' in loads:
        try:
            gps = gps_provider(start=True) if gps_provider else None
            if gps is None:
                gps_error = 'no GPS receiver found'
        except Exception as e:
            gps_error = str(e)
    try:
        phases = {}
        for phase in ('idle', 'load'):
            result['phase'] = phase
            if phase == 'load':
                load_gen = _Loads(loads)
                load_gen.start()
            d0 = _disconnect_count()
            samples = []
            end = time.time() + half
            while time.time() < end:
                samples.append(_sample())
                if gps is not None:
                    samples[-1]['gps'] = _gps_sample(gps)
                done = (len(samples) + (half if phase == 'load' else 0))
                result['progress'] = min(99, int(100 * done / (half * 2)))
                result['live'] = samples[-1]
                time.sleep(max(0, 1 - (time.time() - samples[-1]['t'])))
            phases[phase] = _summarise(samples, _disconnect_count() - d0)
        info = {}
        if 'gps' in loads:
            info['gps_error'] = gps_error
        if load_gen:
            load_gen.close()
            if 'sdr' in loads:
                expect = 2400000 * 2 * half
                info['sdr_rate_pct'] = round(100 * load_gen.sdr_bytes / expect)
                info['sdr_error'] = load_gen.sdr_error
            if 'wifi' in loads:
                info['scans_ok'] = load_gen.scans_ok
                info['scans_failed'] = load_gen.scans_failed
            load_gen = None
        result.update({'idle': phases['idle'], 'load': phases['load'],
                       'load_info': info, 'usb_limit_ma': usb.get('usb_limit_ma'),
                       'verdict': _verdict(phases['idle'], phases['load'],
                                           info, usb),
                       'phase': 'done', 'progress': 100,
                       'finished': time.time()})
    except Exception as e:
        result.update({'phase': 'error', 'error': str(e)})
    finally:
        if load_gen:
            load_gen.close()
        result.pop('live', None)
        _state['running'] = False


def start_test(duration=40, loads=None):
    loads = [x for x in (loads or []) if x in ('cpu', 'sdr', 'wifi', 'gps')]
    duration = max(10, min(int(duration or 40), 120))
    with _lock:
        if _state['running']:
            return {'success': False, 'error': 'A power test is already running'}
        _state['running'] = True
    threading.Thread(target=_run_test, args=(duration, loads),
                     daemon=True).start()
    return {'success': True, 'duration': duration, 'loads': loads}


def test_status():
    return {'running': _state['running'], 'result': _state['result'],
            'loads': available_loads()}


if __name__ == '__main__':      # quick CLI check: python3 power_tools.py
    import json
    print(json.dumps({'usb_current': usb_current_status(),
                      'dropouts': usb_dropouts(),
                      'loads': available_loads()}, indent=2))
