# gps_assist.py
# Self-aided GNSS start for u-blox receivers (position/time pre-load plus
# saved almanac/ephemeris), so a cold boot behaves like a warm/hot start.
#
# Why: the cheap u-blox 7 USB pucks have no battery-backed RAM, so every power
# cycle is a full cold start — the receiver has no idea where it is, what time
# it is, or where the satellites are, and must demodulate ~30 s of continuous
# ephemeris per satellite (and 12.5 min for a full almanac) before it can fix.
# On a marginal sky (window, dashboard, a noisy Wi-Fi adapter next to the puck)
# that often never completes. We already know most of that information:
#
#   * position — GPSManager persists the last confirmed fix (last_gps.json)
#   * time     — the Pi's clock, when NTP has synchronized it
#   * orbits   — the receiver's own almanac/ephemeris, polled after a good fix
#                and saved here, then handed back at the next boot
#
# Frames are standard UBX. AID-INI/HUI/ALM/EPH cover u-blox 6/7 (and M8); the
# MGA-INI pair covers M8/M9/M10, which dropped AID-INI. A receiver ignores the
# class it does not implement, so sending both is harmless.

import ctypes
import json
import os
import socket
import struct
import time
import logging
from datetime import datetime, timezone

logger = logging.getLogger("GPSAssist")

UBX_SYNC = b'\xb5\x62'

CLS_AID = 0x0B
ID_AID_INI = 0x01
ID_AID_HUI = 0x02
ID_AID_ALM = 0x30
ID_AID_EPH = 0x31
CLS_MGA = 0x13
ID_MGA_INI = 0x40

# GPS epoch (1980-01-06) in Unix seconds, and GPS-UTC offset. The leap-second
# count only moves on IERS announcement (none since 2017); a 1 s error is far
# inside the time accuracy we declare, so a constant is fine.
GPS_EPOCH_UNIX = 315964800
GPS_LEAP_SECONDS = 18

# How precise we claim the injected hints are. Generous on purpose: the last
# fix may be from another town, and an over-confident hint slows a receiver
# down more than a vague one. 100 km still pins which satellites are up.
POS_ACC_M = 100_000
TIME_ACC_MS = 1000

# Freshness limits for re-injecting saved orbit data. Broadcast ephemeris is
# valid ~4 h around its reference time; the almanac stays usable for weeks;
# HUI (health/UTC/iono) changes rarely.
EPH_MAX_AGE_S = 4 * 3600
ALM_MAX_AGE_S = 30 * 86400
HUI_MAX_AGE_S = 30 * 86400

# Payload sizes of AID messages that actually carry data (a receiver answers a
# poll for an SV it knows nothing about with just the 8-byte header).
_ALM_FULL_LEN = 40
_EPH_FULL_LEN = 104
_HUI_LEN = 72

GPSD_CONTROL_SOCKETS = ('/run/gpsd.sock', '/var/run/gpsd.sock')
TIME_ERROR = 5   # adjtimex() clock state: "clock not synchronized"


def ubx_frame(msg_class, msg_id, payload=b''):
    """Build a UBX frame with its 8-bit Fletcher checksum."""
    body = bytes((msg_class, msg_id)) + struct.pack('<H', len(payload)) + payload
    ck_a = ck_b = 0
    for byte in body:
        ck_a = (ck_a + byte) & 0xFF
        ck_b = (ck_b + ck_a) & 0xFF
    return UBX_SYNC + body + bytes((ck_a, ck_b))


def parse_ubx_frames(data):
    """Extract checksum-valid UBX frames from a byte stream.

    Returns a list of (msg_class, msg_id, payload). Tolerates interleaved
    NMEA/JSON text and truncated frames at either end.
    """
    frames = []
    i = 0
    n = len(data)
    while True:
        i = data.find(UBX_SYNC, i)
        if i < 0 or i + 8 > n:
            break
        length = struct.unpack_from('<H', data, i + 4)[0]
        end = i + 6 + length + 2
        if end > n:
            break
        frame = bytes(data[i:end])
        if ubx_frame(frame[2], frame[3], frame[6:-2]) == frame:
            frames.append((frame[2], frame[3], frame[6:-2]))
            i = end
        else:
            i += 2
    return frames


def gps_week_tow(unix_t):
    """Unix time -> (GPS week, time-of-week ms)."""
    gps_s = unix_t - GPS_EPOCH_UNIX + GPS_LEAP_SECONDS
    week = int(gps_s // 604800)
    tow_ms = int(round((gps_s - week * 604800) * 1000))
    return week, tow_ms


def clock_is_synced():
    """True when the system clock is NTP-disciplined.

    A Pi Zero has no RTC: booted without network it runs on fake-hwclock (the
    last shutdown time), which may be hours or days off. Feeding a receiver a
    wrong time is worse than feeding it none, so time is only injected when the
    kernel says the clock is synchronized — adjtimex() is what timesyncd,
    chrony and ntpd all report through.
    """
    if time.time() < 1704067200:            # before 2024: obviously unset
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        buf = ctypes.create_string_buffer(512)   # struct timex, modes=0 → read
        state = libc.adjtimex(buf)
        if state >= 0:
            return state != TIME_ERROR
    except Exception:
        pass
    return os.path.exists('/run/systemd/timesync/synchronized')


def aid_ini_frame(lat=None, lon=None, alt_m=None, unix_t=None,
                  pos_acc_m=POS_ACC_M, time_acc_ms=TIME_ACC_MS):
    """UBX-AID-INI (u-blox 6/7/M8): rough position and/or time."""
    flags = 0
    lat_i = lon_i = alt_cm = pos_acc = 0
    if lat is not None and lon is not None:
        flags |= 0x01 | 0x20                 # posValid | lla
        lat_i = int(round(lat * 1e7))
        lon_i = int(round(lon * 1e7))
        pos_acc = int(pos_acc_m * 100)
        if alt_m is None:
            flags |= 0x40                    # altInv: 2D hint only
        else:
            alt_cm = int(round(alt_m * 100))
    week = tow_ms = t_acc = 0
    if unix_t is not None:
        flags |= 0x02                        # tmValid (GPS week/TOW)
        week, tow_ms = gps_week_tow(unix_t)
        t_acc = int(time_acc_ms)
    payload = struct.pack('<iiiIhHIiIIiII',
                          lat_i, lon_i, alt_cm, pos_acc,
                          0, week, tow_ms, 0, t_acc, 0,
                          0, 0, flags)
    return ubx_frame(CLS_AID, ID_AID_INI, payload)


def mga_ini_pos_frame(lat, lon, alt_m=None, pos_acc_m=POS_ACC_M):
    """UBX-MGA-INI-POS_LLH (u-blox M8/M9/M10)."""
    payload = struct.pack('<BB2xiiiI', 0x01, 0,
                          int(round(lat * 1e7)), int(round(lon * 1e7)),
                          int(round((alt_m or 0) * 100)), int(pos_acc_m * 100))
    return ubx_frame(CLS_MGA, ID_MGA_INI, payload)


def mga_ini_time_frame(unix_t, time_acc_ms=TIME_ACC_MS):
    """UBX-MGA-INI-TIME_UTC (u-blox M8/M9/M10)."""
    dt = datetime.fromtimestamp(unix_t, tz=timezone.utc)
    t_acc_s, t_acc_ms = divmod(int(time_acc_ms), 1000)
    payload = struct.pack('<BBBbHBBBBBxIH2xI', 0x10, 0, 0, GPS_LEAP_SECONDS,
                          dt.year, dt.month, dt.day,
                          dt.hour, dt.minute, dt.second,
                          dt.microsecond * 1000, t_acc_s, t_acc_ms * 1_000_000)
    return ubx_frame(CLS_MGA, ID_MGA_INI, payload)


def poll_frames():
    """Polls that make the receiver dump what it knows (all SVs)."""
    return [ubx_frame(CLS_AID, ID_AID_HUI),
            ubx_frame(CLS_AID, ID_AID_ALM),
            ubx_frame(CLS_AID, ID_AID_EPH)]


# ── Orbit-data store ────────────────────────────────────────────────────────

def load_store(path):
    try:
        with open(path) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        logger.debug(f"GPS aid store unreadable ({e}); ignoring")
        return {}


def update_store(store, frames, now):
    """Merge polled AID frames into the store, per satellite.

    Merging (not replacing) matters: the receiver only reports what it holds
    right now, so a poll after it lost a few satellites — or one taken early
    in a drive — would otherwise shrink a fuller set saved earlier. Almanac
    entries are overwritten per SV (newer wins). Ephemeris entries carry their
    own timestamp, since each SV's is only good for ~4 h; entries past that
    are dropped here. Returns (n_alm, n_eph, hui) for THIS poll.
    """
    alm = {}
    eph = {}
    hui = None
    for cls, mid, payload in frames:
        if cls != CLS_AID:
            continue
        if mid == ID_AID_ALM and len(payload) == _ALM_FULL_LEN:
            alm[str(struct.unpack_from('<I', payload)[0])] = payload.hex()
        elif mid == ID_AID_EPH and len(payload) == _EPH_FULL_LEN:
            eph[str(struct.unpack_from('<I', payload)[0])] = payload.hex()
        elif mid == ID_AID_HUI and len(payload) == _HUI_LEN:
            hui = payload.hex()
    if alm:
        store['alm'] = {**(store.get('alm') or {}), **alm}
        store['alm_saved_at'] = now
    if eph or store.get('eph'):
        merged = {}
        for sv, entry in (store.get('eph') or {}).items():
            if isinstance(entry, str):          # pre-merge format: one set time
                entry = {'d': entry, 't': store.get('eph_saved_at') or 0}
            if 0 <= now - entry.get('t', 0) <= EPH_MAX_AGE_S:
                merged[sv] = entry
        for sv, hx in eph.items():
            merged[sv] = {'d': hx, 't': now}
        store['eph'] = merged
        if eph:
            store['eph_saved_at'] = now
    if hui:
        store['hui'] = hui
        store['hui_saved_at'] = now
    return len(alm), len(eph), bool(hui)


def save_store(path, store):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(store, f)
    os.replace(tmp, path)


def build_assist_frames(last_known, now, synced, store=None):
    """Everything worth handing the receiver at start, in u-blox's recommended
    order (INI, HUI, ALM, EPH). Returns (frames, summary list)."""
    frames = []
    summary = []
    lat = lon = alt = None
    if last_known and last_known.get('lat') is not None \
            and last_known.get('lon') is not None:
        lat, lon, alt = last_known['lat'], last_known['lon'], last_known.get('alt')
    t = now if synced else None
    if lat is not None or t is not None:
        frames.append(aid_ini_frame(lat, lon, alt, t))
    if lat is not None:
        frames.append(mga_ini_pos_frame(lat, lon, alt))
        summary.append(f"position {lat:.4f},{lon:.4f} (±{POS_ACC_M // 1000} km)")
    if t is not None:
        frames.append(mga_ini_time_frame(t))
        summary.append("time (NTP)")
    if not store:
        return frames, summary

    # Orbit data goes in with or without NTP. Wardriving boots are usually
    # offline, and a Pi without an RTC then runs on fake-hwclock (the last
    # saved time), so the clock is untrusted — but it is only ever BEHIND real
    # time. An age past the limit on that clock is therefore a real age past
    # the limit: skip it. Anything younger is sent and the receiver decides:
    # it learns GPS time from the first satellite within seconds and checks
    # each ephemeris against its own reference time, ignoring expired ones.
    # A negative age (clock behind the save) only happens on such a clock.
    def fresh(ts, max_age):
        age = now - (ts or 0)
        return age <= max_age and (age >= 0 or not synced)

    if store.get('hui') and fresh(store.get('hui_saved_at'), HUI_MAX_AGE_S):
        frames.append(ubx_frame(CLS_AID, ID_AID_HUI, bytes.fromhex(store['hui'])))
    if store.get('alm') and fresh(store.get('alm_saved_at'), ALM_MAX_AGE_S):
        for hx in store['alm'].values():
            frames.append(ubx_frame(CLS_AID, ID_AID_ALM, bytes.fromhex(hx)))
        summary.append(f"almanac {len(store['alm'])} SV")
    n_eph = 0
    for entry in (store.get('eph') or {}).values():
        if isinstance(entry, str):          # pre-merge format
            entry = {'d': entry, 't': store.get('eph_saved_at') or 0}
        if fresh(entry.get('t'), EPH_MAX_AGE_S):
            frames.append(ubx_frame(CLS_AID, ID_AID_EPH, bytes.fromhex(entry['d'])))
            n_eph += 1
    if n_eph:
        summary.append(f"ephemeris {n_eph} SV"
                       + ("" if synced else " (receiver checks age)"))
    return frames, summary


# ── Transports ──────────────────────────────────────────────────────────────

def _gpsd_control_path():
    for p in GPSD_CONTROL_SOCKETS:
        if os.path.exists(p):
            return p
    return None


def gpsd_write(device, frames, pace=0.05):
    """Write raw frames to a gpsd-owned device through gpsd's control socket
    ("&<device>=<hex>"), so we never fight gpsd for the serial port. Falls
    back to writing the tty directly (Ragnar runs as root, which bypasses
    gpsd's TIOCEXCL). Returns the number of frames accepted."""
    ctl = _gpsd_control_path()
    ok = 0
    for frame in frames:
        sent = False
        if ctl:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect(ctl)
                    s.sendall(f"&{device}={frame.hex()}\n".encode())
                    sent = s.recv(64).startswith(b'OK')
            except Exception as e:
                logger.debug(f"gpsd control write failed: {e}")
        if not sent:
            sent = write_tty(device, [frame], pace=0) == 1
        ok += sent
        time.sleep(pace)
    return ok


def write_tty(device, frames, pace=0.05):
    """Write frames straight to the receiver's tty (no termios changes — a USB
    CDC receiver ignores the line settings, and gpsd's must stay intact)."""
    ok = 0
    try:
        fd = os.open(device, os.O_WRONLY | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError as e:
        logger.debug(f"cannot open {device} for assist: {e}")
        return 0
    try:
        for frame in frames:
            try:
                os.write(fd, frame)
                ok += 1
            except OSError:
                pass
            if pace:
                time.sleep(pace)
    finally:
        os.close(fd)
    return ok


def gpsd_capture(device, polls, seconds=6.0, host='127.0.0.1', port=2947):
    """Send polls to a gpsd-owned receiver and collect the UBX replies from a
    raw (pass-through) gpsd watch. Returns parsed frames."""
    buf = bytearray()
    with socket.create_connection((host, port), timeout=2) as s:
        s.sendall(b'?WATCH={"enable":true,"json":false,"raw":2}\n')
        s.settimeout(0.3)
        try:
            while s.recv(4096):
                pass            # drain the VERSION/DEVICES/WATCH preamble
        except socket.timeout:
            pass
        gpsd_write(device, polls)
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                chunk = s.recv(8192)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
    return parse_ubx_frames(bytes(buf))
