# gps_manager.py
# GPS module support for Ragnar wardriving.
# Supports gpsd (preferred) and direct NMEA serial for USB/native serial GPS receivers.

import os
import re
import time
import glob
import json
import socket
import struct
import threading
import logging

logger = logging.getLogger("GPSManager")

_NMEA_GGA = re.compile(
    r'^\$[A-Z]{2}GGA,'
    r'(?P<time>\d{6}(?:\.\d+)?)?,'
    r'(?P<lat>\d{2,4}\.\d+)?,(?P<lat_dir>[NS])?,'
    r'(?P<lon>\d{3,5}\.\d+)?,(?P<lon_dir>[EW])?,'
    r'(?P<fix>\d),'
    r'(?P<sats>\d+),'
    r'(?P<hdop>[^,]*),'
    r'(?P<alt>[^,]*),(?P<alt_unit>[^,]*),'
)

_NMEA_RMC = re.compile(
    r'^\$[A-Z]{2}RMC,'
    r'(?P<time>\d{6}(?:\.\d+)?)?,'
    r'(?P<status>[AV]),'
    r'(?P<lat>\d{2,4}\.\d+)?,(?P<lat_dir>[NS])?,'
    r'(?P<lon>\d{3,5}\.\d+)?,(?P<lon_dir>[EW])?,'
    r'(?P<speed_knots>[^,]*),'
    r'(?P<course>[^,]*),'
)

_NMEA_GSV_HEADER = re.compile(
    r'^\$(?P<talker>[A-Z]{2})GSV,(?P<total_msgs>\d+),(?P<msg_num>\d+),(?P<in_view>\d+),'
    r'(?P<body>.*?)\*[0-9A-Fa-f]{2}\s*$'
)


UBX_SYNC = b'\xb5\x62'

# Start of a plausible NMEA sentence: '$' + talker/sentence letters + ','
# (e.g. $GPGGA, $GNRMC, $PUBX). Deliberately loose about the exact talker,
# strict that binary noise decoding to a stray '$' does not qualify.
_NMEA_SHAPE = re.compile(r'^\$[A-Z]{4,5}\d*,')


def _ubx_frame(msg_class, msg_id, payload=b''):
    """Build a UBX frame with its 8-bit Fletcher checksum."""
    body = bytes((msg_class, msg_id)) + struct.pack('<H', len(payload)) + payload
    ck_a = ck_b = 0
    for byte in body:
        ck_a = (ck_a + byte) & 0xFF
        ck_b = (ck_b + ck_a) & 0xFF
    return UBX_SYNC + body + bytes((ck_a, ck_b))


def ubx_enable_nmea_frames(save=True):
    """UBX frames that switch a u-blox port from UBX-only to NMEA output.

    Some u-blox receivers (commonly the u-blox 7 USB pucks) ship or end up
    configured to emit only UBX binary. We parse NMEA, so in that state a
    perfectly healthy receiver yields no position at all. This is the standard
    remedy, sent to the receiver over the same serial port:

      CFG-PRT  add NMEA to the port's output mask, keeping UBX so anything
               already speaking UBX (e.g. gpsd) keeps working
      CFG-MSG  explicitly enable GGA/GSA/GSV/RMC in case they were switched off
      CFG-CFG  persist, so the fix survives a replug

    Returned as a list (CFG-PRT first) rather than one blob: the receiver may
    reinitialize the port while applying CFG-PRT and drop bytes that are
    already in flight, so the sender must pace the frames — see
    _recover_from_ubx(), and scripts/gps_set_nmea.py which does the same.
    """
    frames = [
        # portID 3 = USB; mode/baud are ignored there but must be present.
        # outProtoMask bit0=UBX bit1=NMEA -> 0x0003.
        _ubx_frame(0x06, 0x00, struct.pack('<BBHIIHHHH',
                                           3, 0, 0, 0, 0, 0x0007, 0x0003, 0, 0)),
    ]
    for msg_id in (0x00, 0x02, 0x03, 0x04):    # GGA, GSA, GSV, RMC
        frames.append(_ubx_frame(0x06, 0x01, bytes((0xF0, msg_id, 1))))
    if save:
        frames.append(_ubx_frame(0x06, 0x09,
                                 struct.pack('<IIIB', 0, 0x0000FFFF, 0, 0x17)))
    return frames


def ubx_enable_nmea_sequence(save=True):
    """The same frames as one byte string (drift check against the script)."""
    return b''.join(ubx_enable_nmea_frames(save))


def _nmea_to_decimal(raw, direction):
    """Convert NMEA lat/lon (ddmm.mmmm) to decimal degrees."""
    if not raw or not direction:
        return None
    try:
        if direction in ('N', 'S'):
            degrees = int(raw[:2])
            minutes = float(raw[2:])
        else:
            degrees = int(raw[:3])
            minutes = float(raw[3:])
        decimal = degrees + minutes / 60.0
        if direction in ('S', 'W'):
            decimal = -decimal
        return round(decimal, 7)
    except (ValueError, IndexError):
        return None


def _port_is_espressif(port):
    """Return True iff udev reports an Espressif device on `port`.

    Used to distinguish ESP32 companions (Huginn/Piglet) from other serial
    devices that share USB-UART bridge chips (CP210x, CH340) — the chip alone
    isn't enough to identify ESP32, the device-level strings are.
    """
    try:
        import subprocess
        r = subprocess.run(
            ['udevadm', 'info', '-a', port],
            capture_output=True, text=True, timeout=3
        )
        if r.returncode != 0:
            return False
        out = r.stdout.lower()
        return 'espressif' in out
    except Exception:
        return False


def _probe_nmea(dev, timeout_per_baud=1.5):
    """Try common GPS baud rates and look for NMEA sentences.

    Many modules ship at 9600 but Garmin and some older receivers default
    to 4800; u-blox configured for higher data rates can be at 38400 or
    115200. We try each in order until we see a recognizable NMEA prefix
    or run out of options.

    Returns True if NMEA was seen at any baud, False otherwise.
    """
    try:
        import serial as pyserial
    except ImportError:
        return False
    for baud in (9600, 4800, 38400, 115200):
        try:
            with pyserial.Serial(dev, baud, timeout=timeout_per_baud) as ser:
                data = ser.read(512).decode('ascii', errors='ignore')
                if '$GP' in data or '$GN' in data or '$GL' in data:
                    return True
        except Exception:
            continue
    return False


def _try_gpsd(host='127.0.0.1', port=2947, timeout=2):
    """Return an open gpsd socket if gpsd is running and responsive, else None."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(b'?WATCH={"enable":true,"json":true}\n')
        data = sock.recv(2048).decode('utf-8', errors='ignore')
        if '"class"' in data:
            sock.settimeout(None)
            return sock
    except Exception:
        pass
    if sock:
        try:
            sock.close()
        except Exception:
            pass
    return None


def detect_gps_device(exclude_ports=None):
    """Auto-detect a GPS source.

    Detection has four stages, in order of confidence:
      0. gpsd socket — returns the sentinel string 'gpsd' if gpsd is running.
         This avoids port conflicts when gpsd already owns the serial device.
      1. by-id symlinks containing GPS keywords (gps, u-blox, nmea, gnss, …).
      2. by-id symlinks NOT containing known-ESP32 markers — probe for NMEA.
      3. raw ttyACM/ttyUSB/ttyS/ttyAMA — probe for NMEA at multiple bauds.
         Covers native UART ports (e.g. Raspberry Pi /dev/ttyAMA0, /dev/serial0).

    Args:
        exclude_ports: ports to skip outright (e.g. an ESP32 port already
                       claimed by the companion serial listener).
    """
    exclude = set(exclude_ports or [])
    by_id = '/dev/serial/by-id'

    def _resolve(entry):
        return os.path.realpath(os.path.join(by_id, entry))

    # Stage 0: gpsd socket. If gpsd is running it already owns the serial port,
    # so trying to open that port directly would fail. Defer to gpsd instead.
    sock = _try_gpsd()
    if sock:
        sock.close()
        logger.debug("gpsd detected — using gpsd socket")
        return 'gpsd'

    # Build the exclude set first so by-id keyword matches don't accidentally
    # return an Espressif device that just happens to have "gnss" in its
    # product string (rare, but bounded by being explicit).
    if os.path.isdir(by_id):
        for entry in os.listdir(by_id):
            path = _resolve(entry)
            if _port_is_espressif(path):
                exclude.add(path)

    # Stage 1: by-id keyword match (most reliable — udev says it's a GPS).
    if os.path.isdir(by_id):
        for entry in os.listdir(by_id):
            lower = entry.lower()
            if any(kw in lower for kw in ('gps', 'u-blox', 'ublox', 'nmea', 'gnss', 'bn-', 'vk-')):
                path = _resolve(entry)
                if os.path.exists(path) and path not in exclude:
                    return path

    # Stage 2: by-id symlinks that aren't ESP32 — try the NMEA probe on each.
    # Catches modules whose product string doesn't include a GPS keyword
    # (generic CP210x / CH340 / FTDI bridges with no GPS-specific marking).
    if os.path.isdir(by_id):
        for entry in sorted(os.listdir(by_id)):
            path = _resolve(entry)
            if path in exclude or not os.path.exists(path):
                continue
            if _probe_nmea(path):
                return path

    # Stage 3: raw device nodes — covers USB serial, native UART, and Raspberry
    # Pi serial ports (/dev/ttyAMA0, /dev/serial0) that have no by-id symlink.
    candidates = []
    for pattern in ('/dev/ttyACM*', '/dev/ttyUSB*', '/dev/ttyS[0-9]*', '/dev/ttyAMA*'):
        candidates.extend(glob.glob(pattern))
    for fixed in ('/dev/serial0', '/dev/serial1'):
        if os.path.exists(fixed):
            candidates.append(fixed)
    seen = set()
    for dev in sorted(candidates):
        real = os.path.realpath(dev)
        if dev in exclude or real in exclude or real in seen:
            continue
        seen.add(real)
        if _probe_nmea(dev):
            return dev

    return None


class GPSManager:
    """Manages a GPS source (gpsd socket or direct NMEA serial), providing real-time position data."""

    def __init__(self, port=None, baudrate=9600, exclude_ports=None,
                 state_file=None):
        self.port = port
        self.baudrate = baudrate
        self._exclude_ports = set(exclude_ports or [])
        self._serial = None
        self._gpsd_sock = None
        self._use_gpsd = False
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

        # Current GPS state
        self.latitude = None
        self.longitude = None
        self.altitude = None
        self.speed_kmh = None
        self.course = None
        self.fix_quality = 0
        self.satellites = 0
        self.satellites_in_view = 0
        self.snr_max = None
        self.hdop = None
        self.last_update = 0
        self.last_sentence = 0
        self._gsv_by_talker = {}
        # Per-satellite sky view (prn/elev/az/snr) keyed by talker, plus the
        # in-flight accumulator that stitches the multi-message GSV sequence
        # (each sentence carries ≤4 satellites) back into one sweep.
        self._sats_by_talker = {}
        self._gsv_accum = {}
        # Last-known position — the most recent confirmed fix, kept in memory and
        # mirrored to disk so it survives reboots. Lets the sky view place stars
        # from roughly the right spot before this boot's receiver gets its own
        # fix (a u-blox cold start can take minutes). A later real fix always
        # wins; this is only ever a starting point.
        self.state_file = state_file
        self.last_known = None            # {'lat','lon','alt','t'} or None
        self._last_persist = 0.0
        if state_file:
            self._load_last_known()
        # Time-to-first-fix bookkeeping. A cold start has to demodulate the
        # ephemeris (~30 s of uninterrupted reception), so a receiver that keeps
        # browning out or is being desensed shows satellites in view while TTFF
        # never completes. Recording when the reader started and when the first
        # fix landed makes that visible instead of inferred.
        self.start_time = 0
        self.first_fix_time = 0
        self.connected = False
        self.error = None
        # Tracks whether the current position came from an external source
        # (e.g. a USB-connected Piglet companion reporting its own GPS).
        # Set by update_external_fix(); cleared once a local receiver
        # produces a real fix.
        self._external_source = None

    def start(self):
        """Start GPS reading thread."""
        if self._running:
            return

        # Clock TTFF from the moment the reader is asked to run, not from the
        # first sentence — the gap before data arrives is part of the problem
        # when a receiver is struggling.
        self.start_time = time.time()
        self.first_fix_time = 0

        if not self.port:
            self.port = detect_gps_device(exclude_ports=self._exclude_ports)
        if not self.port:
            self.error = "No GPS device detected"
            logger.warning(self.error)
            return False

        if self.port == 'gpsd':
            return self._start_gpsd()
        return self._start_serial()

    def _start_gpsd(self):
        sock = _try_gpsd()
        if not sock:
            self.error = "gpsd not reachable on localhost:2947"
            logger.error(self.error)
            return False
        self._gpsd_sock = sock
        self._use_gpsd = True
        self._running = True
        self.connected = True
        self.error = None
        self._thread = threading.Thread(target=self._read_loop_gpsd, daemon=True, name="gps-reader")
        self._thread.start()
        logger.info("GPS started via gpsd")
        return True

    def _start_serial(self):
        try:
            import serial as pyserial
            self._serial = pyserial.Serial(self.port, self.baudrate, timeout=1)
            self._running = True
            self.connected = True
            self.error = None
            self._thread = threading.Thread(target=self._read_loop, daemon=True, name="gps-reader")
            self._thread.start()
            logger.info(f"GPS started on {self.port} @ {self.baudrate} baud")
            return True
        except ImportError:
            self.error = "pyserial not installed (pip install pyserial)"
            logger.error(self.error)
            return False
        except Exception as e:
            self.error = f"GPS init failed: {e}"
            logger.error(self.error)
            return False

    def stop(self):
        """Stop GPS reading."""
        self._running = False
        self.connected = False
        if self._serial:
            try:
                self._serial.close()
            except Exception:
                pass
            self._serial = None
        if self._gpsd_sock:
            try:
                self._gpsd_sock.close()
            except Exception:
                pass
            self._gpsd_sock = None
        logger.info("GPS stopped")

    def attach(self, port):
        """(Re)point the GPS reader at a serial port — called by the wardriving
        device monitor when a GPS puck is hot-plugged or re-enumerates.

        Idempotent: if already reading that port, do nothing. Prefers gpsd when
        it is running (it owns the serial device). This is what makes GPS
        self-healing — a puck that appears minutes after boot, or bounces
        (disconnect→reconnect), is attached automatically with no restart.
        """
        if not port:
            return False
        target = port
        sock = _try_gpsd()
        if sock:
            try:
                sock.close()
            except Exception:
                pass
            target = 'gpsd'
        if self._running and self.port == target:
            return True
        if self._running:
            self.stop()
        self.port = target
        return self.start()

    def detach(self):
        """Release the current GPS device — called when it is unplugged so the
        monitor can re-attach a fresh one later."""
        was = self.port
        self.stop()
        self.port = None
        self.error = "No GPS device detected"
        if was:
            logger.info(f"GPS detached from {was}")

    def has_fix(self):
        """Return True if GPS has a valid position fix (not stale)."""
        if self.fix_quality <= 0 or self.latitude is None or self.longitude is None:
            return False
        # Consider fix stale after 10 seconds without update
        if self.last_update and (time.time() - self.last_update) > 10:
            return False
        # Stamp TTFF here rather than in each of the GGA / RMC / gpsd paths:
        # this method is the one definition of "we actually have a fix", so
        # every producer would otherwise need the same guard duplicated.
        if not self.first_fix_time:
            self.first_fix_time = time.time()
        return True

    @property
    def ttff_seconds(self):
        """Seconds from reader start to first fix, or None if still searching."""
        if not self.start_time or not self.first_fix_time:
            return None
        return round(self.first_fix_time - self.start_time, 1)

    def get_position(self):
        """Return current position dict (or None if no fix)."""
        if not self.has_fix():
            return None
        with self._lock:
            return {
                'lat': self.latitude,
                'lon': self.longitude,
                'alt': self.altitude,
                'speed_kmh': self.speed_kmh,
                'course': self.course,
                'fix': self.fix_quality,
                'satellites': self.satellites,
                'hdop': self.hdop,
                'timestamp': self.last_update
            }

    def _load_last_known(self):
        """Load the persisted last-known position at startup (best-effort)."""
        try:
            with open(self.state_file) as f:
                d = json.load(f)
            self.last_known = {
                'lat': float(d['lat']), 'lon': float(d['lon']),
                'alt': d.get('alt'), 't': d.get('t'),
            }
            logger.info("GPS last-known position loaded: "
                        f"{self.last_known['lat']:.4f}, {self.last_known['lon']:.4f}")
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"last-known GPS load failed: {e}")

    def _record_position(self, now):
        """Update (and throttle-persist) last-known position. Call under _lock
        at each confirmed-fix point, with self.latitude/longitude already set."""
        if self.latitude is None or self.longitude is None:
            return
        self.last_known = {'lat': self.latitude, 'lon': self.longitude,
                           'alt': self.altitude, 't': now}
        if self.state_file and (now - self._last_persist) > 60:
            self._last_persist = now
            try:
                os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
                tmp = self.state_file + '.tmp'
                with open(tmp, 'w') as f:
                    json.dump(self.last_known, f)
                os.replace(tmp, self.state_file)   # atomic
            except Exception as e:
                logger.debug(f"last-known GPS persist failed: {e}")

    # Talker code -> human constellation name, for the sky view. Shared by the
    # gpsd (SKY) and serial (GSV) paths, both of which key by these codes.
    _TALKER_NAMES = {
        'GP': 'GPS', 'GL': 'GLONASS', 'GA': 'Galileo', 'GB': 'BeiDou',
        'BD': 'BeiDou', 'GQ': 'QZSS', 'GI': 'NavIC', 'GN': 'combined',
    }

    def get_sky_view(self):
        """Per-satellite sky list (constellation / prn / az / elev / snr) for the
        sky-view plot, from the live GSV/SKY bookkeeping. Only satellites with
        both azimuth and elevation (the plottable ones); stale talkers (>30 s)
        are skipped. Cheap enough to poll at ~1 Hz for a live view."""
        now = time.time()
        with self._lock:
            items = [(t, s, ts) for t, (s, ts) in self._sats_by_talker.items()]
        out = []
        for talker, sats, ts in items:
            if ts and now - ts > 30:
                continue
            cons = self._TALKER_NAMES.get(talker, talker)
            for s in sats:
                if s.get('az') is None or s.get('elev') is None:
                    continue
                out.append({
                    'constellation': cons, 'talker': talker,
                    'prn': s.get('prn'), 'az': s.get('az'),
                    'elev': s.get('elev'), 'snr': s.get('snr'),
                })
        return out

    def get_status(self):
        """Return full GPS status dict."""
        with self._lock:
            if self._external_source:
                source = self._external_source
            elif self._use_gpsd:
                source = 'gpsd'
            else:
                source = 'serial'
            return {
                'connected': self.connected,
                'source': source,
                'port': self.port,
                'has_fix': self.has_fix(),
                'fix_quality': self.fix_quality,
                'satellites': self.satellites,
                'satellites_in_view': self.satellites_in_view,
                'snr_max': self.snr_max,
                'hdop': self.hdop,
                # TTFF once fixed; until then, how long we have been searching.
                'ttff_seconds': self.ttff_seconds,
                'searching_seconds': (round(time.time() - self.start_time, 1)
                                      if (self.start_time and not self.first_fix_time)
                                      else None),
                'latitude': self.latitude,
                'longitude': self.longitude,
                'altitude': self.altitude,
                'speed_kmh': self.speed_kmh,
                'course': self.course,
                'last_update': self.last_update,
                'last_sentence': self.last_sentence,
                'last_known': self.last_known,
                'error': self.error
            }

    def update_external_fix(self, lat, lon, alt=None, speed_kmh=None,
                            satellites=None, hdop=None, source='companion'):
        """Inject a position from an external source (e.g. a USB-connected
        Piglet/HuginnESP companion that has its own GPS receiver).

        Lets Ragnar operate as if it had GPS even when no local receiver is
        attached, so BT/cell scans, the gps_track table, and the status UI
        all see a position. A local receiver always wins: if NMEA from the
        directly-attached GPS arrived within the last 5 s we ignore the
        external update.
        """
        if lat is None or lon is None:
            return False
        try:
            lat = float(lat)
            lon = float(lon)
        except (TypeError, ValueError):
            return False
        # Reject the "no fix yet" sentinel many modules emit (0.0, 0.0 is
        # in the Gulf of Guinea — practically never a real wardriving fix).
        if lat == 0.0 and lon == 0.0:
            return False
        now = time.time()
        # Prefer a fresh local fix over an external one. Only skip when the
        # current state actually came from a local receiver (NMEA/gpsd) —
        # otherwise back-to-back external updates would block each other.
        if (self._external_source is None
                and (self._serial is not None or self._gpsd_sock is not None)
                and self.last_update
                and (now - self.last_update) < 5
                and self.fix_quality > 0):
            return False
        with self._lock:
            self.latitude = lat
            self.longitude = lon
            if alt is not None:
                try:
                    self.altitude = float(alt)
                except (TypeError, ValueError):
                    pass
            if speed_kmh is not None:
                try:
                    self.speed_kmh = float(speed_kmh)
                except (TypeError, ValueError):
                    pass
            if satellites is not None:
                try:
                    self.satellites = int(satellites)
                except (TypeError, ValueError):
                    pass
            if hdop is not None:
                try:
                    self.hdop = float(hdop)
                except (TypeError, ValueError):
                    pass
            if self.fix_quality <= 0:
                self.fix_quality = 1
            self.last_update = now
            self._record_position(now)
            self.last_sentence = now
            self.connected = True
            self.error = None
            self._external_source = source
        return True

    def _read_loop_gpsd(self):
        """Background thread: read JSON objects from gpsd and parse position."""
        buf = ''
        while self._running:
            try:
                if not self._gpsd_sock:
                    self._reconnect_gpsd()
                    continue
                chunk = self._gpsd_sock.recv(4096).decode('utf-8', errors='ignore')
                if not chunk:
                    raise ConnectionError("gpsd closed connection")
                buf += chunk
                while '\n' in buf:
                    line, buf = buf.split('\n', 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    cls = obj.get('class')
                    if cls == 'TPV':
                        self._parse_tpv(obj)
                    elif cls == 'SKY':
                        self._parse_sky(obj)
            except Exception as e:
                if self._running:
                    logger.debug(f"gpsd read error: {e}")
                    if self._gpsd_sock:
                        try:
                            self._gpsd_sock.close()
                        except Exception:
                            pass
                        self._gpsd_sock = None
                    with self._lock:
                        self.connected = False
                    self._reconnect_gpsd()

    def _reconnect_gpsd(self):
        """Attempt to reconnect to gpsd."""
        time.sleep(3)
        if not self._running:
            return
        sock = _try_gpsd()
        if sock:
            self._gpsd_sock = sock
            with self._lock:
                self.connected = True
                self.error = None
            logger.info("GPS reconnected via gpsd")
        else:
            with self._lock:
                self.error = "gpsd not reachable"
            time.sleep(5)

    def _parse_tpv(self, obj):
        """Parse a gpsd TPV (Time-Position-Velocity) object."""
        mode = obj.get('mode', 0)  # 1=no fix, 2=2D, 3=3D
        status = obj.get('status', 1)  # 1=normal GPS, 2=DGPS
        now = time.time()
        with self._lock:
            if mode >= 2 and 'lat' in obj and 'lon' in obj:
                self.latitude = obj['lat']
                self.longitude = obj['lon']
                self.altitude = obj.get('alt')
                speed_ms = obj.get('speed')
                self.speed_kmh = round(speed_ms * 3.6, 1) if speed_ms is not None else None
                self.course = obj.get('track')
                self.fix_quality = 2 if status == 2 else 1
                self.hdop = obj.get('hdop') or self.hdop
                self.last_update = now
                self._record_position(now)
                self._external_source = None
            else:
                self.fix_quality = 0
            self.last_sentence = now

    # gpsd gnssid -> NMEA talker code, so the gpsd path keys its per-constellation
    # bookkeeping the same way the direct-NMEA GSV path does (see _parse_nmea).
    _GNSS_TALKER = {0: 'GP', 1: 'SB', 2: 'GA', 3: 'GB', 5: 'GQ', 6: 'GL', 7: 'GI'}

    def _parse_sky(self, obj):
        """Parse a gpsd SKY object: satellite count, HDOP, and — the part that
        used to be missing — the per-constellation breakdown and per-satellite
        sky view. gpsd's SKY carries az/el/ss/gnssid per satellite, the same
        information the NMEA GSV sentences give, so the constellations card and
        the sky-view plot work on gpsd too, not just direct-serial NMEA."""
        now = time.time()
        with self._lock:
            hdop = obj.get('hdop')
            if hdop is not None:
                self.hdop = hdop
            self.last_sentence = now

            # gpsd interleaves DOP-only SKY reports (no `satellites` array) with
            # full ones. Those must NOT zero the counts/constellations — an empty
            # SKY arriving right after a full one was blanking "satellites in
            # view" while the fix and the constellation card stayed populated.
            # Only a SKY that actually carries satellites updates this bookkeeping
            # (mirrors the NMEA path, where non-GSV sentences never zero it).
            sats = obj.get('satellites') or []
            if not sats:
                return

            used = sum(1 for s in sats if s.get('used', False))
            self.satellites = used
            self.satellites_in_view = len(sats)
            snrs = [s.get('ss') for s in sats if isinstance(s.get('ss'), (int, float))]
            self.snr_max = max(snrs) if snrs else None

            # Group gpsd's flat satellite list by constellation. gpsd sends the
            # full in-view list every SKY, so a straight replace per talker (not
            # a merge) is correct.
            by_talker = {}
            for s in sats:
                gid = s.get('gnssid')
                talker = self._GNSS_TALKER.get(gid, 'GN') if gid is not None else 'GN'
                ss, az, el = s.get('ss'), s.get('az'), s.get('el')
                svid = s.get('svid')
                try:
                    prn = int(svid if svid is not None else s.get('PRN'))
                except (TypeError, ValueError):
                    prn = None
                rec = by_talker.setdefault(talker, {'sats': [], 'snr': None})
                rec['sats'].append({
                    'prn': prn,
                    'elev': int(el) if isinstance(el, (int, float)) else None,
                    'az': int(az) if isinstance(az, (int, float)) else None,
                    'snr': int(ss) if isinstance(ss, (int, float)) else None,
                })
                if isinstance(ss, (int, float)):
                    rec['snr'] = ss if rec['snr'] is None else max(rec['snr'], ss)
            for talker, rec in by_talker.items():
                self._gsv_by_talker[talker] = (len(rec['sats']), rec['snr'], now)
                self._sats_by_talker[talker] = (rec['sats'], now)
            # Same 30 s pruning as the NMEA path (ts is the last tuple element).
            for d in (self._gsv_by_talker, self._sats_by_talker):
                for t in [t for t, v in d.items() if now - v[-1] > 30]:
                    del d[t]

    def _read_loop(self):
        """Background thread: read NMEA sentences and parse position."""
        buffer = ''
        while self._running:
            try:
                if not self._serial or not self._serial.is_open:
                    self._reconnect()
                    continue

                raw = self._serial.readline()
                if not raw:
                    continue

                # A u-blox receiver can come up emitting only UBX *binary*
                # frames (every one starts b5 62). We parse NMEA, so that state
                # used to be invisible: healthy receiver, bytes flowing, every
                # one silently dropped by the '$' test below, and the UI stuck
                # on "Searching..." with nothing logged. Say so, once, with the
                # fix — and surface it via get_status()['error'].
                if UBX_SYNC in raw:
                    self._ubx_seen = getattr(self, '_ubx_seen', 0) + 1
                    if self._ubx_seen % 20 == 0 and not getattr(self, '_nmea_seen', 0):
                        self._recover_from_ubx()
                    continue

                line = raw.decode('ascii', errors='ignore').strip()
                # Require real sentence shape ($GPGGA, $GNRMC, $PUBX, ...),
                # not just a leading '$': in a UBX-only stream a binary chunk
                # can decode to a line starting with '$', and one such fluke
                # counted as NMEA would permanently disarm the UBX recovery
                # below while the receiver stays unusable.
                if not _NMEA_SHAPE.match(line):
                    continue

                self._nmea_seen = getattr(self, '_nmea_seen', 0) + 1
                if getattr(self, 'error', None) and 'UBX binary' in str(self.error):
                    with self._lock:          # NMEA is flowing again — clear it
                        self.error = None

                self._parse_nmea(line)

            except Exception as e:
                if self._running:
                    logger.debug(f"GPS read error: {e}")
                    self._reconnect()

    def _recover_from_ubx(self, max_attempts=3):
        """Self-heal a receiver that is emitting UBX binary instead of NMEA.

        Writes the standard CFG-PRT/CFG-MSG/CFG-CFG sequence back over the same
        port. Without this the receiver is silently useless to us — we drop every
        byte and the UI sits on "Searching..." forever — and the fix required a
        human to notice and run scripts/gps_set_nmea.py by hand. Bounded retries
        so a device that ignores the config (or isn't really u-blox) can't turn
        into a write loop; after that we leave the actionable error in place.
        """
        attempts = getattr(self, '_ubx_fix_attempts', 0)
        if attempts >= max_attempts:
            return
        self._ubx_fix_attempts = attempts + 1
        try:
            # Pace the frames like scripts/gps_set_nmea.py does (the path that
            # is proven on real hardware). Applying CFG-PRT can reinitialize
            # the port, and the cheap u-blox 7 clones drop bytes that arrive
            # while that happens — blasting the whole sequence in one write
            # loses the CFG-MSG/CFG-CFG tail on exactly the receivers this
            # recovery exists for.
            frames = ubx_enable_nmea_frames()
            for i, frame in enumerate(frames):
                self._serial.write(frame)
                self._serial.flush()
                time.sleep(0.3 if i == 0 else 0.05)
            logger.warning(
                f"GPS on {self.port} is emitting UBX binary, not NMEA — sent the "
                f"NMEA-enable config (attempt {self._ubx_fix_attempts}/{max_attempts})")
            with self._lock:
                self.error = (
                    "GPS was in UBX binary mode; sent NMEA-enable config. If this "
                    "persists, run: sudo python3 scripts/gps_set_nmea.py "
                    + str(self.port or ''))
        except Exception as e:
            msg = (f"GPS is emitting UBX binary, not NMEA, and the automatic fix "
                   f"failed ({e}). Run: sudo python3 scripts/gps_set_nmea.py "
                   f"{self.port or ''}")
            logger.error(msg)
            with self._lock:
                self.error = msg

    def _reconnect(self):
        """Attempt to reconnect to GPS device."""
        try:
            if self._serial:
                self._serial.close()
        except Exception:
            pass

        with self._lock:
            self.connected = False

        time.sleep(3)

        if not self._running:
            return

        # Try to reopen — use cached port first, re-detect only every 30 s
        try:
            import serial as pyserial
            now = time.time()
            if self.port:
                port = self.port
            elif hasattr(self, '_detect_cache_time') and now - self._detect_cache_time < 30:
                port = self._detect_cache_port
            else:
                port = detect_gps_device()
                self._detect_cache_port = port
                self._detect_cache_time = now
            if port:
                self._serial = pyserial.Serial(port, self.baudrate, timeout=1)
                self.port = port
                # Fresh device state: the u-blox 7 pucks have no battery/flash,
                # so a replugged receiver comes back in whatever mode it ships
                # in (often UBX-only). Stale counters from before the replug
                # would block the UBX recovery exactly when it's needed again.
                self._ubx_seen = 0
                self._nmea_seen = 0
                self._ubx_fix_attempts = 0
                with self._lock:
                    self.connected = True
                    self.error = None
                logger.info(f"GPS reconnected on {port}")
            else:
                with self._lock:
                    self.error = "GPS device lost"
                time.sleep(5)
        except Exception as e:
            with self._lock:
                self.error = f"GPS reconnect failed: {e}"
            time.sleep(5)

    def _parse_nmea(self, line):
        """Parse a single NMEA sentence."""
        now = time.time()

        # GGA — position + fix quality + satellites + altitude
        m = _NMEA_GGA.match(line)
        if m:
            lat = _nmea_to_decimal(m.group('lat'), m.group('lat_dir'))
            lon = _nmea_to_decimal(m.group('lon'), m.group('lon_dir'))
            with self._lock:
                if lat is not None and lon is not None:
                    self.latitude = lat
                    self.longitude = lon
                try:
                    self.fix_quality = int(m.group('fix'))
                except (ValueError, TypeError):
                    self.fix_quality = 0
                try:
                    self.satellites = int(m.group('sats'))
                except (ValueError, TypeError):
                    pass
                try:
                    self.hdop = float(m.group('hdop')) if m.group('hdop') else None
                except (ValueError, TypeError):
                    pass
                try:
                    self.altitude = float(m.group('alt')) if m.group('alt') else None
                except (ValueError, TypeError):
                    pass
                self.last_update = now
                self._record_position(now)
                self.last_sentence = now
                self._external_source = None
            return

        # RMC — position + speed + course
        m = _NMEA_RMC.match(line)
        if m:
            if m.group('status') == 'A':  # Active (valid fix)
                lat = _nmea_to_decimal(m.group('lat'), m.group('lat_dir'))
                lon = _nmea_to_decimal(m.group('lon'), m.group('lon_dir'))
                with self._lock:
                    if lat is not None and lon is not None:
                        self.latitude = lat
                        self.longitude = lon
                        # RMC status 'A' *is* a valid fix. fix_quality was
                        # previously only ever set by GGA, so a receiver that
                        # emits RMC without GGA (or with GGA disabled) parsed a
                        # perfectly good position and then failed has_fix()'s
                        # `fix_quality > 0` test forever — coordinates in hand,
                        # UI stuck on "Searching...". Only promote from 0 so a
                        # richer GGA quality (2=DGPS, 4=RTK) is never downgraded.
                        # Staleness is still enforced by has_fix(): a later 'V'
                        # stops refreshing last_update, so the fix ages out.
                        if not self.fix_quality:
                            self.fix_quality = 1
                    try:
                        knots = float(m.group('speed_knots')) if m.group('speed_knots') else None
                        self.speed_kmh = round(knots * 1.852, 1) if knots is not None else None
                    except (ValueError, TypeError):
                        pass
                    try:
                        self.course = float(m.group('course')) if m.group('course') else None
                    except (ValueError, TypeError):
                        pass
                    self.last_update = now
                    self._record_position(now)
                    self.last_sentence = now
                    self._external_source = None
            else:
                with self._lock:
                    self.last_sentence = now
            return

        m = _NMEA_GSV_HEADER.match(line)
        if m:
            try:
                talker = m.group('talker')
                in_view = int(m.group('in_view'))
                total_msgs = int(m.group('total_msgs'))
                msg_num = int(m.group('msg_num'))
                fields = m.group('body').split(',')
                snr_max = None
                # The body is repeating quads: prn, elev, az, snr. NMEA 4.10+
                # appends a trailing signalID field, so iterate complete quads
                # only (range stops before an odd tail).
                msg_sats = []
                for i in range(0, len(fields) - 3, 4):
                    prn = fields[i].strip()
                    elev = fields[i + 1].strip()
                    az = fields[i + 2].strip()
                    raw = fields[i + 3].strip()
                    try:
                        snr = int(raw) if raw else None
                    except ValueError:
                        snr = None
                    if snr is not None and (snr_max is None or snr > snr_max):
                        snr_max = snr
                    if not prn:
                        continue
                    try:
                        msg_sats.append({
                            'prn': int(prn),
                            'elev': int(elev) if elev else None,
                            'az': int(az) if az else None,
                            'snr': snr,
                        })
                    except ValueError:
                        continue
                with self._lock:
                    # Reset the accumulator on the first message of a sweep and
                    # commit the whole list on the last, so the sky view never
                    # shows a half-populated constellation mid-sequence.
                    if msg_num <= 1:
                        self._gsv_accum[talker] = []
                    self._gsv_accum.setdefault(talker, []).extend(msg_sats)
                    if msg_num >= total_msgs:
                        self._sats_by_talker[talker] = (self._gsv_accum.pop(talker, []), now)

                    prev = self._gsv_by_talker.get(talker, (0, None, 0))
                    merged_snr = snr_max
                    if merged_snr is None:
                        merged_snr = prev[1]
                    elif prev[1] is not None and now - prev[2] < 2:
                        merged_snr = max(merged_snr, prev[1])
                    self._gsv_by_talker[talker] = (in_view, merged_snr, now)
                    stale = [t for t, v in self._gsv_by_talker.items() if now - v[2] > 30]
                    for t in stale:
                        del self._gsv_by_talker[t]
                    for t in [t for t, v in self._sats_by_talker.items()
                              if now - v[1] > 30]:
                        del self._sats_by_talker[t]
                    self.satellites_in_view = sum(v[0] for v in self._gsv_by_talker.values())
                    snrs = [v[1] for v in self._gsv_by_talker.values() if v[1] is not None]
                    self.snr_max = max(snrs) if snrs else None
                    self.last_sentence = now
            except Exception:
                pass
            return

        if line.startswith('$') and len(line) > 6 and line[3:6] in ('VTG', 'GSA', 'GLL', 'TXT'):
            with self._lock:
                self.last_sentence = now
