# wardriving.py
# High-performance wardriving engine for Ragnar.
# Captures WiFi networks with GPS coordinates using external antennas.
# Supports multiple WiFi adapters, exports to WiGLE CSV and KML.

import os
import re
import csv
import json
import time
import uuid
import queue
import sqlite3
import threading
import subprocess
import logging
from datetime import datetime, timezone

logger = logging.getLogger("Wardriving")

# WiGLE CSV header
WIGLE_HEADER = [
    'MAC', 'SSID', 'AuthMode', 'FirstSeen', 'Channel', 'RSSI',
    'CurrentLatitude', 'CurrentLongitude', 'AltitudeMeters', 'AccuracyMeters', 'Type'
]

# Common camera manufacturer MAC OUI prefixes (first 3 bytes)
_CAMERA_OUI = {
    '00:80:F0', '00:62:6E', 'C0:56:E3', '28:57:BE', 'AC:CC:8E',  # Axis
    '00:0F:7C', 'B0:C5:54', '7C:11:CB', '30:71:B2', '4C:BD:8F',  # ACTi, Hikvision
    '44:47:CC', '54:C4:15', 'E0:50:8B', 'C0:06:0C', 'E0:62:90',  # Hikvision
    '44:19:B6', 'D8:36:7A', 'C4:2F:90', '34:EA:34', '58:03:FB',  # Hikvision
    'A0:BD:1D', '3C:EF:8C', '48:EA:63', 'BC:AD:28', 'DC:B8:08',  # Dahua
    '08:ED:ED', '34:E6:D7', '90:02:A9', 'EC:39:18',               # Dahua
    '00:30:53', '00:04:7D', '00:E0:8F', '60:38:E0',               # Vivotek, Bosch
    '78:A5:04', '78:B2:13', 'CC:2D:21', '00:18:AE',               # Samsung, TVT
    '00:09:89', '00:12:9B', '00:14:95',                            # Geovision, Arecont
    '00:1A:07', '00:1C:F0', '00:24:B5', '64:16:66',               # Reolink, Amcrest
    '9C:8E:CD', 'D4:6D:6D', 'EC:71:DB',                           # TP-Link cameras, Foscam
    '1C:69:0D', 'E0:62:90', '00:62:6E',                            # Foscam additional
    'B4:4B:D0', '48:2C:A0',                                        # Uniview
    '7C:1E:06',                                                     # Tiandy
    '18:FB:7B', '7C:DF:A1', 'C8:47:8C',                           # Beken/BK7231 (Tuya — LSC, Imou, cheap cams)
    '50:02:91', 'D8:1A:D5',                                        # Tuya/LSC additional chipsets
}

# SSID substrings (lowercase) that indicate a camera access point.
# Checked case-insensitively against the broadcast SSID.
_CAMERA_SSID_PATTERNS = {
    # Major brands
    'hikvision', 'ezviz', 'reolink', 'dahua', 'imou',
    'foscam', 'amcrest', 'annke', 'uniview', 'tiandy',
    'vivotek', 'hanwha', 'kedacom', 'milesight',
    'vstarcam', 'tenvis', 'sricam', 'hicamera',
    # LSC Smart Connect (Action store brand, Tuya-based)
    'lsc-', 'lsc_', 'lscsmart',
    # TP-Link camera lines
    'tapo', 'tp-link_tapo', 'tplink_tapo',
    # Consumer / cloud cameras
    'wyze', 'arlo', 'blink', 'ring-', 'ring_',
    # Generic IP camera SSIDs used by ODM firmware
    'ipcam', 'ipc-', 'ipc_', 'cctv', 'hcvr',
    'nvr-', 'nvr_', 'dvr-', 'dvr_',
}

# Encryption mapping
_SECURITY_MAP = {
    'WPA3': '[WPA3][ESS]',
    'WPA2': '[WPA2-PSK-CCMP][ESS]',
    'WPA1 WPA2': '[WPA-PSK-TKIP+CCMP][WPA2-PSK-CCMP][ESS]',
    'WPA2 802.1X': '[WPA2-EAP-CCMP][ESS]',
    'WPA1': '[WPA-PSK-TKIP][ESS]',
    'WEP': '[WEP][ESS]',
    '': '[ESS]',
    '--': '[ESS]',
}


def _map_security(security_str):
    """Map nmcli security string to WiGLE-compatible auth mode."""
    if not security_str:
        return '[ESS]'
    s = security_str.strip()
    return _SECURITY_MAP.get(s, f'[{s}][ESS]')


def _freq_to_channel(freq_mhz):
    """Convert WiFi frequency (MHz) to channel number."""
    try:
        freq = int(freq_mhz)
    except (ValueError, TypeError):
        return 0
    # 2.4 GHz
    if 2412 <= freq <= 2484:
        if freq == 2484:
            return 14
        return (freq - 2407) // 5
    # 5 GHz
    if 5170 <= freq <= 5825:
        return (freq - 5000) // 5
    # 6 GHz (WiFi 6E)
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return 0


class WardrivingSession:
    """Represents a single wardriving session with its own SQLite DB."""

    def __init__(self, data_dir, session_id=None):
        self.session_id = session_id or datetime.now().strftime('%Y%m%d_%H%M%S')
        self.data_dir = os.path.join(data_dir, 'wardriving')
        os.makedirs(self.data_dir, exist_ok=True)
        self.db_path = os.path.join(self.data_dir, f'session_{self.session_id}.db')
        self.start_time = time.time()
        self.end_time = None
        self.network_count = 0
        self.unique_bssids = set()
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """Create the session database tables."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=-8000")    # 8 MB cache (safe for Pi Zero 512 MB)
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS networks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bssid TEXT NOT NULL,
                    ssid TEXT DEFAULT '',
                    security TEXT DEFAULT '',
                    channel INTEGER DEFAULT 0,
                    frequency INTEGER DEFAULT 0,
                    rssi INTEGER DEFAULT -100,
                    latitude REAL,
                    longitude REAL,
                    altitude REAL,
                    speed_kmh REAL,
                    hdop REAL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    best_rssi INTEGER DEFAULT -100,
                    best_lat REAL,
                    best_lon REAL,
                    scan_count INTEGER DEFAULT 1,
                    interface TEXT DEFAULT '',
                    band TEXT DEFAULT '2.4GHz',
                    is_camera INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_bssid ON networks(bssid)
            """)
            # Per-interface observation rows — one per (bssid, interface) so we
            # can compare antenna coverage between adapters. The main `networks`
            # table stays one-row-per-bssid (canonical, strongest sample); this
            # sidecar records what each adapter actually saw.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS network_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bssid TEXT NOT NULL,
                    interface TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    best_rssi INTEGER DEFAULT -100,
                    last_rssi INTEGER DEFAULT -100,
                    scan_count INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_obs_bssid_iface
                ON network_observations(bssid, interface)
            """)
            # One-shot backfill for sessions created before observations existed:
            # if the table is empty but networks has rows, seed observations from
            # the canonical interface-of-record. Coverage stats will be degenerate
            # on these old sessions (one interface per BSSID) but at least the
            # per-interface counts won't be silently zero.
            try:
                obs_count = conn.execute(
                    "SELECT COUNT(*) FROM network_observations"
                ).fetchone()[0]
                net_count = conn.execute(
                    "SELECT COUNT(*) FROM networks WHERE interface != ''"
                ).fetchone()[0]
                if obs_count == 0 and net_count > 0:
                    conn.execute("""
                        INSERT OR IGNORE INTO network_observations
                            (bssid, interface, first_seen, last_seen,
                             best_rssi, last_rssi, scan_count)
                        SELECT bssid, interface, first_seen, last_seen,
                               best_rssi, rssi, scan_count
                        FROM networks WHERE interface != ''
                    """)
            except Exception as e:
                logger.debug(f"Observation backfill skipped: {e}")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS bluetooth_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT NOT NULL,
                    name TEXT DEFAULT '',
                    rssi INTEGER DEFAULT -100,
                    device_type TEXT DEFAULT '',
                    latitude REAL,
                    longitude REAL,
                    altitude REAL,
                    best_rssi INTEGER DEFAULT -100,
                    best_lat REAL,
                    best_lon REAL,
                    pending_lat REAL,
                    pending_lon REAL,
                    pending_count INTEGER DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    scan_count INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_bt_mac ON bluetooth_devices(mac)
            """)
            # Migrate older bluetooth_devices tables that lack new columns.
            # SQLite ALTER TABLE doesn't support parameter binding, so we
            # interpolate — but only after asserting names/values match a
            # strict identifier/literal whitelist, so future edits to this
            # list can't accidentally smuggle in unsafe SQL.
            _BT_MIGRATE_COLS = (
                ('best_rssi',     '-100'),
                ('best_lat',      'NULL'),
                ('best_lon',      'NULL'),
                ('pending_lat',   'NULL'),
                ('pending_lon',   'NULL'),
                ('pending_count', '0'),
            )
            for _name, _default in _BT_MIGRATE_COLS:
                assert _name.replace('_', '').isalnum(), f'unsafe column name: {_name!r}'
                assert _default in ('NULL',) or _default.lstrip('-').isdigit(), \
                    f'unsafe default literal: {_default!r}'
            try:
                cols = {r[1] for r in conn.execute("PRAGMA table_info(bluetooth_devices)").fetchall()}
                for col, default in _BT_MIGRATE_COLS:
                    if col not in cols:
                        conn.execute(f"ALTER TABLE bluetooth_devices ADD COLUMN {col} DEFAULT {default}")
            except Exception:
                pass
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cell_towers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cell_id TEXT NOT NULL,
                    mcc TEXT DEFAULT '',
                    mnc TEXT DEFAULT '',
                    lac TEXT DEFAULT '',
                    tech TEXT DEFAULT '',
                    provider TEXT DEFAULT '',
                    signal_dbm INTEGER DEFAULT -120,
                    band_freq TEXT DEFAULT '',
                    latitude REAL,
                    longitude REAL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    scan_count INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_cell ON cell_towers(cell_id)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS gps_track (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    altitude REAL,
                    speed_kmh REAL,
                    satellites INTEGER,
                    hdop REAL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS session_info (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            conn.execute(
                "INSERT OR REPLACE INTO session_info (key, value) VALUES (?, ?)",
                ('start_time', datetime.now(timezone.utc).isoformat())
            )

    def upsert_network(self, bssid, ssid, security, channel, frequency,
                       rssi, lat, lon, alt, speed, hdop, interface=''):
        """Insert or update a discovered network (thread-safe)."""
        # Sanitize SSID: strip null bytes, hex escape sequences, and non-printable chars
        if ssid:
            ssid = ssid.replace('\x00', '')
            # iw outputs literal \x00 sequences (backslash + x + hex) for non-printable SSIDs
            ssid = re.sub(r'\\x[0-9a-fA-F]{2}', '', ssid)
            ssid = ssid.strip()
            # If nothing printable remains, treat as hidden
            if not ssid or all(ord(c) < 32 for c in ssid):
                ssid = ''
        now = datetime.now(timezone.utc).isoformat()
        band = '5GHz' if (frequency and int(frequency) > 4900) else '2.4GHz'
        if frequency and int(frequency) > 5925:
            band = '6GHz'
        # Camera detection: MAC OUI match OR SSID name pattern match
        oui_match = bool(bssid and bssid[:8].upper() in _CAMERA_OUI)
        ssid_lower = (ssid or '').lower()
        ssid_match = any(p in ssid_lower for p in _CAMERA_SSID_PATTERNS)
        is_camera = 1 if (oui_match or ssid_match) else 0

        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    existing = conn.execute(
                        "SELECT rssi, best_rssi, scan_count FROM networks WHERE bssid = ?",
                        (bssid,)
                    ).fetchone()

                    if existing:
                        old_best = existing[1] or -100
                        count = (existing[2] or 0) + 1
                        if rssi > old_best:
                            conn.execute("""
                                UPDATE networks SET
                                    ssid = COALESCE(NULLIF(?, ''), ssid),
                                    security = COALESCE(NULLIF(?, ''), security),
                                    channel = ?, frequency = ?, rssi = ?,
                                    latitude  = COALESCE(?, latitude),
                                    longitude = COALESCE(?, longitude),
                                    altitude  = COALESCE(?, altitude),
                                    speed_kmh = COALESCE(?, speed_kmh),
                                    hdop      = COALESCE(?, hdop),
                                    last_seen = ?, best_rssi = ?,
                                    best_lat  = COALESCE(?, best_lat),
                                    best_lon  = COALESCE(?, best_lon),
                                    scan_count = ?, interface = ?, band = ?
                                WHERE bssid = ?
                            """, (ssid, security, channel, frequency, rssi,
                                  lat, lon, alt, speed, hdop,
                                  now, rssi, lat, lon, count, interface, band, bssid))
                        else:
                            # Update GPS if we have coords now but didn't before
                            if lat and lon:
                                conn.execute("""
                                    UPDATE networks SET
                                        ssid = COALESCE(NULLIF(?, ''), ssid),
                                        security = COALESCE(NULLIF(?, ''), security),
                                        rssi = ?, last_seen = ?, scan_count = ?,
                                        latitude = COALESCE(latitude, ?),
                                        longitude = COALESCE(longitude, ?),
                                        altitude = COALESCE(altitude, ?),
                                        best_lat = COALESCE(best_lat, ?),
                                        best_lon = COALESCE(best_lon, ?)
                                    WHERE bssid = ?
                                """, (ssid, security, rssi, now, count,
                                      lat, lon, alt, lat, lon, bssid))
                            else:
                                conn.execute("""
                                    UPDATE networks SET
                                        ssid = COALESCE(NULLIF(?, ''), ssid),
                                        security = COALESCE(NULLIF(?, ''), security),
                                        rssi = ?, last_seen = ?, scan_count = ?
                                    WHERE bssid = ?
                                """, (ssid, security, rssi, now, count, bssid))
                    else:
                        conn.execute("""
                            INSERT INTO networks
                                (bssid, ssid, security, channel, frequency, rssi,
                                 latitude, longitude, altitude, speed_kmh, hdop,
                                 first_seen, last_seen, best_rssi, best_lat, best_lon,
                                 scan_count, interface, band, is_camera)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                        """, (bssid, ssid, security, channel, frequency, rssi,
                              lat, lon, alt, speed, hdop,
                              now, now, rssi, lat, lon, interface, band, is_camera))
                        self.unique_bssids.add(bssid)
                        self.network_count = len(self.unique_bssids)
                        return True

                    # Per-interface observation row — records what THIS adapter
                    # actually saw, independent of which adapter "owns" the
                    # canonical networks row. Used for antenna-coverage stats.
                    if interface:
                        obs = conn.execute(
                            "SELECT best_rssi, scan_count FROM network_observations "
                            "WHERE bssid = ? AND interface = ?",
                            (bssid, interface)
                        ).fetchone()
                        if obs:
                            obs_best = obs[0] if obs[0] is not None else -100
                            obs_count = (obs[1] or 0) + 1
                            new_best = max(obs_best, rssi)
                            conn.execute(
                                "UPDATE network_observations SET "
                                "last_seen = ?, last_rssi = ?, best_rssi = ?, "
                                "scan_count = ? WHERE bssid = ? AND interface = ?",
                                (now, rssi, new_best, obs_count, bssid, interface)
                            )
                        else:
                            conn.execute(
                                "INSERT INTO network_observations "
                                "(bssid, interface, first_seen, last_seen, "
                                "best_rssi, last_rssi, scan_count) "
                                "VALUES (?, ?, ?, ?, ?, ?, 1)",
                                (bssid, interface, now, now, rssi, rssi)
                            )

            except Exception as e:
                logger.error(f"DB upsert error: {e}")
        return False

    def log_gps_track(self, lat, lon, alt, speed, satellites, hdop):
        """Log a GPS trackpoint."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        "INSERT INTO gps_track (timestamp, latitude, longitude, altitude, speed_kmh, satellites, hdop) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (time.time(), lat, lon, alt, speed, satellites, hdop)
                    )
            except Exception as e:
                logger.debug(f"GPS track log error: {e}")

    # GPS drift threshold: ignore position jumps unless confirmed by
    # multiple consecutive pings at the new location.
    GPS_DRIFT_THRESHOLD_M = 100   # meters — positions closer than this are "same spot"
    GPS_CONFIRM_PINGS = 3         # pings at new position before accepting the move

    @staticmethod
    def _haversine_m(lat1, lon1, lat2, lon2):
        """Approximate distance in meters between two GPS coordinates."""
        from math import radians, sin, cos, sqrt, atan2
        R = 6371000
        dlat = radians(lat2 - lat1)
        dlon = radians(lon2 - lon1)
        a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
        return R * 2 * atan2(sqrt(a), sqrt(1 - a))

    def upsert_bluetooth(self, mac, name, rssi, device_type, lat, lon, alt):
        """Insert or update a discovered Bluetooth device.

        GPS position logic:
        - best_lat/best_lon: position at strongest RSSI (closest sighting)
        - latitude/longitude: confirmed position, updated only after GPS_CONFIRM_PINGS
          consecutive pings at a new location (>GPS_DRIFT_THRESHOLD_M away).
          This filters out GPS drift/jumps while still tracking moving devices.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    existing = conn.execute(
                        """SELECT scan_count, rssi, best_rssi, latitude, longitude,
                                  pending_lat, pending_lon, pending_count
                           FROM bluetooth_devices WHERE mac = ?""", (mac,)
                    ).fetchone()
                    if existing:
                        count = (existing[0] or 0) + 1
                        old_rssi = existing[1] or -100
                        old_best = existing[2] or -100
                        old_lat = existing[3]
                        old_lon = existing[4]
                        pend_lat = existing[5]
                        pend_lon = existing[6]
                        pend_count = existing[7] or 0

                        # Update best position at strongest signal
                        new_best = rssi if rssi > old_best else old_best
                        best_lat_val = lat if (rssi > old_best and lat) else None
                        best_lon_val = lon if (rssi > old_best and lon) else None

                        # GPS drift protection for main lat/lon
                        update_lat = old_lat
                        update_lon = old_lon
                        new_pend_lat = pend_lat
                        new_pend_lon = pend_lon
                        new_pend_count = pend_count

                        if lat and lon:
                            if old_lat is None or old_lon is None:
                                # First GPS fix — accept immediately
                                update_lat = lat
                                update_lon = lon
                                new_pend_lat = None
                                new_pend_lon = None
                                new_pend_count = 0
                            else:
                                dist = self._haversine_m(old_lat, old_lon, lat, lon)
                                if dist < self.GPS_DRIFT_THRESHOLD_M:
                                    # Same area — no change needed, reset pending
                                    new_pend_lat = None
                                    new_pend_lon = None
                                    new_pend_count = 0
                                else:
                                    # New position detected — is it consistent?
                                    if pend_lat is not None and pend_lon is not None:
                                        pend_dist = self._haversine_m(pend_lat, pend_lon, lat, lon)
                                        if pend_dist < self.GPS_DRIFT_THRESHOLD_M:
                                            new_pend_count = pend_count + 1
                                            if new_pend_count >= self.GPS_CONFIRM_PINGS:
                                                # Confirmed move — accept new position
                                                update_lat = lat
                                                update_lon = lon
                                                new_pend_lat = None
                                                new_pend_lon = None
                                                new_pend_count = 0
                                        else:
                                            # Different from pending too — reset pending
                                            new_pend_lat = lat
                                            new_pend_lon = lon
                                            new_pend_count = 1
                                    else:
                                        # Start tracking new candidate position
                                        new_pend_lat = lat
                                        new_pend_lon = lon
                                        new_pend_count = 1

                        conn.execute("""
                            UPDATE bluetooth_devices SET
                                name = COALESCE(NULLIF(?, ''), name),
                                rssi = ?, device_type = COALESCE(NULLIF(?, ''), device_type),
                                latitude = ?, longitude = ?,
                                altitude = COALESCE(?, altitude),
                                best_rssi = ?,
                                best_lat = COALESCE(?, best_lat),
                                best_lon = COALESCE(?, best_lon),
                                pending_lat = ?, pending_lon = ?, pending_count = ?,
                                last_seen = ?, scan_count = ?
                            WHERE mac = ?
                        """, (name, rssi, device_type,
                              update_lat, update_lon, alt,
                              new_best, best_lat_val, best_lon_val,
                              new_pend_lat, new_pend_lon, new_pend_count,
                              now, count, mac))
                    else:
                        conn.execute("""
                            INSERT INTO bluetooth_devices
                                (mac, name, rssi, device_type, latitude, longitude, altitude,
                                 best_rssi, best_lat, best_lon,
                                 pending_lat, pending_lon, pending_count,
                                 first_seen, last_seen, scan_count)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0, ?, ?, 1)
                        """, (mac, name, rssi, device_type, lat, lon, alt,
                              rssi, lat, lon, now, now))
            except Exception as e:
                logger.debug(f"BT upsert error: {e}")
            except Exception as e:
                logger.debug(f"BT upsert error: {e}")

    def upsert_cell_tower(self, cell_id, mcc, mnc, lac, tech, provider,
                          signal_dbm, band_freq, lat, lon):
        """Insert or update a detected cell tower."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    existing = conn.execute(
                        "SELECT scan_count FROM cell_towers WHERE cell_id = ?", (cell_id,)
                    ).fetchone()
                    if existing:
                        count = (existing[0] or 0) + 1
                        conn.execute("""
                            UPDATE cell_towers SET
                                signal_dbm = MAX(signal_dbm, ?), last_seen = ?, scan_count = ?,
                                latitude = COALESCE(?, latitude), longitude = COALESCE(?, longitude)
                            WHERE cell_id = ?
                        """, (signal_dbm, now, count, lat, lon, cell_id))
                    else:
                        conn.execute("""
                            INSERT INTO cell_towers
                                (cell_id, mcc, mnc, lac, tech, provider, signal_dbm, band_freq,
                                 latitude, longitude, first_seen, last_seen, scan_count)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                        """, (cell_id, mcc, mnc, lac, tech, provider, signal_dbm, band_freq,
                              lat, lon, now, now))
            except Exception as e:
                logger.debug(f"Cell upsert error: {e}")

    def get_stats(self):
        """Return session statistics (cached for 5 s to reduce SQLite load)."""
        now = time.time()
        if hasattr(self, '_stats_cache') and self._stats_cache and now - self._stats_cache_time < 5:
            return self._stats_cache
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    # Single query for band + security counts
                    row = conn.execute("""
                        SELECT
                            COUNT(*) AS total,
                            SUM(CASE WHEN security IN ('', '--', 'OWE') THEN 1 ELSE 0 END) AS open_nets,
                            SUM(CASE WHEN security LIKE '%WEP%' THEN 1 ELSE 0 END) AS wep_nets,
                            SUM(CASE WHEN security LIKE '%WPA%' THEN 1 ELSE 0 END) AS wpa_nets,
                            SUM(CASE WHEN band = '2.4GHz' THEN 1 ELSE 0 END) AS band_24,
                            SUM(CASE WHEN band = '5GHz' THEN 1 ELSE 0 END) AS band_5,
                            SUM(CASE WHEN band = '6GHz' THEN 1 ELSE 0 END) AS band_6,
                            SUM(CASE WHEN is_camera = 1 THEN 1 ELSE 0 END) AS cameras
                        FROM networks
                    """).fetchone()
                    total = row['total']
                    open_nets = row['open_nets'] or 0
                    wep_nets = row['wep_nets'] or 0
                    wpa_nets = row['wpa_nets'] or 0
                    band_24 = row['band_24'] or 0
                    band_5 = row['band_5'] or 0
                    band_6 = row['band_6'] or 0
                    camera_count = row['cameras'] or 0
                    strongest = conn.execute("SELECT bssid, ssid, best_rssi FROM networks ORDER BY best_rssi DESC LIMIT 1").fetchone()
                    trackpoints = conn.execute("SELECT COUNT(*) FROM gps_track").fetchone()[0]

                    # Bluetooth and cell counts (tables may not exist in old DBs)
                    bt_count = 0
                    cell_count = 0
                    try:
                        bt_count = conn.execute("SELECT COUNT(*) FROM bluetooth_devices").fetchone()[0]
                    except Exception:
                        pass
                    try:
                        cell_count = conn.execute("SELECT COUNT(*) FROM cell_towers").fetchone()[0]
                    except Exception:
                        pass

                    result = {
                        'session_id': self.session_id,
                        'total_networks': total,
                        'unique_bssids': total,
                        'open_networks': open_nets,
                        'wep_networks': wep_nets,
                        'wpa_networks': wpa_nets,
                        'band_2_4ghz': band_24,
                        'band_5ghz': band_5,
                        'band_6ghz': band_6,
                        'bluetooth_devices': bt_count,
                        'cell_towers': cell_count,
                        'cameras': camera_count,
                        'gps_trackpoints': trackpoints,
                        'strongest': dict(strongest) if strongest else None,
                        'duration_seconds': (self.end_time or time.time()) - self.start_time,
                        'start_time': self.start_time,
                        'db_path': self.db_path
                    }
                    self._stats_cache = result
                    self._stats_cache_time = now
                    return result
            except Exception as e:
                logger.error(f"Stats error: {e}")
                return {'error': str(e)}

    def get_coverage_stats(self, interfaces=None):
        """Antenna-coverage breakdown from network_observations.

        Returns per-interface:
          unique     — distinct BSSIDs this interface ever saw
          only_here  — BSSIDs ONLY this interface saw (no other adapter)
          best_rssi_avg / best_rssi_median — antenna sensitivity proxies
        Plus a global `overlap` (BSSIDs seen by 2+ adapters).

        `interfaces` filters out non-scanner sources like 'esp32-serial' or
        'import' so the comparison only includes live radios.
        """
        out = {'per_interface': {}, 'overlap': 0}
        try:
            with sqlite3.connect(self.db_path) as conn:
                # How many adapters saw each BSSID? Used for only-here + overlap.
                seen_by = {}  # bssid -> set of interfaces
                cur = conn.execute(
                    "SELECT bssid, interface FROM network_observations"
                )
                for bssid, iface in cur:
                    seen_by.setdefault(bssid, set()).add(iface)

                relevant = set(interfaces) if interfaces else None
                # Overlap = BSSIDs seen by 2+ scanner interfaces
                if relevant:
                    out['overlap'] = sum(
                        1 for bs, ifs in seen_by.items()
                        if len(ifs & relevant) >= 2
                    )
                else:
                    out['overlap'] = sum(1 for ifs in seen_by.values() if len(ifs) >= 2)

                cur = conn.execute(
                    "SELECT interface, best_rssi FROM network_observations"
                )
                per = {}
                for iface, rssi in cur:
                    if relevant and iface not in relevant:
                        continue
                    per.setdefault(iface, []).append(rssi if rssi is not None else -100)

                for iface, rssis in per.items():
                    rssis_sorted = sorted(rssis)
                    n = len(rssis_sorted)
                    median = rssis_sorted[n // 2] if n else 0
                    avg = sum(rssis_sorted) / n if n else 0
                    only = 0
                    for bs, ifs in seen_by.items():
                        scanner_ifs = ifs & relevant if relevant else ifs
                        if scanner_ifs == {iface}:
                            only += 1
                    out['per_interface'][iface] = {
                        'unique': n,
                        'only_here': only,
                        'best_rssi_avg': round(avg, 1),
                        'best_rssi_median': median,
                    }
        except Exception as e:
            logger.debug(f"Coverage stats error: {e}")
        return out

    def get_networks(self, limit=500, offset=0, sort_by='best_rssi', order='DESC'):
        """Get paginated network list."""
        allowed_sort = {'best_rssi', 'ssid', 'channel', 'first_seen', 'last_seen', 'scan_count', 'band'}
        if sort_by not in allowed_sort:
            sort_by = 'best_rssi'
        if order.upper() not in ('ASC', 'DESC'):
            order = 'DESC'
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(
                        f"SELECT * FROM networks ORDER BY {sort_by} {order} LIMIT ? OFFSET ?",
                        (limit, offset)
                    ).fetchall()
                    return [dict(r) for r in rows]
            except Exception as e:
                logger.error(f"Get networks error: {e}")
                return []

    def get_bluetooth_devices(self):
        """Get all discovered Bluetooth devices."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(
                        "SELECT * FROM bluetooth_devices ORDER BY rssi DESC"
                    ).fetchall()
                    return [dict(r) for r in rows]
            except Exception:
                return []

    def get_cell_towers(self):
        """Get all discovered cell towers."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(
                        "SELECT * FROM cell_towers ORDER BY signal_dbm DESC"
                    ).fetchall()
                    return [dict(r) for r in rows]
            except Exception:
                return []

    def get_gps_track(self):
        """Return GPS track as list of [lat, lon] points."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    rows = conn.execute(
                        "SELECT latitude, longitude FROM gps_track ORDER BY timestamp"
                    ).fetchall()
                    return [[r[0], r[1]] for r in rows]
            except Exception:
                return []

    def backfill_gps_from_track(self, max_gap_seconds=300):
        """Fill missing positions on networks / BT / cell rows by interpolating
        each row's first_seen timestamp against the gps_track table.

        Handles the typical wardriving GPS gap: device discovered during the
        first ~minutes before fix lock, or during a brief reception dropout.
        Uses linear interpolation when bracketing trackpoints exist within
        max_gap_seconds on both sides; falls back to the nearest single
        trackpoint when only one side is close enough.

        Returns dict {wifi, bluetooth, cells} of row counts backfilled.
        Invalidates the stats cache so subsequent reads reflect new positions.
        """
        import bisect
        result = {'wifi': 0, 'bluetooth': 0, 'cells': 0, 'trackpoints': 0}

        def _parse_iso(s):
            if not s:
                return None
            try:
                return datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp()
            except Exception:
                return None

        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    track = conn.execute(
                        "SELECT timestamp, latitude, longitude, altitude, speed_kmh "
                        "FROM gps_track ORDER BY timestamp"
                    ).fetchall()
                    if not track:
                        return result
                    ts_list = [t['timestamp'] for t in track]
                    result['trackpoints'] = len(track)

                    def _pos_at(epoch):
                        if epoch is None:
                            return None
                        idx = bisect.bisect_left(ts_list, epoch)
                        before = track[idx - 1] if idx > 0 else None
                        after = track[idx] if idx < len(track) else None
                        if before and after:
                            gb = epoch - before['timestamp']
                            ga = after['timestamp'] - epoch
                            if gb <= max_gap_seconds and ga <= max_gap_seconds:
                                span = (after['timestamp'] - before['timestamp']) or 1
                                f_time = max(0.0, min(1.0, (epoch - before['timestamp']) / span))
                                v1 = before['speed_kmh']
                                v2 = after['speed_kmh']
                                if v1 is not None and v2 is not None and (v1 + v2) > 0:
                                    f = (2 * v1 * f_time + (v2 - v1) * f_time * f_time) / (v1 + v2)
                                    f = max(0.0, min(1.0, f))
                                else:
                                    f = f_time
                                lat = before['latitude'] + (after['latitude'] - before['latitude']) * f
                                lon = before['longitude'] + (after['longitude'] - before['longitude']) * f
                                alt = None
                                if before['altitude'] is not None and after['altitude'] is not None:
                                    alt = before['altitude'] + (after['altitude'] - before['altitude']) * f
                                return (lat, lon, alt)
                        cand = before if (before and (epoch - before['timestamp']) <= max_gap_seconds) else None
                        if cand is None and after and (after['timestamp'] - epoch) <= max_gap_seconds:
                            cand = after
                        if cand:
                            return (cand['latitude'], cand['longitude'], cand['altitude'])
                        return None

                    rows = conn.execute(
                        "SELECT bssid, first_seen FROM networks "
                        "WHERE best_lat IS NULL OR best_lon IS NULL"
                    ).fetchall()
                    for r in rows:
                        pos = _pos_at(_parse_iso(r['first_seen']))
                        if pos:
                            conn.execute(
                                "UPDATE networks SET "
                                "latitude = COALESCE(latitude, ?), "
                                "longitude = COALESCE(longitude, ?), "
                                "altitude = COALESCE(altitude, ?), "
                                "best_lat = ?, best_lon = ? WHERE bssid = ?",
                                (pos[0], pos[1], pos[2], pos[0], pos[1], r['bssid'])
                            )
                            result['wifi'] += 1

                    try:
                        rows = conn.execute(
                            "SELECT mac, first_seen FROM bluetooth_devices "
                            "WHERE latitude IS NULL OR longitude IS NULL"
                        ).fetchall()
                        for r in rows:
                            pos = _pos_at(_parse_iso(r['first_seen']))
                            if pos:
                                conn.execute(
                                    "UPDATE bluetooth_devices SET "
                                    "latitude = ?, longitude = ?, "
                                    "altitude = COALESCE(altitude, ?), "
                                    "best_lat = COALESCE(best_lat, ?), "
                                    "best_lon = COALESCE(best_lon, ?) WHERE mac = ?",
                                    (pos[0], pos[1], pos[2], pos[0], pos[1], r['mac'])
                                )
                                result['bluetooth'] += 1
                    except sqlite3.OperationalError:
                        pass

                    try:
                        rows = conn.execute(
                            "SELECT cell_id, first_seen FROM cell_towers "
                            "WHERE latitude IS NULL OR longitude IS NULL"
                        ).fetchall()
                        for r in rows:
                            pos = _pos_at(_parse_iso(r['first_seen']))
                            if pos:
                                conn.execute(
                                    "UPDATE cell_towers SET latitude = ?, longitude = ? "
                                    "WHERE cell_id = ?",
                                    (pos[0], pos[1], r['cell_id'])
                                )
                                result['cells'] += 1
                    except sqlite3.OperationalError:
                        pass

                self._stats_cache_time = 0
                logger.info(
                    f"GPS backfill: wifi={result['wifi']} bt={result['bluetooth']} "
                    f"cells={result['cells']} (using {result['trackpoints']} trackpoints)"
                )
            except Exception as e:
                logger.error(f"GPS backfill error: {e}")
        return result

    def export_wigle_csv(self, device_name='Ragnar'):
        """Export session to WiGLE CSV format string including WiFi, BT, and cell."""
        lines = []
        dn = device_name or 'Ragnar'
        lines.append(f'WigleWifi-1.4,appRelease=Ragnar,model=RaspberryPi,release=1.0,device={dn},display=EPD,board=RPi,brand=Ragnar')
        lines.append(','.join(WIGLE_HEADER))

        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    # WiFi networks
                    rows = conn.execute("SELECT * FROM networks ORDER BY first_seen").fetchall()
                    for row in rows:
                        r = dict(row)
                        lines.append(','.join([
                            r.get('bssid', ''),
                            r.get('ssid', '').replace(',', '\\,'),
                            _map_security(r.get('security', '')),
                            r.get('first_seen', ''),
                            str(r.get('channel', 0)),
                            str(r.get('best_rssi', -100)),
                            str(r.get('best_lat', '') or ''),
                            str(r.get('best_lon', '') or ''),
                            str(r.get('altitude', '') or ''),
                            str(r.get('hdop', '') or ''),
                            'WIFI'
                        ]))
                    # Bluetooth devices
                    try:
                        bt_rows = conn.execute("SELECT * FROM bluetooth_devices ORDER BY first_seen").fetchall()
                        for row in bt_rows:
                            r = dict(row)
                            lines.append(','.join([
                                r.get('mac', ''),
                                r.get('name', '').replace(',', '\\,'),
                                '[BT]',
                                r.get('first_seen', ''),
                                '0',
                                str(r.get('rssi', -100)),
                                str(r.get('latitude', '') or ''),
                                str(r.get('longitude', '') or ''),
                                str(r.get('altitude', '') or ''),
                                '',
                                'BT'
                            ]))
                    except Exception:
                        pass
                    # Cell towers
                    try:
                        cell_rows = conn.execute("SELECT * FROM cell_towers ORDER BY first_seen").fetchall()
                        for row in cell_rows:
                            r = dict(row)
                            lines.append(','.join([
                                r.get('cell_id', ''),
                                f"{r.get('provider', '')} {r.get('tech', '')}".strip().replace(',', '\\,'),
                                f"[{r.get('tech', 'GSM')}]",
                                r.get('first_seen', ''),
                                str(r.get('band_freq', '')),
                                str(r.get('signal_dbm', -120)),
                                str(r.get('latitude', '') or ''),
                                str(r.get('longitude', '') or ''),
                                '',
                                '',
                                'GSM'
                            ]))
                    except Exception:
                        pass
            except Exception as e:
                logger.error(f"WiGLE export error: {e}")

        return '\n'.join(lines)

    def export_kml(self):
        """Export session to KML format for Google Earth."""
        kml_parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<kml xmlns="http://www.opengis.net/kml/2.2">',
            '<Document>',
            f'<name>Ragnar Wardriving - {self.session_id}</name>',
            '<Style id="open"><IconStyle><color>ff00ff00</color><scale>0.8</scale></IconStyle></Style>',
            '<Style id="wep"><IconStyle><color>ff00ffff</color><scale>0.8</scale></IconStyle></Style>',
            '<Style id="wpa"><IconStyle><color>ff0000ff</color><scale>0.8</scale></IconStyle></Style>',
            '<Style id="bt"><IconStyle><color>ffff8800</color><scale>0.6</scale></IconStyle></Style>',
            '<Style id="cell"><IconStyle><color>ff8800ff</color><scale>0.7</scale></IconStyle></Style>',
            '<Style id="camera"><IconStyle><color>ffff0088</color><scale>0.9</scale></IconStyle></Style>',
        ]

        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute("SELECT * FROM networks WHERE best_lat IS NOT NULL").fetchall()
                    for row in rows:
                        r = dict(row)
                        sec = r.get('security', '')
                        style = '#open' if not sec or sec in ('', '--') else ('#wep' if 'WEP' in sec else '#wpa')
                        ssid = (r.get('ssid') or '<hidden>').replace('&', '&amp;').replace('<', '&lt;')
                        kml_parts.append(f'''<Placemark>
<name>{ssid}</name>
<description>BSSID: {r.get("bssid","")}\nSecurity: {sec}\nChannel: {r.get("channel",0)}\nSignal: {r.get("best_rssi",-100)} dBm</description>
<styleUrl>{style}</styleUrl>
<Point><coordinates>{r.get("best_lon",0)},{r.get("best_lat",0)},{r.get("altitude",0) or 0}</coordinates></Point>
</Placemark>''')
            except Exception as e:
                logger.error(f"KML export error: {e}")

        # Add Bluetooth devices
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    bt_rows = conn.execute("SELECT * FROM bluetooth_devices WHERE latitude IS NOT NULL").fetchall()
                    for row in bt_rows:
                        r = dict(row)
                        name = (r.get('name') or r.get('mac', 'Unknown')).replace('&', '&amp;').replace('<', '&lt;')
                        kml_parts.append(f'''<Placemark>
<name>BT: {name}</name>
<description>MAC: {r.get("mac","")}\nType: {r.get("device_type","")}\nRSSI: {r.get("rssi",-100)} dBm</description>
<styleUrl>#bt</styleUrl>
<Point><coordinates>{r.get("longitude",0)},{r.get("latitude",0)},0</coordinates></Point>
</Placemark>''')
            except Exception:
                pass

        # Add Cell towers
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cell_rows = conn.execute("SELECT * FROM cell_towers WHERE latitude IS NOT NULL").fetchall()
                    for row in cell_rows:
                        r = dict(row)
                        kml_parts.append(f'''<Placemark>
<name>Cell: {r.get("provider","")} {r.get("tech","")}</name>
<description>CellID: {r.get("cell_id","")}\nMCC/MNC: {r.get("mcc","")}/{r.get("mnc","")}\nSignal: {r.get("signal_dbm",-120)} dBm</description>
<styleUrl>#cell</styleUrl>
<Point><coordinates>{r.get("longitude",0)},{r.get("latitude",0)},0</coordinates></Point>
</Placemark>''')
            except Exception:
                pass

        # Add GPS track
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    track = conn.execute("SELECT latitude, longitude, altitude FROM gps_track ORDER BY timestamp").fetchall()
                    if track:
                        coords = ' '.join(f'{r[1]},{r[0]},{r[2] or 0}' for r in track)
                        kml_parts.append(f'''<Placemark>
<name>GPS Track</name>
<Style><LineStyle><color>ff0088ff</color><width>3</width></LineStyle></Style>
<LineString><tessellate>1</tessellate><coordinates>{coords}</coordinates></LineString>
</Placemark>''')
            except Exception:
                pass

        kml_parts.extend(['</Document>', '</kml>'])
        return '\n'.join(kml_parts)

    def import_wigle_csv(self, csv_path_or_stream):
        """Import a WiGLE-format CSV file into this session.

        Supports Piglet, HuginnESP, and standard WiGLE CSV exports.
        Returns dict with counts of imported records.
        """
        imported_wifi = 0
        imported_bt = 0
        imported_cell = 0
        skipped = 0

        try:
            # Handle both file path and file-like objects
            if isinstance(csv_path_or_stream, str):
                fh = open(csv_path_or_stream, 'r', encoding='utf-8', errors='replace')
            else:
                fh = csv_path_or_stream

            lines = fh.readlines()
            if hasattr(csv_path_or_stream, 'close') and isinstance(csv_path_or_stream, str):
                fh.close()

            # Skip WiGLE metadata line(s) starting with WigleWifi
            data_lines = []
            header_line = None
            for line in lines:
                stripped = line.strip()
                if stripped.lower().startswith('wigle') or stripped.lower().startswith('#'):
                    continue
                if header_line is None:
                    header_line = stripped
                    continue
                data_lines.append(stripped)

            if not header_line:
                return {'error': 'No CSV header found', 'imported': 0}

            # Parse header - normalize to lowercase
            headers = [h.strip().lower() for h in header_line.split(',')]

            # Map common WiGLE column names
            col_map = {}
            for i, h in enumerate(headers):
                if h in ('mac', 'bssid'):
                    col_map['mac'] = i
                elif h in ('ssid', 'name'):
                    col_map['ssid'] = i
                elif h in ('authmode', 'security', 'encryption'):
                    col_map['auth'] = i
                elif h in ('firstseen', 'first_seen', 'time'):
                    col_map['firstseen'] = i
                elif h in ('channel',):
                    col_map['channel'] = i
                elif h in ('rssi', 'signal', 'level'):
                    col_map['rssi'] = i
                elif h in ('currentlatitude', 'latitude', 'lat'):
                    col_map['lat'] = i
                elif h in ('currentlongitude', 'longitude', 'lon', 'long'):
                    col_map['lon'] = i
                elif h in ('altitudemeters', 'altitude', 'alt'):
                    col_map['alt'] = i
                elif h in ('type',):
                    col_map['type'] = i

            if 'mac' not in col_map:
                return {'error': 'CSV missing MAC/BSSID column', 'imported': 0}

            for line in data_lines:
                if not line:
                    continue
                # CSV parse (handles quoted fields)
                try:
                    row = next(csv.reader([line]))
                except Exception:
                    skipped += 1
                    continue

                if len(row) <= col_map.get('mac', 0):
                    skipped += 1
                    continue

                mac = row[col_map['mac']].strip().upper()
                if not mac or len(mac) < 12:
                    skipped += 1
                    continue

                ssid = row[col_map['ssid']].strip() if 'ssid' in col_map and col_map['ssid'] < len(row) else ''
                auth = row[col_map['auth']].strip() if 'auth' in col_map and col_map['auth'] < len(row) else ''
                channel = 0
                if 'channel' in col_map and col_map['channel'] < len(row):
                    try:
                        channel = int(row[col_map['channel']])
                    except (ValueError, TypeError):
                        pass
                rssi = -80
                if 'rssi' in col_map and col_map['rssi'] < len(row):
                    try:
                        rssi = int(row[col_map['rssi']])
                    except (ValueError, TypeError):
                        pass
                lat = None
                lon = None
                alt = None
                if 'lat' in col_map and col_map['lat'] < len(row):
                    try:
                        lat = float(row[col_map['lat']])
                    except (ValueError, TypeError):
                        pass
                if 'lon' in col_map and col_map['lon'] < len(row):
                    try:
                        lon = float(row[col_map['lon']])
                    except (ValueError, TypeError):
                        pass
                if 'alt' in col_map and col_map['alt'] < len(row):
                    try:
                        alt = float(row[col_map['alt']])
                    except (ValueError, TypeError):
                        pass

                # Determine type
                record_type = ''
                if 'type' in col_map and col_map['type'] < len(row):
                    record_type = row[col_map['type']].strip().upper()

                if record_type in ('BT', 'BLE', 'BLUETOOTH'):
                    self.upsert_bluetooth(mac, ssid, rssi, 'BLE', lat, lon, alt)
                    imported_bt += 1
                elif record_type in ('GSM', 'CDMA', 'LTE', 'UMTS', 'CELL', '5G', 'NR'):
                    self.upsert_cell_tower(
                        cell_id=mac, tech=record_type, provider=ssid,
                        signal_dbm=rssi, lat=lat, lon=lon
                    )
                    imported_cell += 1
                else:
                    # WiFi network
                    freq = 0
                    if channel:
                        if channel <= 14:
                            freq = 2407 + channel * 5
                        elif channel >= 36:
                            freq = 5000 + channel * 5
                    self.upsert_network(
                        bssid=mac, ssid=ssid, security=auth,
                        channel=channel, frequency=freq, rssi=rssi,
                        lat=lat, lon=lon, alt=alt, speed=None, hdop=None,
                        interface='import'
                    )
                    imported_wifi += 1

        except Exception as e:
            logger.error(f"WiGLE CSV import error: {e}")
            return {'error': str(e), 'imported': 0}

        total = imported_wifi + imported_bt + imported_cell
        logger.info(f"WiGLE CSV imported: {imported_wifi} WiFi, {imported_bt} BT, {imported_cell} Cell, {skipped} skipped")
        return {
            'success': True,
            'imported_wifi': imported_wifi,
            'imported_bluetooth': imported_bt,
            'imported_cell': imported_cell,
            'total_imported': total,
            'skipped': skipped
        }

    def close(self):
        """Finalize session."""
        self.end_time = time.time()
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO session_info (key, value) VALUES (?, ?)",
                        ('end_time', datetime.now(timezone.utc).isoformat())
                    )
                    conn.execute(
                        "INSERT OR REPLACE INTO session_info (key, value) VALUES (?, ?)",
                        ('total_networks', str(self.network_count))
                    )
            except Exception:
                pass


class WardrivingEngine:
    """Main wardriving engine that coordinates WiFi scanning and GPS."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.data_dir = getattr(shared_data, 'data_dir', 'data')
        self._running = False
        self._thread = None
        self._bt_thread = None
        self._cell_thread = None
        self._gps = None
        self.session = None
        self.scan_interval = 2  # seconds between scans (fast!)
        self.interfaces = []     # WiFi interfaces to use
        self._iface_zero_scans = {}  # consecutive zero-network scans per interface
        self._iface_prepared = set()  # interfaces successfully brought up at least once
        self._iface_last_error = {}  # most informative scan-failure reason per interface
        self._iface_freq_cache = {}  # cached supported-frequency list per interface
        # Band-splitting: when multiple adapters are present, pin each one to a
        # subset of bands so adapters don't redundantly sweep the same channels.
        # 'redundant' (default) = every adapter sweeps every band it supports.
        # 'split' = round-robin band assignment, one band per adapter.
        self.band_mode = 'redundant'
        self._iface_band_assignment = {}  # iface -> set of allowed bands {'2.4','5','6'}
        self.networks_per_scan = 0
        self.total_networks = 0
        self.scans_completed = 0
        self.last_scan_time = 0
        self.error = None
        self._gps_track_interval = 5  # log GPS position every 5 seconds
        self._last_gps_track = 0
        self.bt_count = 0
        self.cell_count = 0
        self.device_name = ''
        self._serial_thread = None
        self._serial_port = None
        self.serial_connected = False
        self.serial_networks = 0
        self._serial_entry_buffer = {}  # Buffer for multi-line HuginnESP entries
        # WiGLE CSV header tracking — built when we see the column-header row
        # right after a `WigleWifi-X.Y,...` banner from Piglet. Used to map
        # data-row columns by name, so we survive format changes (1.4 → 1.6
        # added Frequency, RCOIs, MfgrId columns and shifted RSSI/Lat/etc.).
        self._wigle_col_map = None      # dict like {'mac': 0, 'ssid': 1, ...}
        self._wigle_expect_header = False  # True for the line right after WigleWifi banner
        self._current_esp_mode = 'wifi'
        self._esp_ble_count = 0
        self._esp_stations = []
        self._companion_name = ''  # 'Huginn', 'Piglet', or 'RagnarBridge'
        self._mesh_node_count = 0  # Piglet Core mesh node count
        # Queue of `set ...\r\n` byte-strings for the listener thread to write
        # to Huginn. Webapp thread enqueues; listener owns the serial handle.
        self._huginn_config_queue = queue.Queue()
        # Per-connection flag: have we pushed the initial Huginn config yet?
        # Reset by the listener on every reconnect so a late-promoted Huginn
        # (detected via [BOOT] line after the handshake window) still gets it.
        self._huginn_handshake_pushed = False
        # ESP-Now coordinator (Piglet Core mode) — created when bridge detected
        self._coordinator = None

    def start(self, interfaces=None, gps_port=None, device_name=None):
        """Start a wardriving session."""
        if self._running:
            return {'error': 'Already running'}

        # Device name from param or config
        self.device_name = device_name or self.shared_data.config.get('wardriving_device_name', '') or ''

        # Detect/validate interfaces
        self.interfaces = interfaces or self._detect_wifi_interfaces()
        if not self.interfaces:
            return {'error': 'No WiFi interfaces found'}

        # Bring each interface up (rfkill unblock + ip link up). USB adapters
        # like the NETGEAR mt76x2u enumerate as admin-DOWN; iw scan on a DOWN
        # interface returns "Network is down" and zero results forever.
        for iface in self.interfaces:
            self._prepare_interface(iface)

        # Compute per-adapter band assignments (only matters when band_mode='split').
        # Must run AFTER _prepare_interface because freq detection reads iw phy info,
        # which can fail on a wedged/down interface.
        self.band_mode = (self.shared_data.config.get('wardriving_band_mode', 'redundant')
                          or 'redundant').lower()
        if self.band_mode not in ('redundant', 'split'):
            self.band_mode = 'redundant'
        self._iface_freq_cache.clear()  # force re-detection with new assignments
        self._compute_band_assignments()

        # Pre-detect ESP32 companion port BEFORE GPS auto-detection so we can
        # exclude it. This prevents GPS from opening the ESP32's serial port
        # and stealing bytes (which causes GPS to report 0 sats and the serial
        # listener to mis-classify the device).
        #
        # IMPORTANT: only trust the saved `wardriving_serial_port` config if
        # udev STILL says it's an Espressif device. Stale values from prior
        # sessions (e.g. ttyACM0 was once an ESP32, now it's a GPS) would
        # otherwise blindly exclude the GPS port and make detection silently
        # fail. Verifying before adding fixes a bug where GPS auto-detect
        # returns None despite the device being properly enumerated.
        saved_serial_port = self.shared_data.config.get('wardriving_serial_port', '')
        verified_saved = (
            saved_serial_port
            and os.path.exists(saved_serial_port)
            and self._port_is_espressif(saved_serial_port)
        )
        if saved_serial_port and not verified_saved:
            logger.info(
                f"Saved wardriving_serial_port={saved_serial_port} is no longer an "
                f"Espressif device; not using it as a GPS exclude"
            )
        pre_detected_esp = self._detect_esp32_serial() if not verified_saved else None
        esp_exclude = set()
        if verified_saved:
            esp_exclude.add(saved_serial_port)
        if pre_detected_esp:
            esp_exclude.add(pre_detected_esp)
        # Keep the rest of the start() flow working with the local `serial_port`
        # variable it expects — only the *verified* value is allowed through.
        serial_port = saved_serial_port if verified_saved else ''

        # Start GPS (exclude known ESP32 ports from probing)
        from gps_manager import GPSManager
        # Treat "auto" or empty string as None to trigger auto-detection
        if gps_port and gps_port.lower() == 'auto':
            gps_port = None
        self._gps = GPSManager(port=gps_port, exclude_ports=esp_exclude)
        gps_ok = self._gps.start()
        if not gps_ok:
            logger.warning(f"GPS not available: {self._gps.error}. Wardriving without GPS.")

        # Create session
        self.session = WardrivingSession(self.data_dir)
        self._running = True
        self.error = None
        self.scans_completed = 0
        self.bt_count = 0
        self.cell_count = 0

        # Save device name and session info
        if self.device_name:
            try:
                with sqlite3.connect(self.session.db_path) as conn:
                    conn.execute("INSERT OR REPLACE INTO session_info (key, value) VALUES (?, ?)",
                                 ('device_name', self.device_name))
            except Exception:
                pass

        # Start scanning threads
        self._thread = threading.Thread(target=self._scan_loop, daemon=True, name="wardriving")
        self._thread.start()

        # Start Bluetooth scanning thread
        self._bt_thread = threading.Thread(target=self._bt_scan_loop, daemon=True, name="wardriving-bt")
        self._bt_thread.start()

        # Start cell scanning thread
        self._cell_thread = threading.Thread(target=self._cell_scan_loop, daemon=True, name="wardriving-cell")
        self._cell_thread.start()

        # Start serial ESP32 listener (Piglet/HuginnESP) - auto-detect or use configured port.
        # Guards against two real failure modes seen in practice:
        #   1. Same port as GPS: opening /dev/ttyACM0 twice makes both threads read
        #      half the bytes each. GPS reports 0 satellites; serial listener parses
        #      NMEA as garbage and mis-classifies the device as Piglet.
        #   2. Stale saved port: shared_data.config holds a port from a previous
        #      session, but the ESP32 has been unplugged. Re-verify via udevadm.
        serial_port = self.shared_data.config.get('wardriving_serial_port', '')
        gps_port = self._gps.port if self._gps else None
        if serial_port and serial_port == gps_port:
            logger.info(f"Serial listener skipped: {serial_port} is already in use by GPS")
            serial_port = ''
        if not serial_port:
            serial_port = self._detect_esp32_serial()
        else:
            # Saved port — confirm an Espressif device is actually still there.
            verified = self._detect_esp32_serial()
            if verified and verified != serial_port:
                logger.info(f"Saved serial_port {serial_port} doesn't match detected {verified}; using detected")
                serial_port = verified
            elif not verified:
                # No Espressif on any port. Try udev directly on the saved port
                # so we don't false-negative when the saved port still works.
                if not self._port_is_espressif(serial_port):
                    logger.info(f"Saved serial_port {serial_port} no longer has an ESP32; skipping serial listener")
                    serial_port = ''
        if serial_port and serial_port == gps_port:
            # Re-check after auto-detection in case it picked up the GPS port.
            logger.warning(f"Serial detect returned GPS port {serial_port}; skipping serial listener")
            serial_port = ''
        if serial_port:
            self._serial_port = serial_port
            self.shared_data.config['wardriving_serial_port'] = serial_port
            self._serial_thread = threading.Thread(target=self._serial_listen_loop, daemon=True, name="wardriving-serial")
            self._serial_thread.start()
            logger.info(f"HuginnESP/Piglet auto-detected on {serial_port}")

        logger.info(f"Wardriving started: interfaces={self.interfaces}, GPS={gps_ok}, device={self.device_name}")
        return {
            'success': True,
            'session_id': self.session.session_id,
            'interfaces': self.interfaces,
            'gps_available': gps_ok,
            'gps_port': self._gps.port if gps_ok else None
        }

    def stop(self):
        """Stop the current wardriving session."""
        if not self._running:
            return {'error': 'Not running'}

        self._running = False
        if self.session:
            self.session.close()
        if self._gps:
            self._gps.stop()
            # Drop the reference so a fresh probe runs next time get_status() or
            # start() is called. Otherwise the stale GPSManager (with any error
            # it accumulated during the prior session — e.g. "No GPS device
            # detected" from a session where the receiver wasn't plugged in
            # yet) is what callers see, even after the user plugs in the GPS.
            self._gps = None
        # Force re-probe on the next status call instead of serving cached
        # "not detected" from before the user plugged in the receiver.
        if hasattr(self, '_gps_probe_cache'):
            self._gps_probe_cache = None
            self._gps_probe_time = 0

        stats = self.session.get_stats() if self.session else {}
        logger.info(f"Wardriving stopped. Networks: {stats.get('total_networks', 0)}")
        return {'success': True, 'stats': stats}

    def start_serial(self, port):
        """Start serial listener on the given port."""
        if self._serial_thread and self._serial_thread.is_alive():
            return {'error': 'Serial already running'}
        # Refuse to open the GPS port — would cause both threads to fight for
        # the same tty bytes (GPS reports 0 sats, listener mis-classifies).
        gps_port = self._gps.port if self._gps else None
        if gps_port and port == gps_port:
            return {'error': f'Port {port} is already in use by GPS'}
        self._serial_port = port
        self._running_serial = True
        self._serial_thread = threading.Thread(target=self._serial_listen_loop, daemon=True, name="wardriving-serial")
        self._serial_thread.start()
        return {'success': True, 'port': port}

    def stop_serial(self):
        """Stop the serial listener."""
        self._serial_port = None
        self.serial_connected = False
        return {'success': True}

    # ------------------------------------------------------------------
    # Huginn runtime config push (matches HuginnESP src/runtime_config.cpp).
    # Knobs:
    #   wifi_scan_duration_ms : 500..600000  (firmware default 15000)
    #   ble_spam_threshold    : 1..10000     (firmware default 20)
    #   skimmer_names         : CSV string   (firmware has built-in defaults)
    # Firmware state is RAM-only and reapplies on every reboot, so we re-push
    # at every reconnect from shared_data.config.
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_huginn_values(values):
        out = {}
        if 'wifi_scan_duration_ms' in values and values['wifi_scan_duration_ms'] is not None:
            try:
                v = int(values['wifi_scan_duration_ms'])
            except (TypeError, ValueError):
                return None, 'wifi_scan_duration_ms must be an integer'
            if v < 500 or v > 600000:
                return None, 'wifi_scan_duration_ms out of range (500..600000)'
            out['wifi_scan_duration_ms'] = v
        if 'ble_spam_threshold' in values and values['ble_spam_threshold'] is not None:
            try:
                v = int(values['ble_spam_threshold'])
            except (TypeError, ValueError):
                return None, 'ble_spam_threshold must be an integer'
            if v < 1 or v > 10000:
                return None, 'ble_spam_threshold out of range (1..10000)'
            out['ble_spam_threshold'] = v
        if 'skimmer_names' in values and values['skimmer_names'] is not None:
            raw = values['skimmer_names']
            if isinstance(raw, list):
                names = [str(n).strip() for n in raw if str(n).strip()]
            else:
                names = [s.strip() for s in str(raw).split(',') if s.strip()]
            for n in names:
                if ',' in n or '\r' in n or '\n' in n:
                    return None, f'skimmer_names: invalid entry {n!r}'
            out['skimmer_names'] = ','.join(names)
        return out, None

    def get_huginn_config(self):
        """Return current Huginn knobs from shared_data.config (with firmware defaults)."""
        cfg = self.shared_data.config
        return {
            'wifi_scan_duration_ms': cfg.get('huginn_wifi_scan_duration_ms', 15000),
            'ble_spam_threshold':    cfg.get('huginn_ble_spam_threshold', 20),
            'skimmer_names':         cfg.get('huginn_skimmer_names', ''),
            'companion':             self._companion_name,
            'connected':             bool(self.serial_connected),
        }

    def push_huginn_config(self, values):
        """Validate, persist and queue Huginn `set ...` commands.

        Webapp thread calls this. The serial listener thread drains the queue
        and writes to the device; we never touch the serial handle here.
        """
        clean, err = self._validate_huginn_values(values or {})
        if err:
            return {'error': err}
        if not clean:
            return {'error': 'no values supplied'}

        # Persist user choices so they re-push on the next reconnect.
        cfg = self.shared_data.config
        if 'wifi_scan_duration_ms' in clean:
            cfg['huginn_wifi_scan_duration_ms'] = clean['wifi_scan_duration_ms']
        if 'ble_spam_threshold' in clean:
            cfg['huginn_ble_spam_threshold'] = clean['ble_spam_threshold']
        if 'skimmer_names' in clean:
            cfg['huginn_skimmer_names'] = clean['skimmer_names']
        try:
            self.shared_data.save_config()
        except Exception as e:
            logger.warning(f"Huginn config: save_config failed: {e}")

        queued = []
        if self.serial_connected and self._companion_name == 'Huginn':
            for line in self._huginn_lines_from(clean):
                self._huginn_config_queue.put(line)
                queued.append(line.decode('ascii', errors='replace').strip())

        return {
            'success': True,
            'saved': clean,
            'queued': queued,
            'live': bool(queued),
        }

    @staticmethod
    def _huginn_lines_from(clean):
        lines = []
        if 'wifi_scan_duration_ms' in clean:
            lines.append(f"set wifi_scan_duration_ms {clean['wifi_scan_duration_ms']}\r\n".encode('ascii'))
        if 'ble_spam_threshold' in clean:
            lines.append(f"set ble_spam_threshold {clean['ble_spam_threshold']}\r\n".encode('ascii'))
        if 'skimmer_names' in clean:
            lines.append(f"set skimmer_names {clean['skimmer_names']}\r\n".encode('ascii'))
        return lines

    def _huginn_initial_push_lines(self):
        """Build the handshake push from shared_data.config — only keys the
        user has actually set (missing keys leave firmware defaults alone)."""
        cfg = self.shared_data.config
        clean = {}
        if 'huginn_wifi_scan_duration_ms' in cfg:
            clean['wifi_scan_duration_ms'] = cfg['huginn_wifi_scan_duration_ms']
        if 'huginn_ble_spam_threshold' in cfg:
            clean['ble_spam_threshold'] = cfg['huginn_ble_spam_threshold']
        if 'huginn_skimmer_names' in cfg and cfg['huginn_skimmer_names']:
            clean['skimmer_names'] = cfg['huginn_skimmer_names']
        validated, _ = self._validate_huginn_values(clean)
        return self._huginn_lines_from(validated or {})

    def _drain_huginn_queue(self, ser):
        """Write any pending `set ...` lines to the serial device. Caller owns
        the serial handle. Reads briefly after each write to consume the
        firmware's `{"ok":...}` reply so it doesn't bleed into scan parsing."""
        sent = 0
        while True:
            try:
                line = self._huginn_config_queue.get_nowait()
            except queue.Empty:
                break
            try:
                ser.write(line)
                sent += 1
                # Give firmware a moment, then drain the JSON reply.
                time.sleep(0.1)
                try:
                    reply = ser.read(ser.in_waiting or 0)
                    if reply:
                        logger.info(f"Huginn config: {line.strip()!r} -> {reply!r}")
                except Exception:
                    pass
            except Exception as e:
                logger.warning(f"Huginn config write failed: {e}")
                # Put it back so we retry on the next reconnect.
                self._huginn_config_queue.put(line)
                break
        return sent

    def _detect_esp32_serial(self):
        """Auto-detect an Espressif ESP32 on /dev/ttyACM* or /dev/ttyUSB*."""
        import glob
        candidates = glob.glob('/dev/ttyACM*') + glob.glob('/dev/ttyUSB*')
        # Don't ever return the GPS port — it'd cause a tty collision.
        gps_port = self._gps.port if self._gps else None
        for port in sorted(candidates):
            if gps_port and port == gps_port:
                continue
            if self._port_is_espressif(port):
                logger.info(f"ESP32 detected on {port}")
                return port
        return None

    @staticmethod
    def _port_is_espressif(port):
        """Return True if udev says the device on `port` is an Espressif USB-serial."""
        try:
            result = subprocess.run(
                ['udevadm', 'info', '-a', port],
                capture_output=True, text=True, timeout=3
            )
            return 'Espressif' in result.stdout or 'espressif' in result.stdout.lower()
        except Exception:
            return False

    def _get_interface_info(self, iface):
        """Get detailed info about a WiFi interface (bands, manufacturer, USB/built-in)."""
        info = {'name': iface, 'bands': [], 'manufacturer': '', 'driver': '', 'is_usb': False, 'networks': 0}
        try:
            # Driver
            driver_link = f'/sys/class/net/{iface}/device/driver'
            if os.path.islink(driver_link):
                info['driver'] = os.path.basename(os.readlink(driver_link))
            # USB check
            device_path = os.path.realpath(f'/sys/class/net/{iface}/device')
            info['is_usb'] = '/usb' in device_path
            # Manufacturer from udev
            try:
                result = subprocess.run(
                    ['udevadm', 'info', '-a', f'/sys/class/net/{iface}'],
                    capture_output=True, text=True, timeout=3
                )
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('ATTRS{manufacturer}=='):
                        val = line.split('==', 1)[1].strip('"')
                        if val and val.lower() not in ('linux', 'usb', ''):
                            info['manufacturer'] = val
                            break
                    elif line.startswith('ATTRS{product}==') and not info.get('product'):
                        val = line.split('==', 1)[1].strip('"')
                        if val:
                            info['product'] = val
            except Exception:
                pass
            # Supported bands from iw phy
            phy_path = f'/sys/class/net/{iface}/phy80211/name'
            if os.path.exists(phy_path):
                with open(phy_path) as f:
                    phy = f.read().strip()
                try:
                    result = subprocess.run(
                        ['iw', 'phy', phy, 'info'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        output = result.stdout
                        if 'Band 1:' in output or '2412 MHz' in output:
                            info['bands'].append('2.4GHz')
                        if 'Band 2:' in output or '5180 MHz' in output:
                            info['bands'].append('5GHz')
                        if 'Band 4:' in output or '5955 MHz' in output:
                            info['bands'].append('6GHz')
                except Exception:
                    pass
            if not info['bands']:
                info['bands'] = ['2.4GHz']  # Safe default
            # Per-interface network count from observations (truthful per-adapter
            # count, independent of which adapter wrote the canonical row last).
            if self.session:
                try:
                    with sqlite3.connect(self.session.db_path) as conn:
                        row = conn.execute(
                            "SELECT COUNT(*) FROM network_observations WHERE interface=?",
                            (iface,)
                        ).fetchone()
                        info['networks'] = row[0] if row else 0
                except Exception:
                    pass
            # If scans are failing, surface the last kernel error so the UI can
            # show *why* this adapter is at zero (e.g. EOPNOTSUPP, "Network is
            # down", "Resource busy"). Empty when scans are succeeding.
            err = self._iface_last_error.get(iface) if hasattr(self, '_iface_last_error') else None
            if err and info.get('networks', 0) == 0:
                info['scan_error'] = err
            info['current_type'] = self._iface_type(iface)
            # Bands this adapter is actively sweeping (matters in split mode).
            assigned = self._iface_band_assignment.get(iface)
            if assigned:
                info['sweep_bands'] = sorted(assigned)
        except Exception as e:
            logger.debug(f"Interface info error for {iface}: {e}")
        return info

    def get_interface_details(self):
        """Get details for all active WiFi interfaces (for UI display)."""
        details = []
        for iface in self.interfaces:
            details.append(self._get_interface_info(iface))
        return details

    def is_running(self):
        return self._running

    def get_status(self):
        """Get current wardriving status."""
        # GPS status: use live GPS if running, otherwise probe for device (cached)
        # Only trust the live GPSManager while wardriving is actually running.
        # Otherwise its state can be stale ("No GPS device detected" from a
        # session where the receiver wasn't plugged in yet would persist even
        # after the user plugs it in). Falling through to the probe path on
        # the !running case ensures the status reflects current hardware.
        if self._gps and self._running:
            gps_status = self._gps.get_status()
        else:
            now = time.time()
            if not hasattr(self, '_gps_probe_cache') or now - self._gps_probe_time > 15:
                from gps_manager import detect_gps_device
                try:
                    esp_port = self._serial_port or ''
                    detected = detect_gps_device(exclude_ports={esp_port} if esp_port else None)
                except Exception:
                    detected = None
                self._gps_probe_cache = detected
                self._gps_probe_time = now
            detected = self._gps_probe_cache
            gps_status = {
                'connected': bool(detected),
                'port': detected,
                'has_fix': False,
                'error': None if detected else 'No GPS device detected',
            }

        result = {
            'running': self._running,
            'session_id': self.session.session_id if self.session else None,
            'interfaces': self.interfaces,
            'scans_completed': self.scans_completed,
            'networks_this_scan': self.networks_per_scan,
            'total_networks': self.total_networks,
            'last_scan_time': self.last_scan_time,
            'error': self.error,
            'gps': gps_status,
            'bluetooth_count': self.bt_count,
            'cell_count': self.cell_count,
            'device_name': self.device_name,
            'serial_connected': self.serial_connected,
            'serial_port': self._serial_port or '',
            'serial_networks': self.serial_networks,
            'companion_name': self._companion_name,
            'mesh_node_count': self._mesh_node_count,
            'coordinator': self._coordinator.get_status() if self._coordinator else None,
            'esp_mode': getattr(self, '_current_esp_mode', ''),
            'esp_ble_count': getattr(self, '_esp_ble_count', 0),
            'esp_alerts': getattr(self, '_esp_alerts', [])[-5:],  # Last 5 alerts
            'band_mode': self.band_mode,
        }
        # Interface details (cached 30s — sysfs/udev calls are slow)
        now_if = time.time()
        if self._running and self.interfaces:
            if not hasattr(self, '_iface_cache') or not self._iface_cache or \
               now_if - getattr(self, '_iface_cache_time', 0) > 30:
                self._iface_cache = self.get_interface_details()
                self._iface_cache_time = now_if
            else:
                # Update only the per-interface network counts (cheap DB query)
                if self.session:
                    try:
                        with sqlite3.connect(self.session.db_path) as conn:
                            for d in self._iface_cache:
                                row = conn.execute(
                                    "SELECT COUNT(*) FROM network_observations WHERE interface=?",
                                    (d['name'],)
                                ).fetchone()
                                d['networks'] = row[0] if row else 0
                    except Exception:
                        pass
            result['interface_details'] = self._iface_cache
            # Antenna-coverage breakdown for live scanner interfaces only.
            # Excludes import/esp32-serial sources so the comparison is fair.
            if self.session:
                result['coverage'] = self.session.get_coverage_stats(
                    interfaces=self.interfaces
                )
        else:
            result['interface_details'] = []
        if self.session:
            result['stats'] = self.session.get_stats()
            try:
                with sqlite3.connect(self.session.db_path) as conn:
                    # Unique ESP32-only networks (found by esp32-serial but not by wlan)
                    row = conn.execute(
                        "SELECT COUNT(DISTINCT bssid) FROM networks WHERE interface='esp32-serial'"
                    ).fetchone()
                    result['serial_unique'] = row[0] if row else 0
                    # Unique BLE devices detected via Huginn (overrides running line counter
                    # so the status bar matches what Huginn actually sees, not stream volume)
                    try:
                        row = conn.execute(
                            "SELECT COUNT(*) FROM bluetooth_devices "
                            "WHERE device_type IN ('BLE','Flipper','AirTag','Skimmer')"
                        ).fetchone()
                        result['esp_ble_count'] = row[0] if row else 0
                    except Exception:
                        pass
            except Exception:
                result['serial_unique'] = 0
        return result

    def get_session_list(self):
        """List all saved wardriving sessions."""
        wd_dir = os.path.join(self.data_dir, 'wardriving')
        if not os.path.isdir(wd_dir):
            return []
        sessions = []
        for f in sorted(os.listdir(wd_dir), reverse=True):
            if f.startswith('session_') and f.endswith('.db'):
                sid = f[8:-3]  # strip 'session_' and '.db'
                db_path = os.path.join(wd_dir, f)
                size = os.path.getsize(db_path)
                try:
                    with sqlite3.connect(db_path) as conn:
                        conn.row_factory = sqlite3.Row
                        total = conn.execute("SELECT COUNT(*) FROM networks").fetchone()[0]
                        info = {}
                        for row in conn.execute("SELECT key, value FROM session_info").fetchall():
                            info[row[0]] = row[1]
                    sessions.append({
                        'session_id': sid,
                        'db_path': db_path,
                        'file_size': size,
                        'total_networks': total,
                        'start_time': info.get('start_time', ''),
                        'end_time': info.get('end_time', ''),
                    })
                except Exception:
                    sessions.append({'session_id': sid, 'error': 'corrupt'})
        return sessions

    def wipe_all_data(self):
        """Delete all wardriving session databases. Requires wardriving to be stopped."""
        if self._running:
            return {'error': 'Cannot wipe data while wardriving is running. Stop first.'}
        wd_dir = os.path.join(self.data_dir, 'wardriving')
        if not os.path.isdir(wd_dir):
            return {'success': True, 'deleted': 0}
        deleted = 0
        for f in os.listdir(wd_dir):
            if f.startswith('session_') and f.endswith(('.db', '.db-wal', '.db-shm')):
                try:
                    os.remove(os.path.join(wd_dir, f))
                    deleted += 1
                except Exception as e:
                    logger.warning(f"Failed to delete {f}: {e}")
        self.session = None
        logger.info(f"Wardriving data wiped: {deleted} files deleted")
        return {'success': True, 'deleted': deleted}

    def _detect_wifi_interfaces(self):
        """Detect all available WiFi interfaces (including external USB adapters)."""
        interfaces = []
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'DEVICE,TYPE,STATE', 'device'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    parts = line.split(':')
                    if len(parts) >= 3 and parts[1] == 'wifi':
                        interfaces.append(parts[0])
        except Exception as e:
            logger.debug(f"nmcli detection failed: {e}")

        # Fallback: check sysfs
        if not interfaces:
            try:
                import os
                for name in sorted(os.listdir('/sys/class/net')):
                    if os.path.isdir(f'/sys/class/net/{name}/wireless'):
                        interfaces.append(name)
            except Exception:
                pass

        return interfaces

    def _scan_loop(self):
        """Main scanning loop — runs fast continuous scans."""
        logger.info(f"Scan loop started with {len(self.interfaces)} interface(s)")

        while self._running:
            scan_start = time.time()

            try:
                # Get GPS position
                pos = self._gps.get_position() if self._gps else None
                lat = pos['lat'] if pos else None
                lon = pos['lon'] if pos else None
                alt = pos['alt'] if pos else None
                speed = pos['speed_kmh'] if pos else None
                hdop = pos['hdop'] if pos else None

                # Log GPS track periodically
                if pos and (time.time() - self._last_gps_track) >= self._gps_track_interval:
                    self.session.log_gps_track(
                        lat, lon, alt, speed,
                        pos.get('satellites', 0), hdop
                    )
                    self._last_gps_track = time.time()

                # Scan each interface in parallel — distinct radios can sweep
                # concurrently. With one adapter this is a no-op; with two it
                # halves wall-clock cost and gives each adapter the same RF
                # observation window so antenna comparisons are fair.
                total_found = 0
                if len(self.interfaces) == 1:
                    iface = self.interfaces[0]
                    results = {iface: self._scan_interface(iface)}
                else:
                    results = {}
                    threads = []
                    results_lock = threading.Lock()

                    def _scan_worker(iface_local):
                        try:
                            nets = self._scan_interface(iface_local)
                        except Exception as e:
                            logger.error(f"Scan error on {iface_local}: {e}")
                            nets = []
                        with results_lock:
                            results[iface_local] = nets

                    for iface in self.interfaces:
                        t = threading.Thread(
                            target=_scan_worker, args=(iface,),
                            daemon=True, name=f"wardriving-{iface}"
                        )
                        t.start()
                        threads.append(t)
                    for t in threads:
                        t.join(timeout=20)

                for iface, networks in results.items():
                    for net in networks:
                        self.session.upsert_network(
                            bssid=net['bssid'],
                            ssid=net['ssid'],
                            security=net['security'],
                            channel=net['channel'],
                            frequency=net['frequency'],
                            rssi=net['rssi'],
                            lat=lat, lon=lon, alt=alt,
                            speed=speed, hdop=hdop,
                            interface=iface
                        )
                        total_found += 1

                self.networks_per_scan = total_found
                self.scans_completed += 1
                self.total_networks = self.session.network_count
                self.last_scan_time = time.time()

            except Exception as e:
                self.error = str(e)
                logger.error(f"Scan error: {e}")

            # Wait for next scan (adaptive: faster if moving)
            elapsed = time.time() - scan_start
            wait = max(0.5, self.scan_interval - elapsed)
            # If we have GPS speed data, scan faster when moving
            if self._gps and self._gps.speed_kmh and self._gps.speed_kmh > 5:
                wait = min(wait, 1.0)  # Scan every second when moving

            time.sleep(wait)

        logger.info("Scan loop stopped")

    # All common 2.4 GHz + 5 GHz frequencies for full-channel sweep.
    # This forces the kernel to listen on every channel instead of only the
    # associated one, so stationary wardriving discovers all neighbours in
    # one scan cycle (~2-4 s) instead of trickling in over 30-40 minutes.
    _ALL_FREQUENCIES = [
        # 2.4 GHz (channels 1-14)
        2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472,
        # 5 GHz UNII-1 (36-48)
        5180, 5200, 5220, 5240,
        # 5 GHz UNII-2 (52-64) — DFS
        5260, 5280, 5300, 5320,
        # 5 GHz UNII-2 Extended (100-144) — DFS
        5500, 5520, 5540, 5560, 5580, 5600, 5620, 5640, 5660, 5680, 5700, 5720,
        # 5 GHz UNII-3 (149-165)
        5745, 5765, 5785, 5805, 5825,
    ]

    def _is_associated(self, interface):
        """True if the interface is currently associated with an AP as a client.
        Used to decide whether wardriving can claim it exclusively from NM."""
        try:
            r = subprocess.run(['iw', 'dev', interface, 'link'],
                               capture_output=True, text=True, timeout=3)
            return r.returncode == 0 and 'Connected to' in r.stdout
        except Exception:
            return False

    def _iface_type(self, interface):
        """Return current iw interface type (managed/monitor/...) or '' on failure."""
        try:
            r = subprocess.run(['iw', 'dev', interface, 'info'],
                               capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                m = re.search(r'^\s*type\s+(\S+)', r.stdout, re.MULTILINE)
                if m:
                    return m.group(1).lower()
        except Exception:
            pass
        return ''

    def _iface_phy(self, interface):
        """Return the phy name (e.g. 'phy0') for an interface, or '' on failure."""
        try:
            path = f'/sys/class/net/{interface}/phy80211/name'
            if os.path.exists(path):
                with open(path) as f:
                    return f.read().strip()
        except Exception:
            pass
        return ''

    @staticmethod
    def _freq_to_band(f):
        """Map a frequency (MHz) to a band label: '2.4', '5', or '6'."""
        if f < 3000:
            return '2.4'
        if f < 5925:
            return '5'
        return '6'

    def _iface_supported_freqs(self, interface):
        """Frequencies (MHz) from _ALL_FREQUENCIES that this adapter's phy
        actually supports, further filtered by band assignment if in 'split'
        mode. Cached per-interface.

        Critical for single-band adapters: kernel returns -EINVAL on the whole
        scan trigger if any one frequency in the list is unsupported, so a
        2.4 GHz-only radio (e.g. rt2800usb) silently fails the entire sweep.
        In split mode, additionally restricts the sweep list to the bands
        this adapter has been assigned, so the two radios stop redundantly
        scanning the same channels.
        """
        if interface in self._iface_freq_cache:
            return self._iface_freq_cache[interface]
        supported = set()
        phy = self._iface_phy(interface)
        if phy:
            try:
                r = subprocess.run(['iw', 'phy', phy, 'info'],
                                   capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    # "    * 2412 MHz [1] (20.0 dBm)" — skip "(disabled)" entries
                    for line in r.stdout.split('\n'):
                        if '(disabled)' in line.lower():
                            continue
                        m = re.search(r'\*\s*(\d{4,5})\s*MHz', line)
                        if m:
                            supported.add(int(m.group(1)))
            except Exception as e:
                logger.debug(f"Failed to read supported freqs for {interface}: {e}")
        freqs = [f for f in self._ALL_FREQUENCIES if f in supported] if supported else []

        # Apply band assignment in split mode. Falls through to the full
        # supported list in redundant mode or when no assignment exists.
        if self.band_mode == 'split':
            assigned = self._iface_band_assignment.get(interface)
            if assigned:
                freqs = [f for f in freqs if self._freq_to_band(f) in assigned]

        self._iface_freq_cache[interface] = freqs
        if freqs:
            bands_in_sweep = sorted({self._freq_to_band(f) for f in freqs})
            mode_tag = f"[{self.band_mode}]" if self.band_mode == 'split' else ''
            logger.info(
                f"Wardriving: {interface} sweep list {mode_tag} = "
                f"{len(freqs)} channels ({'/'.join(bands_in_sweep)} GHz)"
            )
        else:
            logger.warning(
                f"Wardriving: {interface} supported-freq detection failed — "
                f"will let kernel pick channels"
            )
        return freqs

    def _compute_band_assignments(self):
        """In 'split' mode, assign each interface one band to sweep so adapters
        don't redundantly scan the same channels.

        Strategy: walk interfaces in detection order, alternating preferred
        band (2.4, then 5, then 2.4, ...). If an adapter doesn't support the
        next preferred band, give it whichever band it does support — this
        keeps single-band adapters useful. After every band has at least one
        adapter, remaining adapters fall back to their best supported band.

        With wlan0 (2.4+5) + NETGEAR (2.4+5):
          wlan0   → 2.4 GHz
          NETGEAR → 5 GHz
        With wlan0 + NETGEAR + Realtek (2.4-only):
          wlan0   → 2.4
          NETGEAR → 5
          Realtek → 2.4 (redundant 2.4 — only band it supports)
        """
        self._iface_band_assignment.clear()
        if self.band_mode != 'split' or not self.interfaces:
            return

        # Determine each interface's supported bands (read once, cheap).
        iface_bands = {}
        for iface in self.interfaces:
            phy = self._iface_phy(iface)
            bands = set()
            if phy:
                try:
                    r = subprocess.run(['iw', 'phy', phy, 'info'],
                                       capture_output=True, text=True, timeout=5)
                    if r.returncode == 0:
                        for line in r.stdout.split('\n'):
                            if '(disabled)' in line.lower():
                                continue
                            m = re.search(r'\*\s*(\d{4,5})\s*MHz', line)
                            if m:
                                bands.add(self._freq_to_band(int(m.group(1))))
                except Exception:
                    pass
            iface_bands[iface] = bands

        preferred_order = ['2.4', '5', '6']
        next_idx = 0
        for iface in self.interfaces:
            supported = iface_bands.get(iface) or set()
            if not supported:
                self._iface_band_assignment[iface] = set()
                continue
            # Find next preferred band this adapter supports
            chosen = None
            for offset in range(len(preferred_order)):
                cand = preferred_order[(next_idx + offset) % len(preferred_order)]
                if cand in supported:
                    chosen = cand
                    break
            if not chosen:
                # Shouldn't happen — supported is non-empty so something matches.
                chosen = sorted(supported)[0]
            self._iface_band_assignment[iface] = {chosen}
            next_idx = (preferred_order.index(chosen) + 1) % len(preferred_order)

        logger.info(
            f"Wardriving: band assignments (split mode) = "
            f"{ {k: sorted(v) for k, v in self._iface_band_assignment.items()} }"
        )

    def _cleanup_phy_children(self, interface):
        """Delete any monitor/AP child interfaces sharing this iface's phy.

        airmon-ng / bettercap / kismet create child interfaces (mon0, wlan1mon,
        …) on the same phy. While the child exists the kernel may refuse scans
        on the managed parent. Wardriving owns non-WiFi-connected adapters, so
        clear them.
        """
        phy = self._iface_phy(interface)
        if not phy:
            return
        try:
            r = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=3)
            if r.returncode != 0:
                return
            current_phy = None
            current_iface = None
            current_type = None
            for line in r.stdout.split('\n'):
                line_strip = line.strip()
                if line.startswith('phy#'):
                    current_phy = 'phy' + line_strip[4:]
                    current_iface = None
                    current_type = None
                elif line_strip.startswith('Interface '):
                    current_iface = line_strip.split(' ', 1)[1].strip()
                    current_type = None
                elif line_strip.startswith('type '):
                    current_type = line_strip.split(' ', 1)[1].strip().lower()
                    if (current_phy == phy and current_iface and
                        current_iface != interface and
                        current_type in ('monitor', 'ap')):
                        logger.warning(
                            f"Wardriving: removing leftover {current_type} "
                            f"child {current_iface} on {phy} (parent {interface})"
                        )
                        try:
                            subprocess.run(['sudo', 'ip', 'link', 'set', current_iface, 'down'],
                                           capture_output=True, timeout=3)
                            subprocess.run(['sudo', 'iw', 'dev', current_iface, 'del'],
                                           capture_output=True, timeout=3)
                        except Exception as e:
                            logger.warning(f"Failed to delete {current_iface}: {e}")
        except Exception as e:
            logger.debug(f"phy-children cleanup failed for {interface}: {e}")

    def _prepare_interface(self, interface):
        """Ensure interface is unblocked, free of monitor children, in managed
        mode, and admin-up.

        Design contract: wardriving owns every wlan adapter that isn't the
        WiFi-management interface. Anything else (leftover airmon mon0,
        bettercap monitor child, manual `iw set type monitor`) gets reclaimed.
        Only pwnagotchi mode — explicitly started by the user — is allowed to
        flip an adapter back to monitor.

        DELIBERATE: wardriving and AP mode are MUTUALLY EXCLUSIVE by design.
        If Ragnar enters AP mode (wlan0 type='ap' via hostapd) while wardriving
        is active, this method will force wlan0 back to 'managed' and the AP
        will collapse. That is intentional — wardriving needs every radio in
        scannable state. If you want AP mode, stop wardriving first (or never
        enable wardriving_on_boot). Do not add an "if type=='ap' then skip"
        guard here without re-discussing this trade-off.
        """
        # rfkill unblock — cheap, idempotent
        try:
            subprocess.run(['sudo', 'rfkill', 'unblock', 'wifi'],
                           capture_output=True, timeout=3)
        except Exception as e:
            logger.debug(f"rfkill unblock failed: {e}")

        # Claim non-associated interfaces from NetworkManager so its autoscan
        # doesn't race our scan trigger (kernel returns -EBUSY when NM has a
        # scan in flight). Skip the management interface (the one currently
        # connected to an AP) — we must not touch that or we kill WiFi.
        if not self._is_associated(interface):
            try:
                r = subprocess.run(
                    ['sudo', 'nmcli', 'dev', 'set', interface, 'managed', 'no'],
                    capture_output=True, text=True, timeout=3
                )
                if r.returncode == 0 and interface not in self._iface_prepared:
                    logger.info(
                        f"Wardriving: {interface} marked unmanaged in NetworkManager "
                        f"(prevents autoscan races)"
                    )
            except Exception as e:
                logger.debug(f"nmcli unmanage on {interface} failed: {e}")

        # Kill any monitor/AP child interfaces on this phy first.
        self._cleanup_phy_children(interface)

        current_type = self._iface_type(interface)

        # Force managed if (a) we know it's not managed, or (b) we couldn't
        # read the type at all — the latter usually means the interface is in
        # a weird state and we want to reset it anyway. The cost of a
        # redundant down/up on an already-managed iface is ~100 ms.
        needs_reset = (not current_type) or (current_type != 'managed')
        if needs_reset:
            reason = current_type or 'unknown-state'
            logger.warning(
                f"Wardriving: {interface} state='{reason}' — forcing managed for scanning"
            )
            try:
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'],
                               capture_output=True, timeout=3)
                r = subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'type', 'managed'],
                                   capture_output=True, text=True, timeout=3)
                if r.returncode != 0:
                    logger.warning(f"iw set type managed on {interface} failed: {r.stderr.strip()}")
            except Exception as e:
                logger.warning(f"forcing managed on {interface} exception: {e}")

        # Always bring it up (cheap no-op if already up)
        try:
            r = subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'],
                               capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                if interface not in self._iface_prepared:
                    logger.info(f"Wardriving: {interface} ready (type=managed, up)")
                self._iface_prepared.add(interface)
            else:
                logger.warning(f"ip link set {interface} up failed: {r.stderr.strip()}")
        except Exception as e:
            logger.warning(f"ip link set {interface} up exception: {e}")

    def _scan_interface(self, interface):
        """Scan a single WiFi interface for networks using iw.

        Uses an active full-channel sweep (scan trigger with all frequencies)
        so that every nearby network is discovered in a single pass, even when
        the interface is associated and stationary.
        """
        # Self-heal: if the previous scan turned up nothing, re-run prepare in
        # case the interface went DOWN, got soft-blocked, or was hot-plugged
        # after start(). Cheap (one rfkill + one ip link call) and idempotent.
        if self._iface_zero_scans.get(interface, 0) > 0 or interface not in self._iface_prepared:
            self._prepare_interface(interface)

        networks = []

        # Method 1: Active full-channel sweep — trigger scan across every
        # frequency this radio supports. We filter against the phy's actual
        # channel list because the kernel returns -EINVAL on the whole
        # trigger if even one requested frequency is unsupported (e.g. a
        # 5 GHz freq on a 2.4-GHz-only adapter like rt2800usb).
        trigger_err = ''
        try:
            sweep_freqs = self._iface_supported_freqs(interface)
            trigger_cmd = ['sudo', 'iw', 'dev', interface, 'scan', 'trigger']
            for f in sweep_freqs:
                trigger_cmd += ['freq', str(f)]
            trigger = subprocess.run(
                trigger_cmd,
                capture_output=True, text=True, timeout=5
            )
            # Retry once on EBUSY — another process (NetworkManager, WiFiManager)
            # may have a scan in flight on this radio. Wait long enough for a
            # typical scan to complete, then try again.
            if trigger.returncode != 0 and 'busy' in (trigger.stderr or '').lower():
                time.sleep(2.5)
                trigger = subprocess.run(
                    trigger_cmd,
                    capture_output=True, text=True, timeout=5
                )
            if trigger.returncode == 0:
                # Wait for the full sweep to finish (typically 2-3 s for all channels)
                time.sleep(2.0)
                result = subprocess.run(
                    ['sudo', 'iw', 'dev', interface, 'scan', 'dump'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    networks = self._parse_iw_scan(result.stdout, interface)
                    if networks:
                        self._iface_last_error.pop(interface, None)
                        return networks
            else:
                trigger_err = (trigger.stderr or trigger.stdout or '').strip().splitlines()[-1:] or ['']
                trigger_err = trigger_err[0][:200]
        except Exception as e:
            trigger_err = str(e)[:200]
            logger.debug(f"iw full-channel sweep failed on {interface}: {e}")
        if trigger_err:
            self._iface_last_error[interface] = trigger_err

        # Method 2: iw scan dump (reads cached scan results — fast fallback)
        try:
            result = subprocess.run(
                ['sudo', 'iw', 'dev', interface, 'scan', 'dump'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                networks = self._parse_iw_scan(result.stdout, interface)
                if networks:
                    return networks
        except Exception as e:
            logger.debug(f"iw scan dump failed on {interface}: {e}")

        # Method 3: Trigger simple scan + dump (no freq list)
        try:
            subprocess.run(
                ['sudo', 'iw', 'dev', interface, 'scan', 'trigger'],
                capture_output=True, text=True, timeout=5
            )
            time.sleep(0.5)
            result = subprocess.run(
                ['sudo', 'iw', 'dev', interface, 'scan', 'dump'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                networks = self._parse_iw_scan(result.stdout, interface)
                if networks:
                    return networks
        except Exception as e:
            logger.debug(f"iw scan trigger+dump failed on {interface}: {e}")

        # Method 3: nmcli fallback
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'BSSID,SSID,SIGNAL,SECURITY,FREQ,CHAN', 'dev', 'wifi', 'list',
                 'ifname', interface, '--rescan', 'auto'],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                networks = self._parse_nmcli_scan(result.stdout)
        except Exception as e:
            logger.debug(f"nmcli scan failed on {interface}: {e}")

        # Track consecutive empty scans so we self-heal and surface real failures
        # instead of silently returning [] forever.
        if networks:
            self._iface_zero_scans[interface] = 0
            self._iface_last_error.pop(interface, None)
        else:
            n = self._iface_zero_scans.get(interface, 0) + 1
            self._iface_zero_scans[interface] = n
            if n == 3 or (n > 3 and n % 10 == 0):
                logger.warning(
                    f"Wardriving: {interface} returned 0 networks for {n} consecutive scans "
                    f"(check 'ip link show {interface}', 'rfkill list', and NetworkManager state)"
                )

        return networks

    def _parse_iw_scan(self, output, interface):
        """Parse iw scan dump output into network dicts."""
        networks = []
        current = None

        def _sanitize_ssid(ssid):
            """Clean up SSID: remove hex escapes, null bytes, control chars."""
            if not ssid:
                return ''
            ssid = ssid.replace('\x00', '')
            # iw outputs literal \xNN for non-printable bytes
            ssid = re.sub(r'\\x[0-9a-fA-F]{2}', '', ssid)
            ssid = ssid.strip()
            if not ssid or all(ord(c) < 32 for c in ssid):
                return ''
            return ssid

        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('BSS '):
                if current and current.get('bssid'):
                    current['ssid'] = _sanitize_ssid(current.get('ssid', ''))
                    networks.append(current)
                # BSS aa:bb:cc:dd:ee:ff(on wlan0) -- associated
                bssid_match = re.match(r'BSS\s+([0-9a-fA-F:]{17})', line)
                current = {
                    'bssid': bssid_match.group(1).upper() if bssid_match else '',
                    'ssid': '',
                    'security': '',
                    'channel': 0,
                    'frequency': 0,
                    'rssi': -100,
                    'interface': interface
                }
            elif current:
                if line.startswith('SSID:'):
                    current['ssid'] = line[5:].strip()
                elif line.startswith('signal:'):
                    try:
                        current['rssi'] = int(float(line.split(':')[1].strip().split(' ')[0]))
                    except (ValueError, IndexError):
                        pass
                elif line.startswith('freq:'):
                    try:
                        # Handle formats: "freq: 2437", "freq: 2437 MHz", etc.
                        freq_str = re.search(r'(\d+)', line.split(':', 1)[1])
                        if freq_str:
                            freq = int(freq_str.group(1))
                            current['frequency'] = freq
                            current['channel'] = _freq_to_channel(freq)
                    except (ValueError, IndexError):
                        pass
                elif line.startswith('DS Parameter set:'):
                    # "DS Parameter set: channel 6" — fallback for channel
                    try:
                        ch_match = re.search(r'channel\s+(\d+)', line)
                        if ch_match and current['channel'] == 0:
                            ch = int(ch_match.group(1))
                            current['channel'] = ch
                            # Estimate frequency from channel if not set
                            if current['frequency'] == 0 and 1 <= ch <= 14:
                                current['frequency'] = 2407 + ch * 5 if ch < 14 else 2484
                    except (ValueError, IndexError):
                        pass
                elif line.startswith('* primary channel:'):
                    # HT/VHT operation: "* primary channel: 36"
                    try:
                        ch_match = re.search(r'(\d+)', line.split(':', 1)[1])
                        if ch_match and current['channel'] == 0:
                            current['channel'] = int(ch_match.group(1))
                    except (ValueError, IndexError):
                        pass
                elif line.startswith('* center freq segment 1:') or line.startswith('center freq 1:'):
                    # VHT/HE operation center frequency
                    try:
                        freq_match = re.search(r'(\d{4,5})', line)
                        if freq_match and current['frequency'] == 0:
                            freq = int(freq_match.group(1))
                            current['frequency'] = freq
                            if current['channel'] == 0:
                                current['channel'] = _freq_to_channel(freq)
                    except (ValueError, IndexError):
                        pass
                elif 'RSN:' == line or line.startswith('RSN:'):
                    current['security'] = 'WPA2'
                elif 'WPA:' == line or line.startswith('WPA:'):
                    if current['security'] != 'WPA2':
                        current['security'] = 'WPA1'
                elif line.startswith('capability:') and 'Privacy' in line:
                    if not current['security']:
                        current['security'] = 'WEP'

        if current and current.get('bssid'):
            current['ssid'] = _sanitize_ssid(current.get('ssid', ''))
            networks.append(current)

        return networks

    def _parse_nmcli_scan(self, output):
        """Parse nmcli terse WiFi scan output."""
        networks = []
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            # nmcli terse: BSSID:SSID:SIGNAL:SECURITY:FREQ:CHAN
            # Handle escaped colons in BSSID
            parts = line.replace('\\:', '\x00').split(':')
            parts = [p.replace('\x00', ':') for p in parts]
            if len(parts) >= 6:
                try:
                    freq = int(parts[4]) if parts[4] else 0
                except ValueError:
                    freq = 0
                try:
                    chan = int(parts[5]) if parts[5] else _freq_to_channel(freq)
                except ValueError:
                    chan = _freq_to_channel(freq)
                try:
                    signal = int(parts[2]) if parts[2] else -100
                    # nmcli gives 0-100 signal, convert to approximate dBm
                    if signal >= 0:
                        rssi = max(-100, min(-20, -100 + signal))
                    else:
                        rssi = signal
                except ValueError:
                    rssi = -100

                networks.append({
                    'bssid': parts[0].upper(),
                    'ssid': parts[1],
                    'rssi': rssi,
                    'security': parts[3],
                    'frequency': freq,
                    'channel': chan,
                })

        return networks

    # ------------------------------------------------------------------
    # Bluetooth scanning
    # ------------------------------------------------------------------

    _bt_powered_on = False  # Class-level: avoid repeated 'power on' calls

    def _bt_scan_loop(self):
        """Background loop: scan for Bluetooth devices every ~15 seconds.

        Skipped while Huginn is streaming over serial — Huginn has a dedicated
        ESP32 BLE radio and the Pi's local bluetoothctl just re-imports BlueZ's
        all-time device cache, inflating unique counts. Piglet does not do BLE,
        so the local scan still runs when only Piglet is connected.
        """
        logger.info("Bluetooth scan loop started")
        while self._running:
            try:
                if self.serial_connected and self._companion_name == 'Huginn':
                    time.sleep(15)
                    continue
                pos = self._gps.get_position() if self._gps else None
                lat = pos['lat'] if pos else None
                lon = pos['lon'] if pos else None
                alt = pos['alt'] if pos else None

                devices = self._scan_bluetooth()
                for dev in devices:
                    self.session.upsert_bluetooth(
                        mac=dev['mac'], name=dev['name'], rssi=dev.get('rssi', -100),
                        device_type=dev.get('type', ''), lat=lat, lon=lon, alt=alt
                    )
                self.bt_count = len(devices)
                if devices:
                    logger.info(f"BT scan found {len(devices)} devices")
            except Exception as e:
                logger.warning(f"BT scan error: {e}")
            time.sleep(15)
        logger.info("Bluetooth scan loop stopped")

    def _scan_bluetooth(self):
        """Scan for Bluetooth Classic + BLE devices."""
        devices = []
        seen_macs = set()

        # Ensure Bluetooth is not soft-blocked
        try:
            subprocess.run(['sudo', 'rfkill', 'unblock', 'bluetooth'],
                           capture_output=True, timeout=3)
        except Exception:
            pass

        # Method 1: bluetoothctl (Classic + BLE)
        try:
            # Power on once per session (skip repeated calls)
            if not WardrivingEngine._bt_powered_on:
                power_result = subprocess.run(['sudo', 'bluetoothctl', 'power', 'on'],
                               capture_output=True, text=True, timeout=5)
                if power_result.returncode == 0:
                    WardrivingEngine._bt_powered_on = True
                    logger.info(f"Bluetooth powered on: {power_result.stdout.strip()}")
                else:
                    logger.warning(f"Bluetooth power on failed: {power_result.stderr.strip()}")
            proc = subprocess.run(
                ['sudo', 'bluetoothctl', '--timeout', '5', 'scan', 'on'],
                capture_output=True, text=True, timeout=8
            )
            # List discovered devices
            result = subprocess.run(
                ['sudo', 'bluetoothctl', 'devices'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    # Format: "Device AA:BB:CC:DD:EE:FF DeviceName"
                    m = re.match(r'Device\s+([0-9A-Fa-f:]{17})\s+(.*)', line.strip())
                    if m:
                        mac = m.group(1).upper()
                        name = m.group(2).strip()
                        if mac not in seen_macs:
                            seen_macs.add(mac)
                            devices.append({'mac': mac, 'name': name, 'rssi': -80, 'type': 'Classic/BLE'})
        except Exception as e:
            logger.warning(f"bluetoothctl scan failed: {e}")

        # Method 2: hcitool lescan for BLE (if available)
        try:
            result = subprocess.run(
                ['sudo', 'timeout', '5', 'hcitool', 'lescan', '--duplicates'],
                capture_output=True, text=True, timeout=8
            )
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    m = re.match(r'([0-9A-Fa-f:]{17})\s+(.*)', line.strip())
                    if m:
                        mac = m.group(1).upper()
                        name = m.group(2).strip()
                        if mac not in seen_macs and name != '(unknown)':
                            seen_macs.add(mac)
                            devices.append({'mac': mac, 'name': name, 'rssi': -85, 'type': 'BLE'})
        except Exception as e:
            logger.warning(f"hcitool lescan failed: {e}")

        return devices

    # ------------------------------------------------------------------
    # Cell network scanning
    # ------------------------------------------------------------------

    def _cell_scan_loop(self):
        """Background loop: scan for cell towers every ~30 seconds."""
        logger.info("Cell network scan loop started")
        while self._running:
            try:
                pos = self._gps.get_position() if self._gps else None
                lat = pos['lat'] if pos else None
                lon = pos['lon'] if pos else None

                towers = self._scan_cell_networks()
                for t in towers:
                    self.session.upsert_cell_tower(
                        cell_id=t['cell_id'], mcc=t.get('mcc', ''), mnc=t.get('mnc', ''),
                        lac=t.get('lac', ''), tech=t.get('tech', ''),
                        provider=t.get('provider', ''), signal_dbm=t.get('signal', -120),
                        band_freq=t.get('band', ''), lat=lat, lon=lon
                    )
                self.cell_count = len(towers)
            except Exception as e:
                logger.debug(f"Cell scan error: {e}")
            time.sleep(30)
        logger.info("Cell network scan loop stopped")

    def _scan_cell_networks(self):
        """Scan for cell networks using ModemManager (mmcli)."""
        towers = []

        # Find modem index
        try:
            result = subprocess.run(
                ['mmcli', '-L'], capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0 or not result.stdout.strip():
                return towers
            # Parse modem number: "/org/freedesktop/ModemManager1/Modem/0"
            modem_match = re.search(r'/Modem/(\d+)', result.stdout)
            if not modem_match:
                return towers
            modem_idx = modem_match.group(1)
        except Exception:
            return towers

        # Get modem info
        try:
            result = subprocess.run(
                ['mmcli', '-m', modem_idx, '--output-json'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                modem = data.get('modem', {})
                generic = modem.get('generic', {})
                thr = modem.get('3gpp', {})

                provider = generic.get('operator-name', '') or thr.get('operator-name', '')
                tech_list = generic.get('access-technologies', [])
                tech = tech_list[0] if tech_list else ''
                signal_raw = generic.get('signal-quality', {}).get('value', 0)
                signal_dbm = int(-120 + (signal_raw * 0.9)) if signal_raw else -120

                mcc = thr.get('operator-code', '')[:3] if thr.get('operator-code') else ''
                mnc = thr.get('operator-code', '')[3:] if thr.get('operator-code') else ''

                # Get cell info from scan
                cell_id_str = thr.get('registration', {}).get('cell-id', '') or str(modem_idx)

                if cell_id_str:
                    towers.append({
                        'cell_id': cell_id_str,
                        'mcc': mcc,
                        'mnc': mnc,
                        'lac': thr.get('registration', {}).get('lac', ''),
                        'tech': tech,
                        'provider': provider,
                        'signal': signal_dbm,
                        'band': '',
                    })
        except Exception as e:
            logger.debug(f"mmcli modem info failed: {e}")

        # Try network scan for nearby towers
        try:
            # 3GPP network scan: use shorter timeout on low-power devices
            _cpu_count = os.cpu_count() or 1
            _scan_timeout = 15 if _cpu_count <= 1 else 60
            result = subprocess.run(
                ['mmcli', '-m', modem_idx, '--3gpp-scan', '--output-json'],
                capture_output=True, text=True, timeout=_scan_timeout
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                scan_results = data.get('modem', {}).get('3gpp', {}).get('scan', [])
                for net in scan_results:
                    cid = f"{net.get('operator-code', '')}-{net.get('operator-long', '')}"
                    if cid and not any(t['cell_id'] == cid for t in towers):
                        towers.append({
                            'cell_id': cid,
                            'mcc': net.get('operator-code', '')[:3] if net.get('operator-code') else '',
                            'mnc': net.get('operator-code', '')[3:] if net.get('operator-code') else '',
                            'lac': '',
                            'tech': net.get('access-technology', ''),
                            'provider': net.get('operator-long', ''),
                            'signal': -100,
                            'band': '',
                        })
        except Exception as e:
            logger.debug(f"mmcli 3gpp scan failed: {e}")

        return towers

    # ------------------------------------------------------------------
    # Serial ESP32 listener (Piglet / HuginnESP)
    # ------------------------------------------------------------------

    def _serial_listen_loop(self):
        """Listen for wardriving data from a USB-connected ESP32 (Piglet/HuginnESP).

        Rotates through HuginnESP commands to maximize data collection:
        - scanap: WiFi network scanning (primary)
        - blescan -f: Find Flipper devices
        - blescan -a: AirTag scanner
        - capture -skimmer: BLE skimmer detection
        - pineap: PineAP/Evil Twin detection
        """
        logger.info(f"Serial ESP32 listener starting on {self._serial_port}")
        try:
            import serial as pyserial
        except ImportError:
            logger.error("pyserial not installed - serial listener disabled")
            return

        # Scan cycle: command, duration(s), mode label
        # WiFi gets most time since it produces the most data
        # BLE commands only output when specific devices are found
        scan_cycle = [
            (b"scanap\r\n", 15, "wifi"),
            (b"blescan -f\r\n", 8, "ble-filtered"),
            (b"scanap\r\n", 15, "wifi"),
            (b"blescan -a\r\n", 8, "ble-all"),
            (b"scanap\r\n", 15, "wifi"),
            (b"capture -skimmer\r\n", 8, "ble-skimmer"),
            (b"scanap\r\n", 15, "wifi"),
            (b"pineap\r\n", 10, "pineap"),
        ]

        while self._running:
            try:
                ser = pyserial.Serial(self._serial_port, 460800, timeout=2)
                self.serial_connected = True
                logger.info(f"Serial connected: {self._serial_port}")

                # Identify companion. Opening pyserial toggles DTR/RTS which
                # resets the ESP32; Huginn takes ~1.5–2s to boot before it
                # accepts commands. Read the boot banner first — Huginn emits
                # `{"device":"HuginnESP",...}` and `[BOOT] HuginnESP starting`
                # within ~2s. Fall back to an active `status` probe if the
                # banner is silent (older firmware / Piglet).
                self._companion_name = ''
                self._huginn_handshake_pushed = False
                try:
                    boot_buf = ''
                    boot_raw = bytearray()
                    deadline = time.time() + 3.0
                    while time.time() < deadline:
                        try:
                            avail = ser.in_waiting
                        except Exception:
                            avail = 0
                        if avail:
                            try:
                                chunk = ser.read(avail)
                                boot_raw += chunk
                                boot_buf += chunk.decode('utf-8', errors='replace')
                            except Exception:
                                pass
                            if ('HuginnESP' in boot_buf or '[CORE]' in boot_buf
                                    or 'Piglet' in boot_buf
                                    or 'RagnarBridge' in boot_buf
                                    or (len(boot_raw) >= 3
                                        and boot_raw[0] == 0xAB
                                        and boot_raw[1] == 0xCD
                                        and boot_raw[2] == 0x03)):
                                break
                        time.sleep(0.1)

                    if 'HuginnESP' in boot_buf or 'huginn' in boot_buf.lower():
                        self._companion_name = 'Huginn'
                    elif 'RagnarBridge' in boot_buf or (
                            len(boot_raw) >= 3
                            and boot_raw[0] == 0xAB
                            and boot_raw[1] == 0xCD
                            and boot_raw[2] == 0x03):
                        self._companion_name = 'RagnarBridge'
                    elif 'Piglet' in boot_buf or '[CORE]' in boot_buf:
                        self._companion_name = 'Piglet'
                    else:
                        # No banner — actively probe with `status`.
                        ser.reset_input_buffer()
                        ser.write(b"status\r\n")
                        time.sleep(1.5)
                        try:
                            probe = ser.read(ser.in_waiting or 512).decode('utf-8', errors='replace')
                        except Exception:
                            probe = ''
                        if '{"mode"' in probe or 'HuginnESP' in probe or 'huginn' in probe.lower():
                            self._companion_name = 'Huginn'
                        elif 'Piglet' in probe:
                            self._companion_name = 'Piglet'
                        else:
                            self._companion_name = 'Piglet'  # passive CSV fallback
                    logger.info(f"Companion identified: {self._companion_name}")

                    # Rescue any WiGLE header lines from the boot buffer so the
                    # column map gets built before the first data rows arrive.
                    if self._companion_name == 'Piglet' and boot_buf:
                        for bline in boot_buf.splitlines():
                            bline = bline.strip()
                            if bline:
                                self._parse_serial_line(bline)
                except Exception as e:
                    logger.debug(f"Companion identify error: {e}")
                    self._companion_name = 'Companion'  # Unknown fallback

                # Push runtime config to Huginn at handshake. Firmware state is
                # RAM-only, so this re-applies on every reconnect.
                if self._companion_name == 'Huginn':
                    for line in self._huginn_initial_push_lines():
                        self._huginn_config_queue.put(line)
                    self._huginn_handshake_pushed = True

                if self._companion_name == 'RagnarBridge':
                    self._run_coordinator_loop(ser)
                    ser.close()
                    continue

                if self._companion_name == 'Huginn':
                    self._run_huginn_wardrive_loop(ser)
                    ser.close()
                    continue

                cycle_index = 0

                while self._running:
                    # Send next scan command
                    cmd, duration, scan_type = scan_cycle[cycle_index % len(scan_cycle)]
                    try:
                        ser.write(b"stop\r\n")
                        time.sleep(0.3)
                        # Also stop BLE/capture if switching away from those modes
                        if scan_type.startswith('ble') or scan_type == 'pineap':
                            ser.write(b"capture -stop\r\n")
                            time.sleep(0.2)
                        # Drain any pending Huginn `set ...` commands queued by
                        # the webapp before the next scan starts emitting data.
                        if self._companion_name == 'Huginn':
                            self._drain_huginn_queue(ser)
                        ser.reset_input_buffer()
                        ser.write(cmd)
                        logger.debug(f"HuginnESP cmd: {cmd.strip()}")
                    except Exception:
                        break

                    # Read output for the duration
                    end_time = time.time() + duration
                    while self._running and time.time() < end_time:
                        try:
                            raw = ser.readline()
                            if not raw:
                                continue
                            line = raw.decode('utf-8', errors='replace').strip()
                            if not line:
                                continue
                            self._parse_serial_line(line)
                        except Exception as e:
                            logger.debug(f"Serial read error: {e}")
                            break

                    # Flush any buffered multi-line entry
                    if self._serial_entry_buffer.get('bssid'):
                        pos = self._gps.get_position() if self._gps else None
                        self._flush_serial_entry(
                            pos['lat'] if pos else None,
                            pos['lon'] if pos else None,
                            pos.get('alt') if pos else None
                        )
                        self._serial_entry_buffer = {}

                    cycle_index += 1

                ser.close()
            except Exception as e:
                self.serial_connected = False
                logger.debug(f"Serial connect failed ({self._serial_port}): {e}")
                # Retry every 5 seconds
                for _ in range(5):
                    if not self._running:
                        break
                    time.sleep(1)

        self.serial_connected = False
        logger.info("Serial ESP32 listener stopped")

    def _run_coordinator_loop(self, ser):
        """Drive the ESP-Now coordinator while the RagnarBridge is connected."""
        from espnow_coordinator import EspNowCoordinator

        _AUTH_MAP = {
            'OPEN': '[ESS]',
            'WEP':  '[WEP][ESS]',
            'WPA':  '[WPA-PSK-TKIP][ESS]',
            'WPA2': '[WPA2-PSK-CCMP][ESS]',
            'WPA3': '[WPA3][ESS]',
        }

        def _on_network(bssid, ssid, auth, channel, rssi, node_mac):
            pos      = self._gps.get_position() if self._gps else None
            gps_lat  = pos['lat']     if pos else None
            gps_lon  = pos['lon']     if pos else None
            gps_alt  = pos.get('alt') if pos else None
            auth_str = auth.upper() if auth else ''
            auth_wigle = _AUTH_MAP.get(auth_str, f'[{auth}][ESS]' if auth else '[ESS]')
            freq = (2407 + channel * 5) if channel <= 14 else (5000 + channel * 5)
            is_new = self.session.upsert_network(
                bssid=bssid, ssid=ssid, security=auth_wigle,
                channel=channel, frequency=freq, rssi=rssi,
                lat=gps_lat, lon=gps_lon, alt=gps_alt,
                speed=None, hdop=None,
                interface='esp32-serial',
            )
            if is_new:
                self.serial_networks += 1

        coord = EspNowCoordinator(on_network=_on_network)
        coord.set_send_callback(lambda data: ser.write(data))
        coord.start()
        self._coordinator = coord

        node_mac_str = lambda mac: ':'.join(f'{b:02X}' for b in mac)
        logger.info("Coordinator loop running — waiting for Piglet nodes")

        try:
            while self._running:
                try:
                    avail = ser.in_waiting or 1
                    data  = ser.read(avail)
                    if data:
                        coord.feed(data)
                        # Update mesh node count for UI
                        self._mesh_node_count = coord.node_count
                except Exception as e:
                    logger.debug(f"Coordinator serial read error: {e}")
                    break
        finally:
            coord.stop()
            self._coordinator = None
            logger.info("Coordinator loop exited")

    def _run_huginn_wardrive_loop(self, ser):
        self._current_esp_mode = 'wardrive'
        try:
            self._drain_huginn_queue(ser)
            ser.reset_input_buffer()
            ser.write(b"wardrive\r\n")
            logger.info("HuginnESP: entered fast wardrive mode")
        except Exception as e:
            logger.warning(f"Failed to start Huginn wardrive mode: {e}")
            return

        last_config_drain = time.time()
        while self._running:
            try:
                raw = ser.readline()
                if raw:
                    line = raw.decode('utf-8', errors='replace').strip()
                    if line:
                        self._parse_serial_line(line)
                now = time.time()
                if now - last_config_drain > 5:
                    self._drain_huginn_queue(ser)
                    last_config_drain = now
            except Exception as e:
                logger.debug(f"Serial read error (wardrive): {e}")
                break

        if self._serial_entry_buffer.get('bssid'):
            pos = self._gps.get_position() if self._gps else None
            self._flush_serial_entry(
                pos['lat'] if pos else None,
                pos['lon'] if pos else None,
                pos.get('alt') if pos else None
            )
            self._serial_entry_buffer = {}

        try:
            ser.write(b"stop\r\n")
        except Exception:
            pass

    def _parse_serial_line(self, line):
        """Parse a single line from ESP32 serial output."""
        if not self.session:
            return

        pos = self._gps.get_position() if self._gps else None
        gps_lat = pos['lat'] if pos else None
        gps_lon = pos['lon'] if pos else None
        gps_alt = pos.get('alt') if pos else None

        # Skip HuginnESP prompt and status lines
        if line.startswith('huginn>') or line.startswith('Wardrive:') or line.startswith('Registered') or line.startswith('Unsupported'):
            return

        # === Piglet Mesh node tracking ===
        # "[CORE] New ... node N:" or "[CORE] Reassigned: N nodes"
        if line.startswith('[CORE]'):
            m = re.search(r'node (\d+):', line)
            if m:
                self._mesh_node_count = max(self._mesh_node_count, int(m.group(1)))
            m = re.search(r'Reassigned:\s*(\d+)\s*nodes', line)
            if m:
                self._mesh_node_count = int(m.group(1))
            m = re.search(r'Node\s+(\d+)\s+timed out', line)
            if m:
                self._mesh_node_count = max(0, self._mesh_node_count - 1)
            # Auto-detect as Piglet if we see [CORE] messages
            if not self._companion_name or self._companion_name == 'Companion':
                self._companion_name = 'Piglet'
            return
        if line.startswith('[MESH]') or line.startswith('[BOOT]'):
            # Auto-detect companion from boot/mesh messages
            if 'HuginnESP' in line:
                if self._companion_name != 'Huginn':
                    self._companion_name = 'Huginn'
                # Late promotion: push runtime config if the handshake window
                # missed the boot banner (slow ESP32 reset, quiet firmware).
                if not self._huginn_handshake_pushed:
                    for cfg_line in self._huginn_initial_push_lines():
                        self._huginn_config_queue.put(cfg_line)
                    self._huginn_handshake_pushed = True
            elif 'Piglet' in line:
                self._companion_name = 'Piglet'
            return

        # Skip scan status messages, help text, and BLE init lines
        skip_prefixes = ('WiFi scan', 'Started', 'Stopped', 'Usage:', 'Scanning started',
                         'BLE initialized', 'BLE scan stopped', 'Skimmer detection',
                         'Monitoring for', 'Stopping', 'PCAP capture', 'Warning: PCAP',
                         'BLE stack not ready', 'Error starting')
        if any(line.startswith(p) for p in skip_prefixes):
            return

        # === Pineapple / Evil Twin / Skimmer detection ===
        if 'Pineapple detected' in line or 'POTENTIAL SKIMMER' in line or 'Evil Twin' in line:
            if 'POTENTIAL SKIMMER' in line:
                self._current_esp_mode = 'ble-skimmer'
            else:
                self._current_esp_mode = 'pineap'
            logger.warning(f"[HuginnESP ALERT] {line}")
            if not hasattr(self, '_esp_alerts'):
                self._esp_alerts = []
            self._esp_alerts.append({'time': time.time(), 'alert': line})
            # Start buffering multi-line alert details
            self._esp_alert_buffer = {'type': 'pineap' if 'Pineapple' in line else ('evil_twin' if 'Evil Twin' in line else 'skimmer')}
            return

        # Buffer continuation lines for alert details (BSSID:, Channel:, Device Name:, MAC Address:, etc.)
        if hasattr(self, '_esp_alert_buffer') and self._esp_alert_buffer:
            buf = self._esp_alert_buffer
            if line.startswith('BSSID:'):
                buf['bssid'] = line.split(':', 1)[1].strip()
            elif line.startswith('Channel:'):
                buf['channel'] = line.split(':', 1)[1].strip()
            elif line.startswith('Security:'):
                buf['security'] = line.split(':', 1)[1].strip()
            elif line.startswith('RSSI:'):
                rssi_val = re.search(r'-?\d+', line)
                buf['rssi'] = int(rssi_val.group()) if rssi_val else -80
            elif line.startswith('SSIDs'):
                buf['ssids'] = line.split(':', 1)[1].strip() if ':' in line else ''
            elif line.startswith('Device Name:'):
                buf['name'] = line.split(':', 1)[1].strip()
            elif line.startswith('MAC Address:'):
                buf['mac'] = line.split(':', 1)[1].strip().upper()
            elif line.startswith('Reason:') or line.startswith('Please verify'):
                # End of skimmer alert — flush to DB
                if buf.get('mac'):
                    self.session.upsert_bluetooth(
                        buf['mac'], buf.get('name', ''), buf.get('rssi', -80),
                        'Skimmer', gps_lat, gps_lon, gps_alt
                    )
                    self._esp_ble_count += 1
                    logger.warning(f"[HuginnESP] Skimmer: {buf.get('name','')} @ {buf['mac']}")
                self._esp_alert_buffer = {}
                return
            else:
                # Unrecognized line — flush buffer
                self._esp_alert_buffer = {}
                # Fall through to normal parsing
            if self._esp_alert_buffer:
                return

        # === AirTag detection (multi-line) ===
        if line.startswith('AirTag found'):
            self._current_esp_mode = 'ble-all'
            self._esp_airtag_buffer = {}
            return
        if hasattr(self, '_esp_airtag_buffer') and self._esp_airtag_buffer is not None:
            if line.startswith('Tag:'):
                self._esp_airtag_buffer['tag'] = line.split(':', 1)[1].strip()
                return
            elif line.startswith('MAC Address:'):
                self._esp_airtag_buffer['mac'] = line.split(':', 1)[1].strip().upper()
                return
            elif line.startswith('RSSI:'):
                rssi_val = re.search(r'-?\d+', line)
                self._esp_airtag_buffer['rssi'] = int(rssi_val.group()) if rssi_val else -80
                # Flush AirTag to DB
                mac = self._esp_airtag_buffer.get('mac', '')
                if mac:
                    self.session.upsert_bluetooth(
                        mac, f"AirTag #{self._esp_airtag_buffer.get('tag', '?')}",
                        self._esp_airtag_buffer.get('rssi', -80),
                        'AirTag', gps_lat, gps_lon, gps_alt
                    )
                    self._esp_ble_count += 1
                    logger.info(f"[HuginnESP] AirTag found: {mac}")
                self._esp_airtag_buffer = None
                return
            elif line.startswith('Payload'):
                return  # Skip payload data line
            else:
                self._esp_airtag_buffer = None

        # === Flipper detection ===
        # Format: "Found White Flipper Device: \nMAC: xx:xx:xx:xx:xx:xx, \nName: xxx, \nRSSI: -70"
        flipper_match = re.match(
            r'Found\s+(White|Black|Transparent)\s+Flipper\s+Device',
            line
        )
        if flipper_match:
            self._current_esp_mode = 'ble-filtered'
            self._esp_flipper_buffer = {'color': flipper_match.group(1)}
            return
        if hasattr(self, '_esp_flipper_buffer') and self._esp_flipper_buffer:
            if line.startswith('MAC:'):
                self._esp_flipper_buffer['mac'] = line.split(':', 1)[1].strip().rstrip(',').upper()
                return
            elif line.startswith('Name:'):
                self._esp_flipper_buffer['name'] = line.split(':', 1)[1].strip().rstrip(',')
                return
            elif line.startswith('RSSI:'):
                rssi_val = re.search(r'-?\d+', line)
                rssi = int(rssi_val.group()) if rssi_val else -80
                buf = self._esp_flipper_buffer
                mac = buf.get('mac', '')
                if mac:
                    name = f"Flipper {buf.get('color', '')} {buf.get('name', '')}".strip()
                    self.session.upsert_bluetooth(mac, name, rssi, 'Flipper', gps_lat, gps_lon, gps_alt)
                    self._esp_ble_count += 1
                    logger.info(f"[HuginnESP] Flipper found: {name} @ {mac}")
                self._esp_flipper_buffer = {}
                return
            else:
                self._esp_flipper_buffer = {}

        # === BLE spam detection ===
        if 'BLE Spam detected' in line:
            self._current_esp_mode = 'ble-all'
            logger.warning(f"[HuginnESP] {line}")
            if not hasattr(self, '_esp_alerts'):
                self._esp_alerts = []
            self._esp_alerts.append({'time': time.time(), 'alert': line})
            return

        # === Generic BLE line (MAC: ... Name: ... RSSI: ...) ===
        # Require ALL THREE fields to be present so we don't false-positive on
        # banners or stray "MAC: ..." debug lines from non-BLE devices (e.g.,
        # Piglet, which has zero BLE code in firmware). A real BLE scan result
        # always carries MAC + Name/Device + RSSI together.
        ble_match = re.match(
            r'MAC(?:\s*Address)?:\s*([0-9a-fA-F:]{17}).*?(?:Name|Device):\s*(.+?).*?RSSI:\s*(-?\d+)',
            line
        )
        if ble_match:
            self._current_esp_mode = 'ble-all'
            mac = ble_match.group(1).upper()
            name = ble_match.group(2).strip().rstrip(',')
            rssi = int(ble_match.group(3))
            self.session.upsert_bluetooth(mac, name, rssi, 'BLE', gps_lat, gps_lon, gps_alt)
            self._esp_ble_count += 1
            return

        # Try JSON format first (HuginnESP style)
        if line.startswith('{'):
            try:
                data = json.loads(line)
                mac = data.get('mac', data.get('bssid', '')).upper()
                if not mac or len(mac) < 12:
                    return
                ssid = data.get('ssid', data.get('name', ''))
                rssi = int(data.get('rssi', data.get('signal', -80)))
                channel = int(data.get('channel', 0))
                auth = data.get('auth', data.get('security', data.get('encryption', '')))
                lat = data.get('lat', data.get('latitude', gps_lat))
                lon = data.get('lon', data.get('longitude', gps_lon))
                alt = data.get('alt', data.get('altitude', gps_alt))
                record_type = data.get('type', 'WIFI').upper()

                if lat:
                    lat = float(lat)
                if lon:
                    lon = float(lon)
                if alt:
                    alt = float(alt)

                if record_type in ('BT', 'BLE', 'BLUETOOTH'):
                    self._current_esp_mode = 'ble-all'
                    self.session.upsert_bluetooth(mac, ssid, rssi, 'BLE', lat, lon, alt)
                    self._esp_ble_count += 1
                else:
                    self._current_esp_mode = 'wifi'
                    freq = 0
                    if channel:
                        freq = (2407 + channel * 5) if channel <= 14 else (5000 + channel * 5)
                    is_new = self.session.upsert_network(
                        bssid=mac, ssid=ssid, security=auth,
                        channel=channel, frequency=freq, rssi=rssi,
                        lat=lat, lon=lon, alt=alt, speed=None, hdop=None,
                        interface='esp32-serial'
                    )
                    if is_new:
                        self.serial_networks += 1
                return
            except (json.JSONDecodeError, ValueError):
                pass

        # Try HuginnESP multi-line text format:
        # [N] SSID: Name,
        #      BSSID: AA:BB:CC:DD:EE:FF,
        #      RSSI: -70,
        #      Channel: 6,
        #      Band: 2.4GHz,
        #      Security: WPA2
        entry_start = re.match(r'^\[(\d+)\]\s*SSID:\s*(.*?)(?:,\s*)?$', line)
        if entry_start:
            self._current_esp_mode = 'wifi'
            # Flush previous buffered entry if exists
            if self._serial_entry_buffer.get('bssid'):
                self._flush_serial_entry(gps_lat, gps_lon, gps_alt)
            self._serial_entry_buffer = {'ssid': entry_start.group(2).strip().rstrip(',')}
            return

        # Parse continuation lines of a multi-line entry
        if self._serial_entry_buffer is not None and 'ssid' in self._serial_entry_buffer:
            kv = re.match(r'^\s*(BSSID|RSSI|Channel|Band|Security|Vendor|PMF):\s*(.*?)(?:,\s*)?$', line)
            if kv:
                key = kv.group(1).lower()
                val = kv.group(2).strip().rstrip(',')
                self._serial_entry_buffer[key] = val
                return
            else:
                # Non-matching line means entry is complete
                if self._serial_entry_buffer.get('bssid'):
                    self._flush_serial_entry(gps_lat, gps_lon, gps_alt)
                self._serial_entry_buffer = {}

        # === WiGLE CSV (Piglet) ===
        # Header-driven so we survive format changes. Piglet emits two banner
        # lines per logging session:
        #   WigleWifi-1.4,appRelease=1,...           ← format banner
        #   MAC,SSID,AuthMode,FirstSeen,Channel,...  ← column header
        # We capture the column header into a name→index map and use that map
        # for all subsequent data rows. Falls back to legacy 1.4 positional
        # layout if no header has been observed (handles firmware that
        # streams data rows before sending a banner).
        if line.startswith('WigleWifi-'):
            # Piglet v2.5 emits WigleWifi-1.6; older firmware emits 1.4. The
            # next non-empty line will be the column-name row.
            self._current_esp_mode = 'wifi'
            self._wigle_expect_header = True
            self._wigle_col_map = None  # reset — about to receive fresh header
            return

        # Try WiGLE CSV format (Piglet style)
        # Use csv.reader to correctly handle quoted fields that contain
        # commas (e.g. SSID "Johansson 2,4Ghz").  Simple split(',') would
        # break those into multiple columns and shift everything.
        try:
            parts = next(csv.reader([line]))
        except (csv.Error, StopIteration):
            parts = line.split(',')  # fallback
        # Capture column header if we're expecting one. Recognize by the
        # presence of 'MAC' or 'BSSID' as the first column, which uniquely
        # identifies the header row vs a data row (data row[0] is a MAC
        # address that wouldn't equal the literal string 'MAC').
        if self._wigle_expect_header and parts and parts[0].strip().upper() in ('MAC', 'BSSID'):
            col_map = {}
            for i, h in enumerate(parts):
                key = h.strip().lower()
                if key in ('mac', 'bssid'):
                    col_map['mac'] = i
                elif key == 'ssid':
                    col_map['ssid'] = i
                elif key in ('authmode', 'security', 'auth'):
                    col_map['auth'] = i
                elif key in ('firstseen', 'first_seen'):
                    col_map['firstseen'] = i
                elif key == 'channel':
                    col_map['channel'] = i
                elif key == 'frequency':
                    col_map['frequency'] = i
                elif key == 'rssi':
                    col_map['rssi'] = i
                elif key in ('currentlatitude', 'latitude', 'lat'):
                    col_map['lat'] = i
                elif key in ('currentlongitude', 'longitude', 'lon'):
                    col_map['lon'] = i
                elif key in ('altitudemeters', 'altitude', 'alt'):
                    col_map['alt'] = i
                elif key in ('accuracymeters', 'accuracy'):
                    col_map['acc'] = i
                elif key == 'type':
                    col_map['type'] = i
            if 'mac' in col_map:
                self._wigle_col_map = col_map
                logger.info(f"Piglet WiGLE column map detected: {len(col_map)} fields")
            self._wigle_expect_header = False
            return

        # Data row — requires at least 8 columns for the minimum useful set
        if len(parts) < 8:
            return
        mac = parts[0].strip().upper()
        if not re.match(r'^[0-9A-F]{2}(:[0-9A-F]{2}){5}$', mac):
            return

        # Use captured header map if available; otherwise fall back to the
        # legacy WiGLE-1.4 positional layout so pre-banner data isn't lost.
        cm = self._wigle_col_map or {
            'mac': 0, 'ssid': 1, 'auth': 2, 'firstseen': 3,
            'channel': 4, 'rssi': 5, 'lat': 6, 'lon': 7,
            'alt': 8, 'acc': 9, 'type': 10,
        }

        # Auto-detect WiGLE 1.6 column shift: Piglet v2.5+ inserts a
        # Frequency column between Channel (4) and RSSI (5→6), pushing
        # every subsequent field right by one.  WiFi RSSI is always
        # negative (dBm), so a positive value at the legacy RSSI position
        # means it's actually a frequency.  Promote to 1.6 layout once
        # and cache it so all subsequent rows parse correctly.
        # Piglet's full 14-column format (WiGLE 1.6):
        #   MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,
        #   Lat,Lon,Alt,Acc,RCOIs,MfgrId,Type
        if not self._wigle_col_map and len(parts) > 11:
            try:
                probe = int(parts[5].strip())
            except (ValueError, TypeError):
                probe = -80
            if probe > 0:
                cm = {
                    'mac': 0, 'ssid': 1, 'auth': 2, 'firstseen': 3,
                    'channel': 4, 'frequency': 5, 'rssi': 6, 'lat': 7,
                    'lon': 8, 'alt': 9, 'acc': 10, 'type': 13,
                }
                self._wigle_col_map = cm
                logger.info("Auto-detected WiGLE 1.6 layout (Frequency column at position 5)")

        def _field(name, default=''):
            idx = cm.get(name)
            if idx is None or idx >= len(parts):
                return default
            return parts[idx].strip()

        ssid = _field('ssid')
        # Piglet wraps SSIDs in double quotes — strip them
        if ssid.startswith('"') and ssid.endswith('"'):
            ssid = ssid[1:-1]
        auth = _field('auth')
        try:
            channel = int(_field('channel') or 0)
        except (ValueError, TypeError):
            channel = 0
        try:
            rssi = int(_field('rssi') or -80)
        except (ValueError, TypeError):
            rssi = -80
        # Frequency from header if present (WiGLE 1.6+), else derive from channel
        try:
            freq_str = _field('frequency')
            freq = int(freq_str) if freq_str else 0
        except (ValueError, TypeError):
            freq = 0
        if not freq and channel:
            freq = (2407 + channel * 5) if channel <= 14 else (5000 + channel * 5)
        try:
            lat = float(_field('lat')) if _field('lat') else gps_lat
            lon = float(_field('lon')) if _field('lon') else gps_lon
            alt = float(_field('alt')) if _field('alt') else gps_alt
        except (ValueError, TypeError):
            lat, lon = gps_lat, gps_lon
            alt = gps_alt

        # Piglet reports 0.000000,0.000000 when it has no GPS fix — fall
        # back to the Pi's own GPS so the network still gets a position.
        if lat is not None and lon is not None and lat == 0.0 and lon == 0.0:
            lat = gps_lat
            lon = gps_lon
            alt = gps_alt

        record_type = (_field('type') or 'WIFI').upper()

        if record_type in ('BT', 'BLE'):
            self._current_esp_mode = 'ble-all'
            self.session.upsert_bluetooth(mac, ssid, rssi, 'BLE', lat, lon, alt)
        elif record_type in ('GSM', 'CDMA', 'LTE', 'UMTS', 'CELL'):
            self.session.upsert_cell_tower(
                cell_id=mac, tech=record_type, provider=ssid,
                signal_dbm=rssi, lat=lat, lon=lon
            )
        else:
            self._current_esp_mode = 'wifi'
            is_new = self.session.upsert_network(
                bssid=mac, ssid=ssid, security=auth,
                channel=channel, frequency=freq, rssi=rssi,
                lat=lat, lon=lon, alt=alt, speed=None, hdop=None,
                interface='esp32-serial'
            )
            if is_new:
                self.serial_networks += 1

    def _flush_serial_entry(self, gps_lat, gps_lon, gps_alt):
        """Flush a buffered HuginnESP multi-line entry to the session."""
        buf = self._serial_entry_buffer
        bssid = buf.get('bssid', '').upper()
        if not bssid or len(bssid) < 12:
            return

        ssid = buf.get('ssid', '')
        if ssid == '(Hidden)':
            ssid = ''
        security = buf.get('security', '')
        channel = 0
        try:
            channel = int(buf.get('channel', 0))
        except (ValueError, TypeError):
            pass
        rssi = -80
        try:
            rssi = int(buf.get('rssi', -80))
        except (ValueError, TypeError):
            pass

        freq = 0
        if channel:
            freq = (2407 + channel * 5) if channel <= 14 else (5000 + channel * 5)

        is_new = self.session.upsert_network(
            bssid=bssid, ssid=ssid, security=security,
            channel=channel, frequency=freq, rssi=rssi,
            lat=gps_lat, lon=gps_lon, alt=gps_alt, speed=None, hdop=None,
            interface='esp32-serial'
        )
        if is_new:
            self.serial_networks += 1
