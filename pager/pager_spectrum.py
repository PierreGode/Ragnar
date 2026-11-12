"""
Ragnar WiFi Spectrum Waterfall - native Pineapple Pager app.

A passive tri-band (2.4 / 5 / 6 GHz) RF spectrum analyser and scrolling
waterfall rendered directly on the Pager's 480x222 LCD. It uses the Pager's
OWN monitor radio (wlan1mon): it retunes across every channel the radio
supports, captures 802.11 frames through a raw AF_PACKET socket, and reads the
per-frame radiotap RSSI. No external SDR, no HackRF, no extra binaries - just
the radio that is already in the device.

Controls on the Pager:
    UP / DOWN   cycle band   (ALL -> 2.4 -> 5 -> 6 GHz)
    GREEN (A)   pause / resume the sweep
    RED   (B)   exit back to the menu
    LEFT/RIGHT  screen brightness

Entry points:
    run_spectrum(gfx, font_small, font_mono)   reuse an existing Pager context
    python3 pager_spectrum.py                  standalone (inits its own display)
"""

import os
import sys
import time
import socket
import struct
import threading
import subprocess
from collections import deque

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))
_lib_path = os.path.join(PAYLOAD_DIR, 'lib')
if os.path.exists(_lib_path) and _lib_path not in sys.path:
    sys.path.insert(0, _lib_path)

from pagerctl import Pager  # noqa: E402

DATA_DIR = os.path.join(PAYLOAD_DIR, 'data')
FONTS_DIR = os.path.join(PAYLOAD_DIR, 'resources', 'fonts')
_FONT_MONO = os.path.join(FONTS_DIR, 'DejaVuSansMono.ttf')
if not os.path.exists(_FONT_MONO):
    _FONT_MONO = os.path.join(FONTS_DIR, 'Arial.ttf')

# ------------------------------------------------------------------ channels

def _chan_2g():
    # 2.4 GHz: channels 1..13 (14 is Japan-only / usually disabled)
    return [(2407 + 5 * ch, ch, '2.4') for ch in range(1, 14)]

def _chan_5g():
    # 5 GHz 20 MHz channels (UNII-1/2/2e/3). DFS ones are attempted and skipped
    # if the radio refuses the retune.
    chans = [36, 40, 44, 48, 52, 56, 60, 64,
             100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
             149, 153, 157, 161, 165]
    return [(5000 + 5 * ch, ch, '5') for ch in chans]

def _chan_6g():
    # 6 GHz 20 MHz channels: 1, 5, 9, ... centres 5955 MHz + 20 MHz steps.
    out = []
    ch = 1
    freq = 5955
    while freq <= 7115:
        out.append((freq, ch, '6'))
        freq += 20
        ch += 4
    return out

BANDS = ['ALL', '2.4', '5', '6']

def channels_for(band):
    if band == '2.4':
        return _chan_2g()
    if band == '5':
        return _chan_5g()
    if band == '6':
        return _chan_6g()
    return _chan_2g() + _chan_5g() + _chan_6g()

# Band accent colours
BAND_RGB = {
    '2.4': (80, 230, 120),   # green
    '5':   (70, 200, 255),   # cyan
    '6':   (230, 120, 255),  # magenta
}
BAND_RGB_565 = {k: Pager.rgb(*v) for k, v in BAND_RGB.items()}

# ------------------------------------------------------------------ palette

def _build_inferno():
    """256-entry inferno-ish palette as RGB565, floor lifted so the field glows."""
    anchors = [
        (0.00, (0, 0, 4)), (0.14, (40, 11, 84)), (0.29, (101, 21, 110)),
        (0.43, (159, 42, 99)), (0.57, (212, 72, 66)), (0.71, (245, 125, 21)),
        (0.86, (250, 193, 39)), (1.00, (252, 255, 164)),
    ]
    pal = []
    for i in range(256):
        t = i / 255.0
        for k in range(len(anchors) - 1):
            t0, c0 = anchors[k]
            t1, c1 = anchors[k + 1]
            if t0 <= t <= t1:
                f = (t - t0) / (t1 - t0) if t1 > t0 else 0.0
                r = int(c0[0] + (c1[0] - c0[0]) * f)
                g = int(c0[1] + (c1[1] - c0[1]) * f)
                b = int(c0[2] + (c1[2] - c0[2]) * f)
                break
        else:
            r, g, b = anchors[-1][1]
        pal.append(Pager.rgb(r, g, b))
    return pal

INFERNO = _build_inferno()

def scale_rgb(rgb, t):
    """Scale an (r,g,b) tuple by intensity t (0..1) -> RGB565, with a floor."""
    t = 0.0 if t < 0 else (1.0 if t > 1 else t)
    f = 0.25 + 0.75 * t
    return Pager.rgb(int(rgb[0] * f), int(rgb[1] * f), int(rgb[2] * f))

# ------------------------------------------------------------------ radiotap

def radiotap_rssi(buf):
    """Return dBm antenna-signal from a radiotap-prefixed frame, or None."""
    if len(buf) < 8:
        return None
    _ver, _pad, rtlen = struct.unpack_from('<BBH', buf, 0)
    present0, = struct.unpack_from('<I', buf, 4)
    pos = 8
    present = present0
    while present & (1 << 31):            # skip extended present words
        if pos + 4 > len(buf):
            return None
        present, = struct.unpack_from('<I', buf, pos)
        pos += 4

    def align(p, a):
        return p + ((a - (p % a)) % a)

    if present0 & (1 << 0):               # TSFT      u64, align 8
        pos = align(pos, 8) + 8
    if present0 & (1 << 1):               # Flags     u8
        pos += 1
    if present0 & (1 << 2):               # Rate      u8
        pos += 1
    if present0 & (1 << 3):               # Channel   u16+u16, align 2
        pos = align(pos, 2) + 4
    if present0 & (1 << 4):               # FHSS      u16
        pos += 2
    if present0 & (1 << 5):               # dBm AntSignal  s8
        if pos < len(buf) and pos < rtlen:
            return struct.unpack_from('<b', buf, pos)[0]
    return None

def parse_mgmt(buf):
    """Parse a beacon / probe-response. Returns (bssid, ssid, channel, enc) or
    None. Passive: reads only what the AP broadcasts."""
    blen = len(buf)
    if blen < 4:
        return None
    rtlen = struct.unpack_from('<H', buf, 2)[0]
    o = rtlen
    if o + 36 > blen:
        return None
    fc = buf[o]
    if (fc & 0x0C) != 0x00:                # not a management frame
        return None
    sub = fc & 0xF0
    if sub != 0x80 and sub != 0x50:        # beacon (0x80) / probe-resp (0x50)
        return None
    bssid = buf[o + 16:o + 22]
    cap = struct.unpack_from('<H', buf, o + 34)[0]
    enc = bool(cap & 0x10)                 # privacy bit
    p = o + 36                             # tagged parameters
    ssid = ''
    channel = None
    while p + 2 <= blen:
        tid = buf[p]
        tlen = buf[p + 1]
        p += 2
        if p + tlen > blen:
            break
        if tid == 0:                       # SSID
            raw = buf[p:p + tlen]
            try:
                ssid = raw.decode('utf-8').rstrip('\x00')
            except Exception:
                ssid = raw.decode('latin-1', 'replace')
        elif tid == 3 and tlen >= 1:       # DS parameter set -> channel
            channel = buf[p]
        elif tid == 48:                    # RSN -> WPA2/3
            enc = True
        p += tlen
    bssid_s = ':'.join('%02x' % b for b in bssid)
    return (bssid_s, ssid, channel, enc)

def find_monitor_iface():
    """Pick a monitor-mode interface, preferring the tri-band one (wlan1mon)."""
    try:
        out = subprocess.check_output(['iw', 'dev'], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    mons = []
    cur = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('Interface '):
            cur = line.split()[1]
        elif line.startswith('type ') and cur and 'monitor' in line:
            mons.append(cur)
    for pref in ('wlan1mon', 'wlan0mon'):
        if pref in mons:
            return pref
    return mons[0] if mons else None

# ------------------------------------------------------------------ sweeper

RSSI_FLOOR = -95.0
RSSI_CEIL = -35.0

def rssi_to_t(rssi):
    if rssi is None:
        return 0.0
    t = (rssi - RSSI_FLOOR) / (RSSI_CEIL - RSSI_FLOOR)
    return 0.0 if t < 0 else (1.0 if t > 1 else t)

class Sweeper(threading.Thread):
    """Background radio sweep. Retunes the monitor iface channel by channel,
    captures briefly, and records peak RSSI + frame count per channel."""

    def __init__(self, dev, dwell=0.06):
        super().__init__(daemon=True)
        self.dev = dev
        self.dwell = dwell
        self.lock = threading.Lock()
        self.band = 'ALL'
        self.channels = channels_for('ALL')
        self.n = len(self.channels)
        self.inten = [0.0] * self.n          # smoothed 0..1 per channel
        self.rssi = [None] * self.n
        self.cur = -1                        # channel index being measured
        self.newest = None                   # most recent completed sweep row
        self.hist_count = 0                  # increments once per completed sweep
        self.best = (-999, -1)               # (rssi, channel index) strongest
        self.best_band = '2.4'
        self.paused = False
        self.stop_flag = False
        self._sock = None
        # passive network inventory: bssid -> [ssid, ch, band, rssi, enc, seen]
        self.aps = {}

    def led_info(self):
        with self.lock:
            return (self.best[0], self.best_band)

    def set_band(self, band):
        with self.lock:
            self.band = band
            self.channels = channels_for(band)
            self.n = len(self.channels)
            self.inten = [0.0] * self.n
            self.rssi = [None] * self.n
            self.cur = -1
            self.newest = None
            self.hist_count = 0
            self.best = (-999, -1)

    def _open(self):
        try:
            subprocess.run(['ip', 'link', 'set', self.dev, 'up'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((self.dev, 0))
        s.settimeout(self.dwell)
        self._sock = s

    def run(self):
        try:
            self._open()
        except Exception:
            return
        while not self.stop_flag:
            if self.paused:
                time.sleep(0.1)
                continue
            with self.lock:
                chans = list(self.channels)
            row = []
            for j, (freq, chlabel, bandlabel) in enumerate(chans):
                if self.stop_flag:
                    break
                with self.lock:
                    self.cur = j
                subprocess.run(['iw', 'dev', self.dev, 'set', 'freq', str(freq)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                peak = None
                nfr = 0
                now = time.time()
                t_end = now + self.dwell
                try:
                    self._sock.settimeout(self.dwell)
                    while time.time() < t_end:
                        try:
                            buf = self._sock.recv(2048)
                        except socket.timeout:
                            break
                        except Exception:
                            break
                        nfr += 1
                        sg = radiotap_rssi(buf)
                        if sg is not None and -110 < sg < -10:
                            if peak is None or sg > peak:
                                peak = sg
                        # passive AP discovery from beacons / probe responses
                        mg = parse_mgmt(buf)
                        if mg is not None:
                            bssid, ssid, dch, enc = mg
                            rs = sg if sg is not None else -100
                            with self.lock:
                                ap = self.aps.get(bssid)
                                if ap is None:
                                    self.aps[bssid] = [ssid, dch or chlabel,
                                                       bandlabel, rs, enc, now]
                                else:
                                    if ssid:
                                        ap[0] = ssid
                                    if dch:
                                        ap[1] = dch
                                    ap[2] = bandlabel
                                    ap[3] = max(ap[3], rs)
                                    ap[4] = ap[4] or enc
                                    ap[5] = now
                except Exception:
                    pass
                t_sig = rssi_to_t(peak)
                t_act = min(1.0, nfr / 18.0)
                t = max(t_sig, t_act * 0.6)
                with self.lock:
                    if j < self.n:
                        # smooth so the display does not strobe
                        self.inten[j] = 0.55 * self.inten[j] + 0.45 * t
                        self.rssi[j] = peak
                row.append(t)
            with self.lock:
                if row and len(row) == self.n:
                    self.newest = row
                    self.hist_count += 1
                    # strongest channel for the footer (computed here, not per frame)
                    best = (-999, -1)
                    for jj in range(self.n):
                        r = self.rssi[jj]
                        if r is not None and r > best[0]:
                            best = (r, jj)
                    self.best = best
                    if best[1] >= 0 and best[1] < len(self.channels):
                        self.best_band = self.channels[best[1]][2]

    def snapshot(self):
        """Cheap per-frame snapshot: copy only the small live vector, never the
        whole history (that deep copy was the main render-thread cost)."""
        with self.lock:
            return (list(self.inten), self.n, self.cur, self.band,
                    self.best, self.hist_count, self.newest,
                    self.channels)

    def networks(self, band=None):
        """AP inventory as rows [ssid, ch, band, rssi, enc], strongest first,
        optionally filtered to a band ('2.4'/'5'/'6'); 'ALL'/None = all."""
        with self.lock:
            rows = [list(v) for v in self.aps.values()]
        if band and band != 'ALL':
            rows = [r for r in rows if r[2] == band]
        rows.sort(key=lambda r: r[3], reverse=True)
        return rows

    def ap_count(self):
        return len(self.aps)

    def ap_channels(self, band):
        """Light (band, channel) list for spectrum markers - no copy/sort."""
        with self.lock:
            if band and band != 'ALL':
                return [(v[2], v[1]) for v in self.aps.values()
                        if v[2] == band and v[1]]
            return [(v[2], v[1]) for v in self.aps.values() if v[1]]

    def export_csv(self, path):
        """Write the discovered networks to a CSV so a sweep leaves real recon
        output behind. Returns the row count, or -1 on failure."""
        try:
            with self.lock:
                items = list(self.aps.items())
            if not items:
                return 0
            import csv
            with open(path, 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(['bssid', 'ssid', 'band_ghz', 'channel', 'rssi_dbm', 'encryption'])
                for bssid, (ssid, ch, band, rssi, enc, seen) in items:
                    w.writerow([bssid, ssid, band, ch if ch else '',
                                rssi, 'WPA/WPA2' if enc else 'open'])
            return len(items)
        except Exception:
            return -1

    def best_24_channel(self):
        """Least-congested 2.4 GHz channel among 1/6/11 (overlap-weighted)."""
        with self.lock:
            vals = [v for v in self.aps.values() if v[2] == '2.4' and v[1]]
        load = {1: 0.0, 6: 0.0, 11: 0.0}
        for ssid, ch, band, rssi, enc, seen in vals:
            w = _rssi_t(rssi) + 0.2
            for c in (1, 6, 11):
                if ch is None:
                    continue
                d = abs(ch - c)
                if d == 0:
                    load[c] += w
                elif d <= 4:
                    load[c] += w * (1.0 - d / 5.0)   # adjacent-channel overlap
        return min(load, key=load.get)

    def stats(self):
        """Counts for the summary view: (total, open, enc, per-band dict)."""
        with self.lock:
            vals = list(self.aps.values())
        total = len(vals)
        enc = sum(1 for v in vals if v[4])
        per = {'2.4': 0, '5': 0, '6': 0}
        for v in vals:
            if v[2] in per:
                per[v[2]] += 1
        return (total, total - enc, enc, per)

    def stop(self):
        self.stop_flag = True
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

# ------------------------------------------------------------------ render

COL_BG = Pager.rgb(6, 8, 16)
COL_GRID = Pager.rgb(30, 38, 54)
COL_TITLE = Pager.rgb(120, 210, 255)
COL_TEXT = Pager.rgb(190, 200, 215)
COL_DIM = Pager.rgb(110, 120, 140)
COL_PEAK = Pager.rgb(255, 255, 255)

# Layout (480x222 landscape)
W, H = 480, 222
SX = 2
SPAN = W - 4
SPEC_Y0, SPEC_H = 20, 108       # spectrum region
WF_Y0 = SPEC_Y0 + SPEC_H + 2    # waterfall top
WF_ROWS = 7
WF_RH = 6
FOOT_Y = WF_Y0 + WF_ROWS * WF_RH + 1

# Display columns: the radio delivers N channel samples; we interpolate them to
# COLS smooth columns so the trace is a flowing curve, not a few fat bars. COLS
# also bounds the per-frame draw cost (each column is ~1 vline ~= 0.32 ms on
# this MIPS LCD; clear+flip is only ~4 ms), so ~96 cols -> ~20 fps.
COLS = 64
COLW = SPAN / float(COLS)
# Waterfall is rendered at a coarse fixed resolution with MAX-POOLing (a step
# function, not interpolation) and heavy quantisation, so flat noise-floor
# regions collapse to long run-length spans and the per-frame cost stays low and
# roughly band-independent. (Interpolating sparse channels defeats RLE.)
WF_COLS = 24
WF_CW = SPAN / float(WF_COLS)
WF_LEVELS = 6
PEAK_STEP = 5                   # draw the peak-hold as an envelope every N cols

# Vertical spectrum gradient (cool -> warm by height), precomputed RGB565.
def _build_spec_grad():
    stops = [(0.0, (20, 60, 120)), (0.35, (30, 190, 180)),
             (0.6, (120, 230, 90)), (0.8, (250, 210, 60)), (1.0, (255, 90, 70))]
    out = []
    for i in range(SPEC_H + 1):
        t = i / float(SPEC_H)
        for k in range(len(stops) - 1):
            t0, c0 = stops[k]
            t1, c1 = stops[k + 1]
            if t0 <= t <= t1:
                f = (t - t0) / (t1 - t0) if t1 > t0 else 0.0
                out.append(Pager.rgb(int(c0[0] + (c1[0] - c0[0]) * f),
                                     int(c0[1] + (c1[1] - c0[1]) * f),
                                     int(c0[2] + (c1[2] - c0[2]) * f)))
                break
        else:
            out.append(Pager.rgb(*stops[-1][1]))
    return out

SPEC_GRAD = _build_spec_grad()

def _downsample(vec, d):
    """Collapse vec to d values by max-pooling each group (step, RLE-friendly)."""
    n = len(vec)
    if n <= d:
        return list(vec) + [0.0] * (d - n)
    out = []
    for i in range(d):
        a = i * n // d
        b = (i + 1) * n // d
        if b <= a:
            b = a + 1
        seg = vec[a:b]
        out.append(max(seg) if seg else 0.0)
    return out

def _interp(vec, d):
    """Resample vec to d points with linear interpolation (smooth curve)."""
    n = len(vec)
    if n == 0:
        return [0.0] * d
    if n == 1:
        return [vec[0]] * d
    out = []
    for i in range(d):
        p = i * (n - 1) / float(d - 1) if d > 1 else 0.0
        a = int(p)
        b = min(a + 1, n - 1)
        f = p - a
        out.append(vec[a] * (1.0 - f) + vec[b] * f)
    return out

BASE_Y = SPEC_Y0 + SPEC_H
TITLE_BG = Pager.rgb(14, 18, 30)
BAND_LBL = Pager.rgb(255, 210, 90)
# Precompute column x positions (avoids float math in the hot loop).
_SPEC_X = [int(SX + j * COLW) for j in range(COLS)]
_WF_X = [int(SX + j * WF_CW) for j in range(WF_COLS + 1)]
_PEAK_X = [int(SX + j * COLW) for j in range(0, COLS, PEAK_STEP)]

class RenderState:
    """Holds the smoothed display vectors so motion eases between radio sweeps."""
    def __init__(self):
        self.disp = [0.0] * COLS     # eased spectrum heights
        self.peak = [0.0] * COLS     # peak-hold
        self.wf = deque(maxlen=WF_ROWS)   # quantised waterfall rows
        self.last_hist = -1
        self.imap = None             # cached interp map for the current n
        self.map_n = -1
        self._marks = []             # cached AP marker (x,color) list
        self._mark_tick = 0

    def markers(self, swp, band, chans, n):
        """AP channel markers for the spectrum baseline, refreshed occasionally
        (cheap: recomputed ~3x/sec, not every frame)."""
        self._mark_tick -= 1
        if self._mark_tick > 0:
            return self._marks
        self._mark_tick = 8
        # map (band, channel) -> column index
        idx = {}
        for j, (_f, ch, b) in enumerate(chans):
            idx[(b, ch)] = j
        out = []
        for b, ch in swp.ap_channels(band):
            j = idx.get((b, ch))
            if j is None:
                continue
            x = int(SX + (j / float(max(1, n - 1))) * SPAN) if n > 1 else SX
            out.append((min(W - 2, max(SX, x)), BAND_RGB_565.get(b, COL_TEXT)))
        self._marks = out
        return out

    def interp_map(self, n):
        """(a, b, f) per output column for resampling n -> COLS; cached."""
        if n == self.map_n:
            return self.imap
        m = []
        if n <= 1:
            m = [(0, 0, 0.0)] * COLS
        else:
            for i in range(COLS):
                p = i * (n - 1) / float(COLS - 1)
                a = int(p)
                b = a + 1 if a + 1 < n else a
                m.append((a, b, p - a))
        self.imap = m
        self.map_n = n
        return m

def _draw_spectrum(gfx, swp, st, font, blink):
    inten, n, cur, band, best, hist_count, newest, chans = swp.snapshot()

    # NOTE: all per-frame text uses the built-in BITMAP font (draw_text), not
    # draw_ttf - TrueType rasterisation costs ~10 ms each and tanked the frame
    # rate when called several times per frame.
    gfx.clear(COL_BG)
    gfx.fill_rect(0, 0, W, 14, TITLE_BG)
    gfx.draw_text(4, 3, "RAGNAR SPECTRUM", COL_TITLE, 1)
    blabel = "ALL" if band == 'ALL' else band + "G"
    gfx.draw_text(W - gfx.text_width(blabel, 1) - 4, 3, blabel, BAND_LBL, 1)

    if n == 0:
        gfx.draw_text_centered(100, "scanning...", COL_DIM, 2)
        gfx.flip()
        return

    # resample channel intensities -> COLS (cached map), then ease toward it
    imap = st.interp_map(n)
    disp, peak = st.disp, st.peak
    for j in range(COLS):
        a, b, f = imap[j]
        tgt = inten[a] * (1.0 - f) + inten[b] * f
        d0 = disp[j]
        d0 = d0 + (tgt - d0) * 0.35
        disp[j] = d0
        pk = peak[j]
        if d0 > pk:
            peak[j] = d0
        elif pk > d0:
            pk -= 0.012
            peak[j] = d0 if pk < d0 else pk

    # faint scope grid
    gfx.hline(SX, SPEC_Y0 + SPEC_H // 3, SPAN, Pager.rgb(20, 26, 40))
    gfx.hline(SX, SPEC_Y0 + 2 * SPEC_H // 3, SPAN, Pager.rgb(20, 26, 40))
    gfx.hline(SX, BASE_Y, SPAN, COL_GRID)

    # --- live sweep cursor at the channel currently being measured
    if 0 <= cur < n:
        cxx = int(SX + (cur / float(max(1, n - 1))) * SPAN) if n > 1 else SX
        gfx.vline(cxx, SPEC_Y0, SPEC_H, Pager.rgb(60, 72, 96))

    # --- spectrum: a filled column per bin, coloured by height (solid curve)
    cwpx = int(COLW) + 1
    for j in range(COLS):
        h = int(disp[j] * SPEC_H)
        if h > 0:
            gfx.fill_rect(_SPEC_X[j], BASE_Y - h, cwpx, h, SPEC_GRAD[h])

    # --- band separators + labels (ALL mode) show where 2.4/5/6 begin
    if band == 'ALL' and n > 1:
        prev = None
        for j in range(n):
            b = chans[j][2]
            if b != prev:
                xx = int(SX + (j / float(n - 1)) * SPAN)
                gfx.vline(xx, SPEC_Y0, SPEC_H, Pager.rgb(40, 48, 66))
                gfx.draw_text(xx + 2, SPEC_Y0 + 1, b + "G", BAND_RGB_565.get(b, COL_DIM), 1)
                prev = b

    # --- peak-hold as a light envelope polyline (cheap)
    px = py = None
    pi = 0
    for j in range(0, COLS, PEAK_STEP):
        x = _PEAK_X[pi]; pi += 1
        y = BASE_Y - int(peak[j] * SPEC_H)
        if px is not None:
            gfx.line(px, py, x, y, COL_PEAK)
        px, py = x, y

    # --- append a waterfall row once per completed radio sweep (max-pool -> RLE)
    if newest is not None and hist_count != st.last_hist:
        st.last_hist = hist_count
        row = _downsample(newest, WF_COLS)
        st.wf.appendleft([min(WF_LEVELS - 1, int(v * WF_LEVELS)) for v in row])

    # --- waterfall: coarse grid, run-length encoded per row
    yoff = WF_Y0
    for qrow in st.wf:
        j = 0
        while j < WF_COLS:
            q = qrow[j]
            k = j + 1
            while k < WF_COLS and qrow[k] == q:
                k += 1
            gfx.fill_rect(_WF_X[j], yoff, max(1, _WF_X[k] - _WF_X[j]), WF_RH,
                          INFERNO[(q * 255) // (WF_LEVELS - 1)])
            j = k
        yoff += WF_RH

    # --- AP markers: a tick at the baseline for each discovered AP's channel
    marks = st.markers(swp, band, chans, n)
    for mx, mcol in marks:
        gfx.vline(mx, BASE_Y - 4, 4, mcol)
        gfx.fill_rect(mx - 1, BASE_Y - 7, 3, 3, mcol)

    # --- footer
    gfx.hline(0, FOOT_Y, W, COL_GRID)
    naps = swp.ap_count()
    if best[1] >= 0 and best[1] < n:
        _f, ch, b = chans[best[1]]
        info = "%d APs  peak ch%d %ddBm" % (naps, ch, best[0])
    else:
        info = "%d APs  scanning..." % naps
    gfx.draw_text(4, FOOT_Y + 3, info, COL_TEXT, 1)
    hint = "A=view RED=exit"
    gfx.draw_text(W - gfx.text_width(hint, 1) - 4, FOOT_Y + 3, hint, COL_DIM, 1)

    gfx.flip()

# ------------------------------------------------------------------ networks view

def _rssi_t(r):
    t = (r + 92) / 57.0
    return 0.0 if t < 0 else (1.0 if t > 1 else t)

def _draw_networks(gfx, swp, band, scroll, font):
    rows = swp.networks(band)
    gfx.clear(COL_BG)
    gfx.fill_rect(0, 0, W, 14, TITLE_BG)
    head = "NETWORKS  %s  %d" % ("ALL" if band == 'ALL' else band + "G", len(rows))
    gfx.draw_text(4, 3, head, COL_TITLE, 1)
    hint = "A=view RED=exit"
    gfx.draw_text(W - gfx.text_width(hint, 1) - 4, 3, hint, COL_DIM, 1)

    row_h = 17
    top = 18
    visible = (FOOT_Y - top) // row_h
    if scroll > max(0, len(rows) - visible):
        scroll = max(0, len(rows) - visible)
    shown = rows[scroll:scroll + visible]

    y = top
    bar_x = W - 92
    for ssid, ch, b, rssi, enc, seen in shown:
        bcol = BAND_RGB_565.get(b, COL_TEXT)
        gfx.fill_rect(2, y + 1, 4, row_h - 3, bcol)           # band chip
        name = ssid if ssid else "<hidden>"
        if len(name) > 20:
            name = name[:19] + "…"
        gfx.draw_text(10, y + 1, name, COL_TEXT if ssid else COL_DIM, 1)
        lock = "#" if enc else "o"                              # locked / open
        gfx.draw_text(10, y + 9, "%s ch%s %sG" % (lock, ch if ch else "?", b),
                      COL_DIM, 1)
        # RSSI bar
        t = _rssi_t(rssi)
        gfx.fill_rect(bar_x, y + 3, 60, 8, Pager.rgb(24, 30, 44))
        gfx.fill_rect(bar_x, y + 3, int(60 * t), 8,
                      SPEC_GRAD[int(t * SPEC_H)])
        gfx.draw_text(bar_x + 64, y + 3, "%d" % rssi, COL_TEXT, 1)
        y += row_h

    if not rows:
        gfx.draw_text_centered(100, "listening for beacons...", COL_DIM, 1)

    gfx.hline(0, FOOT_Y, W, COL_GRID)
    foot = "UP/DN=scroll  LT/RT=band  %d/%d" % (
        min(scroll + visible, len(rows)), len(rows))
    gfx.draw_text(4, FOOT_Y + 3, foot, COL_DIM, 1)
    gfx.flip()
    return scroll

# ------------------------------------------------------------------ stats view

def _draw_stats(gfx, swp, band, font):
    total, nopen, nenc, per = swp.stats()
    rows = swp.networks('ALL')
    gfx.clear(COL_BG)
    gfx.fill_rect(0, 0, W, 14, TITLE_BG)
    gfx.draw_text(4, 3, "RF SURVEY", COL_TITLE, 1)
    hint = "A=view RED=exit"
    gfx.draw_text(W - gfx.text_width(hint, 1) - 4, 3, hint, COL_DIM, 1)

    # headline counters
    def big(x, label, value, col):
        gfx.draw_text(x, 22, str(value), col, 3)
        gfx.draw_text(x, 46, label, COL_DIM, 1)
    big(16, "NETWORKS", total, COL_TITLE)
    big(176, "OPEN", nopen, Pager.rgb(255, 120, 90))
    big(300, "SECURED", nenc, Pager.rgb(90, 230, 140))

    # per-band bars
    y = 72
    maxc = max(1, per['2.4'], per['5'], per['6'])
    for b in ('2.4', '5', '6'):
        c = per[b]
        gfx.draw_text(6, y, b + "G", BAND_RGB_565[b], 1)
        gfx.fill_rect(34, y, 420, 10, Pager.rgb(22, 28, 40))
        gfx.fill_rect(34, y, int(420 * c / maxc), 10, BAND_RGB_565[b])
        gfx.draw_text(460 - gfx.text_width(str(c), 1), y, str(c), COL_TEXT, 1)
        y += 18

    # strongest few
    gfx.hline(4, y + 2, W - 8, COL_GRID)
    y += 8
    gfx.draw_text(6, y, "STRONGEST", COL_DIM, 1)
    y += 12
    for ssid, ch, b, rssi, enc, seen in rows[:3]:
        name = (ssid or "<hidden>")[:22]
        gfx.fill_rect(6, y + 1, 4, 10, BAND_RGB_565.get(b, COL_TEXT))
        gfx.draw_text(14, y, "%-22s %sG ch%s %ddBm" % (name, b, ch or "?", rssi),
                      COL_TEXT, 1)
        y += 14

    # channel recommendation (classic analyser feature)
    if per['2.4'] > 0:
        rec = swp.best_24_channel()
        msg = "clearest 2.4: ch %d" % rec
        gfx.draw_text(W - gfx.text_width(msg, 1) - 6, y, msg, Pager.rgb(90, 230, 140), 1)

    gfx.hline(0, FOOT_Y, W, COL_GRID)
    gfx.draw_text(4, FOOT_Y + 3, "passive survey - no packets sent", COL_DIM, 1)
    gfx.flip()

# ------------------------------------------------------------------ app loop

VIEW_SPECTRUM, VIEW_NETWORKS, VIEW_STATS = 0, 1, 2
VIEW_NAMES = ('spectrum', 'networks', 'survey')

def _splash(gfx, font):
    """Short radar-sweep intro. Skips instantly on any button press."""
    import math
    cx, cy, R = W // 2, 118, 86
    t0 = gfx.get_ticks()
    frames = 26
    for i in range(frames):
        ang = (i / float(frames)) * 2 * math.pi * 1.3
        gfx.clear(COL_BG)
        # concentric rings
        for r in range(20, R + 1, 22):
            gfx.circle(cx, cy, r, Pager.rgb(24, 40, 54))
        gfx.circle(cx, cy, R, Pager.rgb(40, 90, 110))
        # sweep line + fading trail
        for k in range(6):
            a = ang - k * 0.16
            col = Pager.rgb(20 + k * 6, 120 - k * 16, 90 - k * 12)
            gfx.line(cx, cy, int(cx + R * math.cos(a)), int(cy + R * math.sin(a)), col)
        # a few blips
        for bx, by in ((0.4, -0.3), (-0.6, 0.2), (0.1, 0.7), (-0.2, -0.6)):
            gfx.fill_circle(int(cx + bx * R), int(cy + by * R), 2, Pager.rgb(90, 230, 140))
        gfx.draw_text_centered(14, "R A G N A R", COL_TITLE, 3)
        gfx.draw_text_centered(40, "RF OBSERVATORY", Pager.rgb(120, 170, 210), 1)
        gfx.draw_text_centered(210, "tri-band passive spectrum", COL_DIM, 1)
        gfx.flip()
        ev = gfx.get_input_event()
        if ev and ev[1] == Pager.EVENT_PRESS:
            break
        gfx.delay(32)
    _ = t0

def run_spectrum(gfx, font_mono=None):
    """Run the RF observatory UI on an existing Pager context until the user
    presses RED. Returns None."""
    font = font_mono or _FONT_MONO
    dev = find_monitor_iface()
    if not dev:
        gfx.clear(COL_BG)
        gfx.draw_ttf_centered(70, "No monitor radio", Pager.rgb(255, 120, 60), font, 18.0)
        gfx.draw_ttf_centered(100, "wlan1mon not found", COL_DIM, font, 13.0)
        gfx.flip()
        _wait_any(gfx)
        return None

    # Start on 2.4 GHz: few channels -> a fast, lively sweep.
    band_idx = BANDS.index('2.4')
    swp = Sweeper(dev)
    swp.set_band(BANDS[band_idx])
    swp.start()
    st = RenderState()
    view = VIEW_SPECTRUM
    scroll = 0
    try:
        _splash(gfx, font)
    except Exception:
        pass
    try:
        gfx.clear_input_events()
    except Exception:
        pass

    tick = 0
    exit_req = False
    while not exit_req:
        # drain every pending input so buttons feel immediate
        while True:
            ev = gfx.get_input_event()
            if not ev:
                break
            button, etype, _ts = ev
            if etype != Pager.EVENT_PRESS:
                continue
            if button == Pager.BTN_B:
                exit_req = True
                break
            elif button == Pager.BTN_A:                 # cycle view
                view = (view + 1) % 3
                scroll = 0
            elif button == Pager.BTN_UP:
                if view == VIEW_NETWORKS:
                    scroll = max(0, scroll - 1)
                else:
                    band_idx = (band_idx + 1) % len(BANDS)
                    swp.set_band(BANDS[band_idx]); st = RenderState()
            elif button == Pager.BTN_DOWN:
                if view == VIEW_NETWORKS:
                    scroll += 1
                else:
                    band_idx = (band_idx - 1) % len(BANDS)
                    swp.set_band(BANDS[band_idx]); st = RenderState()
            elif button == Pager.BTN_LEFT:
                if view == VIEW_NETWORKS:
                    band_idx = (band_idx - 1) % len(BANDS)
                    swp.set_band(BANDS[band_idx])
                else:
                    _bright(gfx, -1)
            elif button == Pager.BTN_RIGHT:
                if view == VIEW_NETWORKS:
                    band_idx = (band_idx + 1) % len(BANDS)
                    swp.set_band(BANDS[band_idx])
                else:
                    _bright(gfx, +1)
        if exit_req:
            break

        tick += 1
        if tick % 3 == 0:
            _update_leds(gfx, swp, tick // 3)
        if view == VIEW_SPECTRUM:
            _draw_spectrum(gfx, swp, st, font, (tick // 4) % 2 == 0)
        elif view == VIEW_NETWORKS:
            scroll = _draw_networks(gfx, swp, BANDS[band_idx], scroll, font)
            time.sleep(0.03)        # list is static-ish; no need to spin hot
        else:
            _draw_stats(gfx, swp, BANDS[band_idx], font)
            time.sleep(0.05)

    swp.stop()
    try:
        gfx.led_all_off()
    except Exception:
        pass
    # leave recon output behind
    try:
        out = os.path.join(DATA_DIR, 'spectrum_networks.csv')
        os.makedirs(DATA_DIR, exist_ok=True)
        nrows = swp.export_csv(out)
        if nrows and nrows > 0:
            gfx.clear(COL_BG)
            gfx.draw_text_centered(90, "saved %d networks" % nrows, Pager.rgb(90, 230, 140), 2)
            gfx.draw_text_centered(120, "data/spectrum_networks.csv", COL_DIM, 1)
            gfx.flip()
            time.sleep(1.1)
    except Exception:
        pass
    time.sleep(0.05)
    return None

_LED_DIRS = ('up', 'right', 'down', 'left')

def _update_leds(gfx, swp, phase):
    """Physical radar sweep on the 4 d-pad LEDs: one lit position rotates, tinted
    by the strongest band and pulsing with its signal strength."""
    try:
        rssi, band = swp.led_info()
        t = _rssi_t(rssi if rssi is not None else -95)
        base = BAND_RGB.get(band, (120, 160, 200))
        lit = phase % 4
        for i, d in enumerate(_LED_DIRS):
            s = (1.0 if i == lit else 0.12) * (0.25 + 0.75 * t)
            gfx.led_rgb(d, int(base[0] * s), int(base[1] * s), int(base[2] * s))
    except Exception:
        pass

def _bright(gfx, d):
    try:
        cur = gfx.get_brightness()
        mx = gfx.get_max_brightness()
        gfx.set_brightness(max(1, min(mx, cur + d)))
    except Exception:
        pass

def _wait_any(gfx):
    while True:
        ev = gfx.get_input_event()
        if ev and ev[1] == Pager.EVENT_PRESS:
            return
        time.sleep(0.02)

# ------------------------------------------------------------------ standalone

def main():
    gfx = Pager()
    gfx.init()
    gfx.set_rotation(270)
    try:
        gfx.clear_input_events()
    except Exception:
        pass
    try:
        run_spectrum(gfx)
    finally:
        try:
            gfx.clear(Pager.BLACK)
            gfx.flip()
            gfx.cleanup()
        except Exception:
            pass

if __name__ == '__main__':
    main()
