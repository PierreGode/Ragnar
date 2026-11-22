#!/usr/bin/env python3
# cc1101_scan.py
"""
Sub-GHz spectrum sweep with a CC1101, as an RF Waterfall source.

Built for the M5Stack CardputerZero's "Cap CC1101" (see cardputer_caps.py),
which puts the radio on SPI0 CS1. The CC1101 is a narrow-band transceiver, not
an SDR: there is no FFT. The sweep steps the synthesiser across the band and
reads the RSSI register at each step, which gives a coarse but honest picture
of who is transmitting in the 315 / 433 / 868 / 915 MHz ISM bands.

Receive only. This module never keys the transmitter: the only strobes it
sends are reset, idle and receive.

Same shape as the other waterfall sources (sdr_spectrum.py, esp_sdr.py):
module-level detect() / start() / stop() / status() / get_frames(since).

CLI:  sudo python3 cc1101_scan.py [band]     print one sweep (band: 315/433/868/915)
"""

import logging
import sys
import threading
import time

try:
    from logger import Logger
    logger = Logger(name="cc1101_scan.py", level=logging.INFO)
except Exception:  # standalone / CLI use
    logger = logging.getLogger("cc1101_scan")

XTAL_HZ = 26_000_000

# Command strobes
SRES, SRX, SIDLE = 0x30, 0x34, 0x36
# Registers
IOCFG2, IOCFG0 = 0x00, 0x02
PKTCTRL0, FSCTRL1 = 0x08, 0x0B
FREQ2 = 0x0D
MDMCFG4, MDMCFG3, MDMCFG2, MDMCFG1, MDMCFG0 = 0x10, 0x11, 0x12, 0x13, 0x14
MCSM1, MCSM0 = 0x17, 0x18
AGCCTRL2, AGCCTRL1, AGCCTRL0 = 0x1B, 0x1C, 0x1D
FREND1 = 0x21
FSCAL3, FSCAL2, FSCAL1, FSCAL0 = 0x23, 0x24, 0x25, 0x26
TEST2, TEST1, TEST0 = 0x2C, 0x2D, 0x2E
# Status registers (read with the burst bit)
RSSI = 0x34 | 0xC0
MARCSTATE = 0x35 | 0xC0
MARC_RX = 0x0D
WRITE_BURST, READ_SINGLE = 0x40, 0x80

# The synthesiser only locks inside these ranges (CC1101 data sheet).
TUNING_RANGES_MHZ = ((300.0, 348.0), (387.0, 464.0), (779.0, 928.0))

# Preset bands: id -> (low MHz, high MHz)
BANDS = {
    "315": (310.0, 320.0),
    "433": (430.0, 440.0),
    "868": (863.0, 870.0),
    "915": (902.0, 928.0),
}
_DEFAULT_BAND = "433"

MAX_POINTS = 256            # steps per sweep: more is slower, not sharper
MIN_STEP_HZ = 25_000
_RING_FRAMES = 300
_FLOOR_DBM = -120
RSSI_OFFSET_DB = 74         # data sheet offset for the CC1101

# Receiver bandwidth choices: (bandwidth Hz, MDMCFG4 high nibble, TEST2, TEST1)
_BANDWIDTHS = ((58_000, 0xF0, 0x81, 0x35), (102_000, 0xC0, 0x81, 0x35),
               (203_000, 0x80, 0x81, 0x35), (406_000, 0x40, 0x88, 0x31),
               (812_000, 0x00, 0x88, 0x31))


def rssi_dbm(raw):
    """RSSI register (two's complement, 0.5 dB steps) -> dBm."""
    if raw >= 128:
        raw -= 256
    return raw / 2.0 - RSSI_OFFSET_DB


def freq_word(freq_hz):
    """The three FREQ register bytes for a carrier frequency."""
    word = int(round(freq_hz * 65536.0 / XTAL_HZ))
    return [(word >> 16) & 0xFF, (word >> 8) & 0xFF, word & 0xFF]


def tunable(freq_mhz):
    return any(lo <= freq_mhz <= hi for lo, hi in TUNING_RANGES_MHZ)


def antenna_for(freq_mhz):
    """The Cap's matching network for a frequency -> (RF_SW0 level, IOCFG2
    value). IOCFG2 0x6F drives the chip's GDO2 pin (RF_SW1) high, 0x2F low.
    Thresholds are the ones M5Stack's driver uses."""
    if freq_mhz < 374.0:
        return False, 0x6F          # 315 MHz path
    if freq_mhz < 650.5:
        return True, 0x2F           # 433 MHz path
    return True, 0x6F               # 868 / 915 MHz path


def plan_sweep(lo_mhz, hi_mhz):
    """Step frequencies (Hz) and the receiver bandwidth entry for a span."""
    span_hz = (hi_mhz - lo_mhz) * 1e6
    step = max(MIN_STEP_HZ, span_hz / MAX_POINTS)
    points = max(2, int(round(span_hz / step)) + 1)
    freqs = [lo_mhz * 1e6 + i * step for i in range(points)]
    # Bandwidth just wide enough that neighbouring steps overlap: no gaps.
    bandwidth = next((b for b in _BANDWIDTHS if b[0] >= step), _BANDWIDTHS[-1])
    return freqs, bandwidth, step


class CC1101:
    """Just enough of the chip to read signal strength at a frequency."""

    def __init__(self, transfer, set_rf_switch=None, sleep=time.sleep):
        self._xfer = transfer                    # f(list[int]) -> list[int]
        self._set_rf_switch = set_rf_switch or (lambda level: None)
        self._sleep = sleep
        self._antenna = None

    def strobe(self, command):
        self._xfer([command])

    def write(self, register, value):
        self._xfer([register, value & 0xFF])

    def read_status(self, register):
        return self._xfer([register, 0x00])[1]

    def configure(self, bandwidth):
        _, mdmcfg4, test2, test1 = bandwidth
        self.strobe(SRES)
        self._sleep(0.002)
        for register, value in (
                (IOCFG0, 0x2E),            # GDO0 high-impedance
                (PKTCTRL0, 0x32),          # asynchronous serial, no packet engine
                (FSCTRL1, 0x06),           # IF frequency
                (MDMCFG4, mdmcfg4 | 0x0C), (MDMCFG3, 0x22),
                (MDMCFG2, 0x30),           # ASK/OOK, no sync word
                (MDMCFG1, 0x22), (MDMCFG0, 0xF8),
                (MCSM1, 0x3C),             # stay in receive
                (MCSM0, 0x18),             # calibrate on every idle -> receive
                (AGCCTRL2, 0x43), (AGCCTRL1, 0x40), (AGCCTRL0, 0x91),
                (FREND1, 0x56),
                (FSCAL3, 0xE9), (FSCAL2, 0x2A), (FSCAL1, 0x00), (FSCAL0, 0x1F),
                (TEST2, test2), (TEST1, test1), (TEST0, 0x09)):
            self.write(register, value)
        self._antenna = None

    def measure(self, freq_hz, settle=0.0008):
        """Tune, enter receive, return the RSSI in dBm (None if the chip
        never reached receive, e.g. the synthesiser did not lock)."""
        antenna = antenna_for(freq_hz / 1e6)
        self.strobe(SIDLE)
        if antenna != self._antenna:
            self._set_rf_switch(antenna[0])
            self.write(IOCFG2, antenna[1])
            self._antenna = antenna
        self._xfer([FREQ2 | WRITE_BURST] + freq_word(freq_hz))
        self.strobe(SRX)
        for _ in range(12):                      # calibration takes ~0.75 ms
            if self.read_status(MARCSTATE) & 0x1F == MARC_RX:
                break
            self._sleep(0.0004)
        else:
            return None
        self._sleep(settle)
        return rssi_dbm(self.read_status(RSSI))

    def idle(self):
        self.strobe(SIDLE)


class _Sweeper:
    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop = threading.Event()
        self._frames = []
        self._seq = 0
        self._maxhold = None
        self._band = None
        self._lo_mhz = self._hi_mhz = None
        self._points = 0
        self._rbw = None
        self._error = None
        self._restore_pin = None
        # Hardware access, replaceable in tests.
        self.make_radio = self._default_radio

    # -- hardware ----------------------------------------------------------
    def _default_radio(self):
        import cardputer_caps as caps
        import spidev
        spi = spidev.SpiDev()
        spi.open(0, 1)
        spi.max_speed_hz = 500000
        spi.mode = 0
        # G14 drives the Cap's RF_SW0. It is normally the UART's TX pin, so
        # remember its function and give it back when the sweep stops.
        function, _ = caps.read_gpio(14)
        self._restore_pin = function if function and function not in ("op", "ip") else None
        radio = CC1101(spi.xfer2, lambda level: caps.set_gpio(14, level))
        return radio, spi.close

    def _release(self, closer):
        try:
            closer()
        except Exception:
            pass
        if self._restore_pin:
            try:
                import shutil
                import subprocess
                subprocess.run([shutil.which("pinctrl") or "pinctrl", "set", "14", self._restore_pin],
                               capture_output=True, timeout=5)
            except Exception:
                pass
            self._restore_pin = None

    # -- control -----------------------------------------------------------
    def start(self, band=_DEFAULT_BAND, lo_mhz=None, hi_mhz=None):
        if lo_mhz is None or hi_mhz is None:
            if band not in BANDS:
                return {"ok": False, "error": "unknown band"}
            lo_mhz, hi_mhz = BANDS[band]
        lo_mhz, hi_mhz = float(lo_mhz), float(hi_mhz)
        if hi_mhz <= lo_mhz:
            return {"ok": False, "error": "empty span"}
        if not (tunable(lo_mhz) and tunable(hi_mhz)) or antenna_for(lo_mhz) != antenna_for(hi_mhz):
            return {"ok": False, "error": "the CC1101 tunes 300-348, 387-464 and 779-928 MHz; "
                                          "keep the span inside one of those"}
        det = detect()
        if not det.get("available"):
            return {"ok": False, "error": det.get("error", "no CC1101")}
        self.stop()
        freqs, bandwidth, step = plan_sweep(lo_mhz, hi_mhz)
        with self._lock:
            self._band, self._lo_mhz, self._hi_mhz = band, lo_mhz, hi_mhz
            self._points, self._rbw = len(freqs), bandwidth[0]
            self._frames, self._maxhold, self._error = [], None, None
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, args=(freqs, bandwidth),
                                        name="cc1101-sweep", daemon=True)
        self._thread.start()
        logger.info(f"CC1101 sweep {lo_mhz}-{hi_mhz} MHz, {len(freqs)} steps of "
                    f"{step / 1000:.0f} kHz, bandwidth {bandwidth[0] / 1000:.0f} kHz")
        return {"ok": True, "band_mhz": [lo_mhz, hi_mhz], "points": len(freqs)}

    def stop(self):
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=5)
        return {"ok": True}

    def _run(self, freqs, bandwidth):
        closer = lambda: None   # noqa: E731
        try:
            radio, closer = self.make_radio()
            radio.configure(bandwidth)
            misses = 0
            while not self._stop.is_set():
                row = []
                for freq in freqs:
                    if self._stop.is_set():
                        break
                    level = radio.measure(freq)
                    if level is None:
                        misses += 1
                        level = _FLOOR_DBM
                    row.append(level)
                else:
                    if misses >= len(freqs):
                        raise RuntimeError("the CC1101 never entered receive (no synthesiser lock)")
                    misses = 0
                    self._push(row)
            radio.idle()
        except Exception as e:
            logger.error(f"CC1101 sweep stopped: {e}")
            with self._lock:
                self._error = str(e)
        finally:
            self._release(closer)

    def _push(self, row):
        ints = [int(round(v)) for v in row]
        with self._lock:
            self._seq += 1
            self._frames.append({"seq": self._seq, "ts": time.time(), "power": ints})
            if len(self._frames) > _RING_FRAMES:
                self._frames = self._frames[-_RING_FRAMES:]
            self._maxhold = (list(ints) if self._maxhold is None or len(self._maxhold) != len(ints)
                             else [max(a, b) for a, b in zip(self._maxhold, ints)])

    # -- readers -----------------------------------------------------------
    def running(self):
        return bool(self._thread and self._thread.is_alive())

    def status(self):
        with self._lock:
            return {"running": self.running(), "band": self._band,
                    "frames_buffered": len(self._frames), "seq": self._seq,
                    "bins": self._points, "rbw_hz": self._rbw, "error": self._error,
                    "band_mhz": [self._lo_mhz, self._hi_mhz] if self._lo_mhz else None,
                    "floor_dbm": _FLOOR_DBM}

    def get_frames(self, since=0):
        try:
            since = int(since)
        except (TypeError, ValueError):
            since = 0
        with self._lock:
            return {"frames": [f for f in self._frames if f["seq"] > since],
                    "seq": self._seq, "band": self._band,
                    "band_mhz": [self._lo_mhz, self._hi_mhz] if self._lo_mhz else None,
                    "bins": self._points, "floor_dbm": _FLOOR_DBM, "rbw_hz": self._rbw,
                    "max_hold": list(self._maxhold) if self._maxhold else None,
                    "running": self.running(), "error": self._error}


_sweeper = _Sweeper()
_detect_cache = {"at": 0.0, "value": None}
_DETECT_TTL = 15


def detect():
    """Whether a CC1101 Cap is fitted. Never touches the SPI bus while a
    sweep is running (the answer is then known), and is cached briefly."""
    if _sweeper.running():
        return {"available": True, "streaming": True, "model_name": "CC1101",
                "board": "Cap CC1101", "bands": sorted(BANDS)}
    now = time.monotonic()
    if _detect_cache["value"] is not None and now - _detect_cache["at"] < _DETECT_TTL:
        return dict(_detect_cache["value"])
    try:
        import cardputer_caps as caps
        config = caps.saved_config()
        caps.allow_expander(config)
        if not caps.is_cardputer_zero(config):
            value = {"available": False, "error": "needs a CardputerZero with the Cap CC1101"}
        else:
            # Caps are not hot-swappable: use the Cap identified at start
            # instead of probing the buses again.
            caps.power_on_cap()
            cap, version = caps.identify_cap()
            if cap == caps.CAP_LORA_GNSS:
                value = {"available": False, "error": "the LoRa Cap is fitted, not the CC1101 Cap"}
            elif cap != caps.CAP_SUBGHZ_NFC:
                value = {"available": False,
                         "error": "no CC1101 Cap was found at start (power off to fit one)"}
            else:
                value = {"available": True, "model_name": "CC1101", "board": "Cap CC1101",
                         "version": version, "bands": sorted(BANDS),
                         "range_mhz": [list(r) for r in TUNING_RANGES_MHZ]}
    except Exception as e:
        value = {"available": False, "error": str(e)}
    _detect_cache.update(at=now, value=value)
    return dict(value)


def start(band=_DEFAULT_BAND, lo_mhz=None, hi_mhz=None):
    return _sweeper.start(band=band, lo_mhz=lo_mhz, hi_mhz=hi_mhz)


def stop():
    return _sweeper.stop()


def status():
    st = _sweeper.status()
    st["detect"] = detect()
    return st


def get_frames(since=0):
    return _sweeper.get_frames(since)


def main():
    band = sys.argv[1] if len(sys.argv) > 1 else _DEFAULT_BAND
    result = start(band=band)
    if not result.get("ok"):
        print(f"Cannot sweep: {result.get('error')}")
        return 1
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not get_frames()["frames"] and _sweeper.running():
        time.sleep(0.1)
    data = get_frames()
    stop()
    if not data["frames"]:
        print(f"No sweep completed: {data.get('error') or 'timed out'}")
        return 1
    row = data["frames"][-1]["power"]
    lo, hi = data["band_mhz"]
    peak = max(range(len(row)), key=row.__getitem__)
    print(f"{lo}-{hi} MHz, {len(row)} steps: min {min(row)} dBm, max {max(row)} dBm "
          f"at {lo + (hi - lo) * peak / (len(row) - 1):.3f} MHz")
    return 0


if __name__ == "__main__":
    sys.exit(main())
