"""CC1101 sub-GHz sweep against a register-level model of the chip.

The model answers SPI transactions the way the CC1101 does (strobes, single
and burst writes, status reads) and reports an RSSI that depends on the
frequency it was last tuned to, so a sweep must tune correctly to see the
simulated transmitter."""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cc1101_scan as cs  # noqa: E402

TX_STROBES = {0x35, 0x31}        # STX, SFSTXON: never allowed


class FakeChip:
    def __init__(self, carrier_mhz=433.92, lock=True):
        self.reg = {}
        self.strobes = []
        self.state = "idle"
        self.carrier = carrier_mhz
        self.lock = lock
        self.switch = []

    def freq_mhz(self):
        word = (self.reg.get(0x0D, 0) << 16) | (self.reg.get(0x0E, 0) << 8) | self.reg.get(0x0F, 0)
        return word * cs.XTAL_HZ / 65536.0 / 1e6

    def xfer(self, data):
        head = data[0]
        if len(data) == 1:                              # command strobe
            self.strobes.append(head)
            assert head not in TX_STROBES, "transmit strobe sent"
            if head == cs.SRES:
                self.reg, self.state = {}, "idle"
            elif head == cs.SIDLE:
                self.state = "idle"
            elif head == cs.SRX:
                self.state = "rx" if self.lock else "idle"
            return [0x0F]
        if head & 0x80:                                 # read
            if head == cs.MARCSTATE:
                return [0x0F, cs.MARC_RX if self.state == "rx" else 0x01]
            if head == cs.RSSI:
                assert self.state == "rx", "RSSI read outside receive"
                near = abs(self.freq_mhz() - self.carrier) < 0.08
                dbm = -40 if near else -100
                return [0x0F, int((dbm + cs.RSSI_OFFSET_DB) * 2) & 0xFF]
            return [0x0F, self.reg.get(head & 0x3F, 0)]
        if head & 0x40:                                 # burst write
            for i, value in enumerate(data[1:]):
                self.reg[(head & 0x3F) + i] = value
        else:
            self.reg[head] = data[1]
        return [0x0F] * len(data)


@pytest.fixture
def sweeper(monkeypatch):
    s = cs._Sweeper()
    monkeypatch.setattr(cs, "_sweeper", s)
    monkeypatch.setattr(cs, "detect", lambda: {"available": True})
    yield s
    s.stop()


def attach(sweeper, chip):
    closed = []
    sweeper.make_radio = lambda: (cs.CC1101(chip.xfer, chip.switch.append, sleep=lambda t: None),
                                  lambda: closed.append(True))
    return closed


def wait_frames(n=1, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        data = cs.get_frames()
        if len(data["frames"]) >= n or data["error"]:
            return data
        time.sleep(0.01)
    return cs.get_frames()


# ── pure helpers ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,dbm", [(0, -74.0), (20, -64.0), (128, -138.0), (255, -74.5), (200, -102.0)])
def test_rssi_conversion(raw, dbm):
    assert cs.rssi_dbm(raw) == dbm


def test_frequency_word_round_trips():
    for mhz in (315.0, 433.92, 868.3, 915.0):
        b = cs.freq_word(mhz * 1e6)
        back = ((b[0] << 16) | (b[1] << 8) | b[2]) * cs.XTAL_HZ / 65536.0 / 1e6
        assert abs(back - mhz) < 0.0005
    assert cs.freq_word(433.92e6) == [0x10, 0xB0, 0x71]      # data-sheet value


@pytest.mark.parametrize("mhz,expected", [(315, (False, 0x6F)), (433.92, (True, 0x2F)),
                                          (868, (True, 0x6F)), (915, (True, 0x6F))])
def test_antenna_path_follows_the_band(mhz, expected):
    assert cs.antenna_for(mhz) == expected


@pytest.mark.parametrize("mhz,ok", [(300, True), (348, True), (360, False), (433, True),
                                    (500, False), (868, True), (928, True), (950, False)])
def test_tunable_ranges(mhz, ok):
    assert cs.tunable(mhz) is ok


def test_sweep_plan_leaves_no_gaps():
    for lo, hi in list(cs.BANDS.values()) + [(387.0, 464.0), (433.0, 433.5)]:
        freqs, bandwidth, step = cs.plan_sweep(lo, hi)
        assert 2 <= len(freqs) <= cs.MAX_POINTS + 1
        assert abs(freqs[0] - lo * 1e6) < 1 and abs(freqs[-1] - hi * 1e6) <= step
        assert bandwidth[0] >= step or bandwidth is cs._BANDWIDTHS[-1]


# ── the sweep ────────────────────────────────────────────────────────────────

def test_sweep_finds_the_transmitter_and_never_transmits(sweeper):
    chip = FakeChip(carrier_mhz=433.92)
    closed = attach(sweeper, chip)
    assert cs.start(band="433")["ok"]
    data = wait_frames(2)
    assert data["error"] is None and data["running"]
    row = data["frames"][-1]["power"]
    lo, hi = data["band_mhz"]
    assert len(row) == data["bins"]
    peak = max(range(len(row)), key=row.__getitem__)
    peak_mhz = lo + (hi - lo) * peak / (len(row) - 1)
    assert abs(peak_mhz - 433.92) < 0.1 and row[peak] == -40
    assert sorted(set(row)) == [-100, -40]
    assert data["max_hold"][peak] == -40 and data["rbw_hz"] > 0
    cs.stop()
    assert closed == [True] and chip.state == "idle"
    assert not set(chip.strobes) & TX_STROBES
    assert set(chip.strobes) <= {cs.SRES, cs.SRX, cs.SIDLE}
    assert chip.switch == [True]                        # 433 MHz path, set once
    assert chip.reg[cs.IOCFG2] == 0x2F


def test_frames_since_returns_only_new_rows(sweeper):
    attach(sweeper, FakeChip())
    cs.start(band="868")
    first = wait_frames(2)
    seq = first["frames"][-1]["seq"]
    later = cs.get_frames(since=seq)
    assert all(f["seq"] > seq for f in later["frames"])
    assert cs.status()["band_mhz"] == [863.0, 870.0]


def test_no_synthesiser_lock_stops_with_an_error(sweeper):
    attach(sweeper, FakeChip(lock=False))
    cs.start(band="433")
    data = wait_frames(1)
    assert data["frames"] == [] and "never entered receive" in data["error"]
    assert wait_until(lambda: not cs.get_frames()["running"])


def wait_until(predicate, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return False


@pytest.mark.parametrize("kwargs,word", [
    ({"band": "2.4"}, "unknown band"),
    ({"lo_mhz": 350, "hi_mhz": 380}, "300-348"),
    ({"lo_mhz": 340, "hi_mhz": 400}, "300-348"),
    ({"lo_mhz": 434, "hi_mhz": 433}, "empty span")])
def test_spans_the_chip_cannot_tune_are_refused(sweeper, kwargs, word):
    chip = FakeChip()
    attach(sweeper, chip)
    result = cs.start(**kwargs)
    assert result["ok"] is False and word in result["error"]
    assert chip.strobes == []                           # the radio was never touched


def test_no_cap_means_no_sweep(monkeypatch):
    s = cs._Sweeper()
    monkeypatch.setattr(cs, "_sweeper", s)
    monkeypatch.setattr(cs, "detect", lambda: {"available": False, "error": "no CC1101 answers on SPI"})
    s.make_radio = lambda: pytest.fail("must not open the radio")
    assert cs.start(band="433") == {"ok": False, "error": "no CC1101 answers on SPI"}


def test_detect_never_writes_cc1101_registers_to_a_lora_cap(monkeypatch):
    """Both Caps sit on the same chip-select. A LoRa Cap must be recognised
    first, so its SX1262 is never sent CC1101 commands."""
    import cardputer_caps as caps
    monkeypatch.setattr(cs, "_detect_cache", {"at": 0.0, "value": None})
    monkeypatch.setattr(caps, "is_cardputer_zero", lambda cfg=None: True)
    monkeypatch.setattr(caps, "_identity", None)
    monkeypatch.setattr(caps, "probe_lora_cap", lambda: True)
    monkeypatch.setattr(caps, "probe_cc1101", lambda: pytest.fail("SPI probe on a LoRa Cap"))
    monkeypatch.setattr(caps, "power_on_cap", lambda: True)
    info = cs.detect()
    assert info["available"] is False and "LoRa Cap" in info["error"]


def test_detect_uses_the_cap_found_at_start(monkeypatch):
    """Caps are not hot-swappable: no bus probing after the first look."""
    import cardputer_caps as caps
    monkeypatch.setattr(caps, "is_cardputer_zero", lambda cfg=None: True)
    monkeypatch.setattr(caps, "power_on_cap", lambda: True)
    monkeypatch.setattr(caps, "probe_lora_cap", lambda: pytest.fail("re-probed I2C"))
    monkeypatch.setattr(caps, "probe_cc1101", lambda: pytest.fail("re-probed SPI"))
    monkeypatch.setattr(caps, "_identity", ("subghz_nfc", 0x14))
    monkeypatch.setattr(cs, "_detect_cache", {"at": 0.0, "value": None})
    assert cs.detect()["available"] is True and cs.detect()["version"] == 0x14
    monkeypatch.setattr(caps, "_identity", ("none", None))
    monkeypatch.setattr(cs, "_detect_cache", {"at": 0.0, "value": None})
    assert "power off to fit one" in cs.detect()["error"]


def test_detect_on_another_board_is_quiet(monkeypatch):
    import cardputer_caps as caps
    monkeypatch.setattr(cs, "_detect_cache", {"at": 0.0, "value": None})
    monkeypatch.setattr(caps, "is_cardputer_zero", lambda cfg=None: False)
    monkeypatch.setattr(caps, "probe_cc1101", lambda: pytest.fail("no SPI on other boards"))
    assert cs.detect()["available"] is False
