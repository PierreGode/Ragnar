"""Ragnar's GPS for the Meshtastic node on this unit, the standby GPS reader
behind it, and camera detection that does not come and go."""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import meshtastic_node as mn  # noqa: E402
import pi_camera as pc  # noqa: E402


class Iface:
    def __init__(self):
        self.sent = []

    def sendPosition(self, latitude=0.0, longitude=0.0, altitude=0):
        self.sent.append((latitude, longitude, altitude))


@pytest.fixture
def link(monkeypatch):
    lk = mn.MeshLink()
    lk._iface, lk._connected, lk._host = Iface(), True, "127.0.0.1:4403"
    fix = {"pos": {"lat": 59.3293, "lon": 18.0686, "alt": 31.6}}
    monkeypatch.setattr(mn, "_position_source", lambda: fix["pos"])
    monkeypatch.setattr(mn, "_share_enabled", lambda: True)
    monkeypatch.setattr(mn, "_position_release", None)
    lk.fix = fix
    return lk


def test_the_fix_is_handed_to_the_node_on_this_machine(link):
    assert link.share_position(now=1000) is True
    assert link._iface.sent == [(59.3293, 18.0686, 32)]
    assert link.status()["gps_shared"] == {"lat": 59.3293, "lon": 18.0686, "alt": 32, "ts": 1000}


def test_standing_still_sends_every_two_minutes_moving_sends_sooner(link):
    link.share_position(now=1000)
    assert link.share_position(now=1060) is False             # same place, too soon
    assert link.share_position(now=1000 + mn.SHARE_EVERY_SECONDS) is True
    link.fix["pos"] = {"lat": 59.3303, "lon": 18.0686, "alt": 30}   # ~110 m north
    assert link.share_position(now=1130) is False             # never under 30 s apart
    assert link.share_position(now=1160) is True
    assert len(link._iface.sent) == 3


@pytest.mark.parametrize("pos", [None, {}, {"lat": None, "lon": 18.0}, {"lat": 0.0, "lon": 0.0},
                                 {"lat": 95.0, "lon": 18.0}])
def test_nothing_is_sent_without_a_real_fix(link, pos):
    link.fix["pos"] = pos
    assert link.share_position(now=1000) is False and link._iface.sent == []


def test_a_usb_or_remote_node_is_left_alone(link, monkeypatch):
    asked = []
    monkeypatch.setattr(mn, "_position_source", lambda: asked.append(1) or link.fix["pos"])
    link._host = "192.168.1.50:4403"
    assert link.share_position(now=1000) is False
    link._host, link._port = None, "/dev/ttyACM0"
    assert link.share_position(now=1000) is False
    assert asked == [] and link._iface.sent == []             # the GPS is not even opened


def test_the_setting_switches_it_off(link, monkeypatch):
    monkeypatch.setattr(mn, "_share_enabled", lambda: False)
    assert link.share_position(now=1000) is False and link._iface.sent == []


def test_a_failing_node_or_gps_does_not_break_the_link(link, monkeypatch):
    link._iface.sendPosition = lambda **kw: (_ for _ in ()).throw(OSError("link down"))
    assert link.share_position(now=1000) is False and link.status()["gps_shared"] is None
    monkeypatch.setattr(mn, "_position_source", lambda: 1 / 0)
    assert link.share_position(now=1000) is False


def test_stopping_the_link_lets_go_of_the_gps(link, monkeypatch):
    released = []
    monkeypatch.setattr(mn, "_position_release", lambda: released.append(1))
    link.share_position(now=1000)
    link._iface.close = lambda: None
    link.stop()
    assert released == [1] and link.status()["gps_shared"] is None


# ── the standby GPS reader ───────────────────────────────────────────────────

class Gps:
    made = []

    def __init__(self, port=None, baudrate=9600, assist=True, set_clock=True, ok=True):
        self.port, self.baudrate, self.assist, self.set_clock = port, baudrate, assist, set_clock
        self.running, self.ok = False, ok
        Gps.made.append(self)

    def start(self):
        self.running = self.ok
        return self.ok

    def stop(self):
        self.running = False

    def get_status(self):
        return {"connected": True, "port": self.port, "has_fix": True}


@pytest.fixture
def engine():
    wardriving = pytest.importorskip("wardriving")
    Gps.made = []
    eng = wardriving.WardrivingEngine.__new__(wardriving.WardrivingEngine)
    eng._gps = eng._standby_gps = None
    eng._running = eng._starting = False
    eng._gpsd_configured_realpath = lambda: None
    return eng


def test_standby_reader_opens_once_and_is_claimed(engine):
    gps = engine.standby_gps("/dev/ttyS0", 115200, make=Gps)
    assert gps.running and (gps.port, gps.baudrate) == ("/dev/ttyS0", 115200)
    assert gps.assist is False and gps.set_clock is False     # it only listens
    assert engine.standby_gps("/dev/ttyS0", 115200, make=Gps) is gps and len(Gps.made) == 1
    assert engine._held_gps_ports() == ["/dev/ttyS0"]         # nobody else probes the port
    engine.stop_standby_gps()
    assert not gps.running and engine._held_gps_ports() == []


def test_a_session_uses_its_own_gps_never_a_second_reader(engine):
    session_gps = Gps("/dev/ttyS0")
    Gps.made = []
    engine._gps, engine._running = session_gps, True
    assert engine.standby_gps("/dev/ttyS0", 115200, make=Gps) is session_gps and Gps.made == []
    engine._gps, engine._running, engine._starting = None, False, True
    assert engine.standby_gps("/dev/ttyS0", 115200, make=Gps) is None and Gps.made == []


def test_starting_a_session_closes_the_standby_reader_first(engine):
    import wardriving
    src = open(wardriving.__file__).read()
    start = src[src.index("    def start(self, interfaces=None"):]
    # Before anything in start() looks for or opens a GPS.
    assert start.index("self.stop_standby_gps()") < start.index("_ensure_gpsd(") < start.index("GPSManager(")
    gps = engine.standby_gps("/dev/ttyS0", 115200, make=Gps)
    engine.stop_standby_gps()
    assert not gps.running and engine._standby_gps is None


def test_a_port_that_does_not_open_is_retried_later_not_every_tick(engine, monkeypatch):
    bad = lambda **kw: Gps(ok=False, **kw)     # noqa: E731
    assert engine.standby_gps("/dev/ttyS0", 115200, make=bad) is None
    assert engine.standby_gps("/dev/ttyS0", 115200, make=bad) is None
    assert len(Gps.made) == 1
    assert engine.standby_gps(None, None, make=Gps) is None   # no Cap GNSS: nothing opened


# ── camera detection ─────────────────────────────────────────────────────────

def test_a_found_camera_stays_found(monkeypatch):
    answers = [{"present": True, "model": "imx219", "modes": "3280x2464"},
               {"present": False, "reason": "timed out"}]
    calls = []
    cam = pc.PiCamera(detector=lambda: calls.append(1) or answers[len(calls) - 1])
    assert cam.info()["present"] is True
    monkeypatch.setattr(pc, "DETECT_TTL", 0)                  # a minute later...
    assert cam.info()["present"] is True and len(calls) == 1  # ...it is not asked again
    assert cam.info(refresh=True)["present"] is False         # Refresh does ask


def test_no_camera_is_asked_again_after_a_minute(monkeypatch):
    answers = [{"present": False, "reason": "no camera reported"},
               {"present": True, "model": "imx219", "modes": ""}]
    calls = []
    cam = pc.PiCamera(detector=lambda: calls.append(1) or answers[len(calls) - 1])
    assert cam.info()["present"] is False and cam.info()["present"] is False
    assert len(calls) == 1
    monkeypatch.setattr(pc, "DETECT_TTL", 0)
    assert cam.info()["present"] is True


def test_detection_does_not_wait_for_a_photo(monkeypatch):
    cam = pc.PiCamera(detector=lambda: {"present": True, "model": "imx219"})
    import threading
    held = threading.Event()
    done = threading.Event()

    def hold():
        with cam._lock:                      # a photo in progress owns the camera
            held.set()
            done.wait(3)

    threading.Thread(target=hold, daemon=True).start()
    assert held.wait(2)
    result = []
    t = threading.Thread(target=lambda: result.append(cam.status()), daemon=True)
    t.start()
    t.join(1.5)
    done.set()
    assert result and result[0]["present"] is True


def test_a_listing_that_times_out_goes_by_the_kernels_sensor(tmp_path):
    import cardputer_caps as caps
    root = str(tmp_path)
    os.makedirs(root + "/sys/bus/i2c/drivers/imx219/10-0010")

    def slow():
        raise TimeoutError("timed out after 40 seconds")

    found = caps.detect_camera(runner=slow, root=root)
    assert found["present"] is True and found["model"] == "imx219"
    # No sensor in the kernel: a timeout is still "no camera".
    assert caps.detect_camera(runner=slow, root=str(tmp_path / "empty"))["present"] is False
    # A listing that finished and found nothing is believed.
    assert caps.detect_camera(runner=lambda: "No cameras available!", root=root)["present"] is False
