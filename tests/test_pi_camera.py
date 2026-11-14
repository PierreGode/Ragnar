"""Camera service with the rpicam tools replaced by fakes: photo capture,
the shared live view and its hand-over with a photo."""
import io
import os
import subprocess
import sys
import threading
import time
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pi_camera as pc  # noqa: E402

JPEG = lambda tag: b"\xff\xd8" + tag + b"\xff\xd9"   # noqa: E731


@pytest.fixture(autouse=True)
def tools(monkeypatch):
    monkeypatch.setattr(pc, "_tool", lambda *names: "/usr/bin/" + names[0])


# ── MJPEG framing ────────────────────────────────────────────────────────────

def test_frames_are_split_on_jpeg_markers():
    frames, rest = pc.split_jpegs(b"junk" + JPEG(b"one") + JPEG(b"two") + b"\xff\xd8half")
    assert frames == [JPEG(b"one"), JPEG(b"two")]
    assert rest == b"\xff\xd8half"
    frames, rest = pc.split_jpegs(rest + b"-done\xff\xd9")
    assert frames == [b"\xff\xd8half-done\xff\xd9"] and rest == b""
    assert pc.split_jpegs(b"no markers here") == ([], b"")


# ── photo ────────────────────────────────────────────────────────────────────

def runner(stdout=JPEG(b"photo"), code=0, stderr=b"", calls=None):
    def run(cmd, capture_output=True, timeout=None):
        if calls is not None:
            calls.append(cmd)
        return types.SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)
    return run


def test_photo_returns_the_jpeg_and_asks_for_the_size():
    calls = []
    cam = pc.PiCamera(run=runner(calls=calls))
    assert cam.photo(800, 600) == JPEG(b"photo")
    cmd = calls[0]
    assert cmd[0].endswith("rpicam-still") and "-n" in cmd
    assert cmd[cmd.index("--width") + 1] == "800" and cmd[cmd.index("--height") + 1] == "600"
    assert cmd[-2:] == ["-o", "-"]
    assert cam.last_error is None


@pytest.mark.parametrize("stdout,code,stderr,message", [
    (b"", 1, b"line one\nERROR: *** no cameras available ***\n", "no cameras available"),
    (b"not a jpeg", 0, b"", "no image"),
])
def test_photo_failure_carries_the_tools_last_line(stdout, code, stderr, message):
    cam = pc.PiCamera(run=runner(stdout, code, stderr))
    with pytest.raises(RuntimeError) as err:
        cam.photo()
    assert message in str(err.value) and message in cam.last_error


def test_photo_timeout_and_missing_tool(monkeypatch):
    def slow(cmd, capture_output=True, timeout=None):
        raise subprocess.TimeoutExpired(cmd, timeout)
    with pytest.raises(RuntimeError, match="timed out"):
        pc.PiCamera(run=slow).photo()
    monkeypatch.setattr(pc, "_tool", lambda *names: None)
    with pytest.raises(RuntimeError, match="rpicam-apps is not installed"):
        pc.PiCamera(run=runner()).photo()


# ── live view ────────────────────────────────────────────────────────────────

class FakeVid:
    """Stands in for rpicam-vid: a pipe the test feeds MJPEG into."""
    started = []

    def __init__(self, cmd, stdout=None, stderr=None):
        self.cmd = cmd
        r, w = os.pipe()
        self.stdout = os.fdopen(r, "rb", buffering=0)
        self._w = w
        self.terminated = False
        FakeVid.started.append(self)

    def feed(self, data):
        os.write(self._w, data)

    def terminate(self):
        if not self.terminated:
            self.terminated = True
            os.close(self._w)

    def wait(self, timeout=None):
        return 0

    kill = terminate


@pytest.fixture
def cam(monkeypatch):
    FakeVid.started = []
    monkeypatch.setattr(pc, "STREAM_IDLE_SECONDS", 0.1)
    camera = pc.PiCamera(popen=FakeVid, run=runner())
    yield camera
    camera.stop()


def first(gen, n=1, timeout=3.0):
    """Pull n frames from a generator on a thread, with a deadline."""
    out = []
    t = threading.Thread(target=lambda: [out.append(next(gen)) for _ in range(n)], daemon=True)
    t.start()
    return out, t


def wait_for(predicate, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_first_viewer_starts_one_rpicam_vid_and_gets_frames(cam):
    gen = cam.frames(timeout=0.2)
    out, _ = first(gen)
    assert wait_for(lambda: FakeVid.started)
    vid = FakeVid.started[0]
    assert vid.cmd[0].endswith("rpicam-vid") and "mjpeg" in vid.cmd
    vid.feed(JPEG(b"a"))
    assert wait_for(lambda: out == [JPEG(b"a")])
    assert cam.status()["streaming"] and cam.status()["viewers"] == 1


def test_viewers_share_the_stream_and_it_stops_after_the_last_leaves(cam):
    g1, g2 = cam.frames(timeout=0.2), cam.frames(timeout=0.2)
    o1, _ = first(g1)
    o2, _ = first(g2)
    assert wait_for(lambda: cam.status()["viewers"] == 2)
    assert len(FakeVid.started) == 1
    vid = FakeVid.started[0]
    vid.feed(JPEG(b"x"))
    assert wait_for(lambda: o1 == [JPEG(b"x")] and o2 == [JPEG(b"x")])
    g1.close()
    g2.close()
    assert cam.status()["viewers"] == 0
    time.sleep(0.2)
    vid.feed(JPEG(b"y"))                      # the reader notices on its next read
    assert wait_for(lambda: vid.terminated)
    assert not cam.status()["streaming"]


def test_viewer_ends_when_the_camera_dies(cam):
    gen = cam.frames(timeout=0.1)
    done = []
    threading.Thread(target=lambda: done.append(list(gen)), daemon=True).start()
    assert wait_for(lambda: FakeVid.started)
    FakeVid.started[0].terminate()            # rpicam-vid exits
    assert wait_for(lambda: done == [[]])
    assert not cam.status()["streaming"]


def test_photo_pauses_the_live_view_and_resumes_it(cam):
    gen = cam.frames(timeout=0.2)
    out, _ = first(gen)
    assert wait_for(lambda: FakeVid.started)
    assert cam.photo() == JPEG(b"photo")
    assert FakeVid.started[0].terminated      # camera handed to rpicam-still
    assert len(FakeVid.started) == 2          # and the view restarted for the viewer
    FakeVid.started[1].feed(JPEG(b"after"))
    assert wait_for(lambda: out == [JPEG(b"after")])


def test_mjpeg_parts_are_well_formed(cam):
    gen = cam.mjpeg()
    out, _ = first(gen)
    assert wait_for(lambda: FakeVid.started)
    FakeVid.started[0].feed(JPEG(b"frame"))
    assert wait_for(lambda: out)
    part = out[0]
    assert part.startswith(b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: 9\r\n\r\n")
    assert part.endswith(JPEG(b"frame") + b"\r\n")


def test_no_tool_means_no_stream(cam, monkeypatch):
    monkeypatch.setattr(pc, "_tool", lambda *names: None)
    assert list(cam.frames(timeout=0.1)) == []
    assert "not installed" in cam.last_error and cam.status()["viewers"] == 0


def test_detection_is_cached():
    calls = []
    cam = pc.PiCamera(detector=lambda: calls.append(1) or {"present": True, "model": "imx219"})
    assert cam.info()["model"] == "imx219"
    cam.info()
    assert len(calls) == 1
    cam.info(refresh=True)
    assert len(calls) == 2
