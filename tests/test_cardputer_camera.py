"""Camera: turning the picture, video recording, the web endpoints for both,
and the CardputerZero's on-screen camera view with its keys."""
import io
import os
import shutil
import struct
import subprocess
import sys
import threading
import time
import types

import pytest
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pi_camera as pc  # noqa: E402
from test_pi_camera import FakeVid, runner, wait_for  # noqa: E402


def jpeg(colour=(200, 40, 40), size=(640, 480)):
    out = io.BytesIO()
    Image.new("RGB", size, colour).save(out, "JPEG")
    return out.getvalue()


@pytest.fixture(autouse=True)
def tools(monkeypatch):
    # No ffmpeg unless a test asks: recordings stay AVI and nothing is spawned.
    monkeypatch.setattr(pc, "_tool", lambda *names: None if names[0] == "ffmpeg"
                        else "/usr/bin/" + names[0])


@pytest.fixture
def cam(monkeypatch):
    FakeVid.started = []
    monkeypatch.setattr(pc, "STREAM_IDLE_SECONDS", 0.1)
    camera = pc.PiCamera(popen=FakeVid, run=runner())
    yield camera
    camera.stop()


# ── turning the picture ──────────────────────────────────────────────────────

def test_rotation_follows_the_setting_and_the_board(monkeypatch):
    import cardputer_caps
    monkeypatch.setattr(cardputer_caps, "is_cardputer_zero", lambda cfg=None: True)
    assert pc.rotation_for({}) == 180                      # auto on the CardputerZero
    assert pc.rotation_for({"camera_rotation": "auto"}) == 180
    assert pc.rotation_for({"camera_rotation": 0}) == 0    # the user's choice wins
    monkeypatch.setattr(cardputer_caps, "is_cardputer_zero", lambda cfg=None: False)
    assert pc.rotation_for({}) == 0
    assert pc.rotation_for({"camera_rotation": 180}) == 180
    assert pc.rotation_for({"camera_rotation": "sideways"}) == 0


def test_photo_and_live_view_are_both_turned(cam):
    calls = []
    cam._run = runner(calls=calls)
    cam.photo()
    assert "--rotation" not in calls[0]
    cam.set_rotation(180)
    cam.photo()
    assert calls[1][calls[1].index("--rotation") + 1] == "180"
    assert cam.acquire()
    assert "--rotation" in FakeVid.started[0].cmd
    # Turning it while the view runs restarts the view the new way up.
    cam.set_rotation(0)
    assert FakeVid.started[0].terminated and len(FakeVid.started) == 2
    assert "--rotation" not in FakeVid.started[1].cmd
    assert cam.status()["rotation"] == 0
    cam.release()


# ── video ────────────────────────────────────────────────────────────────────

def read_avi(path):
    """Frames of a Motion-JPEG AVI, read through its index."""
    data = open(path, "rb").read()
    assert data[:4] == b"RIFF" and data[8:12] == b"AVI "
    assert struct.unpack("<I", data[4:8])[0] == len(data) - 8
    movi = data.index(b"movi")
    idx = data.rindex(b"idx1")
    count = struct.unpack("<I", data[idx + 4:idx + 8])[0] // 16
    frames = []
    for i in range(count):
        tag, _flags, off, size = struct.unpack("<4sIII", data[idx + 8 + 16 * i:idx + 24 + 16 * i])
        assert tag == b"00dc" and data[movi + off:movi + off + 4] == b"00dc"
        frames.append(data[movi + off + 8:movi + off + 8 + size])
    total = struct.unpack("<I", data[48:52])[0]
    assert total == count
    return frames


def test_avi_holds_every_frame_and_real_tools_can_read_it(tmp_path):
    path = str(tmp_path / "clip.avi")
    writer = pc.AviWriter(path, 640, 480)
    shots = [jpeg((i * 20, 80, 200 - i * 10)) for i in range(12)]
    for shot in shots:
        writer.write(shot)
    writer.close(8.0)
    assert read_avi(path) == shots and writer.bytes == os.path.getsize(path)
    if shutil.which("ffprobe"):
        out = subprocess.run(["ffprobe", "-v", "error", "-show_entries",
                              "stream=codec_name,width,height,nb_frames,avg_frame_rate",
                              "-of", "default=nw=1", path], capture_output=True, text=True).stdout
        assert "codec_name=mjpeg" in out and "nb_frames=12" in out and "avg_frame_rate=8/1" in out
        assert "width=640" in out and "height=480" in out


def test_recording_writes_the_live_view_and_the_view_keeps_running(cam, tmp_path):
    folder = str(tmp_path)
    viewer = cam.frames(timeout=0.2)
    seen = []
    threading.Thread(target=lambda: [seen.append(f) for f in viewer], daemon=True).start()
    assert wait_for(lambda: FakeVid.started)
    rec = cam.start_recording(folder)
    assert pc.VIDEO_RE.match(rec["name"]) and rec["name"].endswith(".avi")
    assert cam.status()["recording"]["name"] == rec["name"]
    assert len(FakeVid.started) == 1                      # the same rpicam-vid
    shots = [jpeg((i * 60, 10, 10)) for i in range(4)]
    for shot in shots:
        FakeVid.started[0].feed(shot)
        assert wait_for(lambda: cam.recording()["frames"] == shots.index(shot) + 1)
        time.sleep(0.02)
    assert wait_for(lambda: seen and seen[-1] == shots[-1])   # viewers still get frames
    # A photo while recording must not interrupt the video.
    assert cam.photo() == shots[-1] and not FakeVid.started[0].terminated
    done = cam.stop_recording()
    assert done["name"] == rec["name"] and done["frames"] == 4 and done["note"] is None
    assert read_avi(os.path.join(folder, rec["name"])) == shots
    assert cam.recording() is None and cam.stop_recording() is None


def test_recording_alone_keeps_the_camera_on_and_lets_go_after(cam, tmp_path):
    cam.start_recording(str(tmp_path))
    assert cam.status()["viewers"] == 1 and cam.streaming
    time.sleep(0.25)                                      # longer than the idle limit
    FakeVid.started[0].feed(jpeg())
    assert wait_for(lambda: cam.recording()["frames"] == 1)
    assert not FakeVid.started[0].terminated
    cam.stop_recording()
    assert cam.status()["viewers"] == 0


def test_recording_stops_itself_at_the_limit(cam, tmp_path, monkeypatch):
    monkeypatch.setattr(pc, "MAX_RECORD_SECONDS", 0)
    rec = cam.start_recording(str(tmp_path))
    FakeVid.started[0].feed(jpeg())
    assert wait_for(lambda: cam.recording() is None)
    assert "limit" in cam.last_video["note"] and cam.last_video["frames"] == 1
    assert len(read_avi(str(tmp_path / rec["name"]))) == 1


def test_recording_stops_when_the_disk_fills(cam, tmp_path, monkeypatch):
    cam.start_recording(str(tmp_path))
    monkeypatch.setattr(pc, "FREE_CHECK_FRAMES", 1)
    monkeypatch.setattr(pc.shutil, "disk_usage", lambda p: types.SimpleNamespace(free=1024))
    FakeVid.started[0].feed(jpeg())
    assert wait_for(lambda: cam.recording() is None)
    assert "disk" in cam.last_video["note"]
    with pytest.raises(RuntimeError, match="free space"):
        cam.start_recording(str(tmp_path))


def test_recording_is_finished_when_the_camera_dies(cam, tmp_path):
    rec = cam.start_recording(str(tmp_path))
    FakeVid.started[0].feed(jpeg())
    assert wait_for(lambda: cam.recording() and cam.recording()["frames"] == 1)
    FakeVid.started[0].terminate()
    assert wait_for(lambda: cam.recording() is None)
    assert len(read_avi(str(tmp_path / rec["name"]))) == 1


def test_a_recording_with_no_frames_leaves_no_file(cam, tmp_path):
    cam.start_recording(str(tmp_path))
    done = cam.stop_recording()
    assert done["name"] is None and os.listdir(tmp_path) == []


def test_recording_fails_cleanly_without_the_camera_tools(cam, tmp_path, monkeypatch):
    monkeypatch.setattr(pc, "_tool", lambda *names: None)
    with pytest.raises(RuntimeError, match="not installed"):
        cam.start_recording(str(tmp_path))
    assert cam.recording() is None and cam.status()["viewers"] == 0


def test_finished_video_becomes_an_mp4_when_ffmpeg_is_there(tmp_path, monkeypatch):
    monkeypatch.setattr(pc, "_tool", lambda *names: "/usr/bin/" + names[0])
    FakeVid.started = []
    cmds = []

    def run(cmd, capture_output=True, timeout=None):
        cmds.append(cmd)
        with open(cmd[-1], "wb") as f:
            f.write(b"mp4 data")
        return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    camera = pc.PiCamera(popen=FakeVid, run=run)
    rec = camera.start_recording(str(tmp_path))
    FakeVid.started[0].feed(jpeg())
    assert wait_for(lambda: camera.recording()["frames"] == 1)
    camera.stop_recording()
    mp4 = rec["name"][:-4] + ".mp4"
    assert wait_for(lambda: os.listdir(tmp_path) == [mp4])   # the AVI is replaced
    assert wait_for(lambda: camera.status()["converting"] == [])
    assert "libx264" in cmds[0] and cmds[0][cmds[0].index("-i") + 1].endswith(rec["name"])
    camera.stop()


def test_a_failed_conversion_keeps_the_avi(tmp_path, monkeypatch):
    monkeypatch.setattr(pc, "_tool", lambda *names: "/usr/bin/" + names[0])
    FakeVid.started = []
    camera = pc.PiCamera(popen=FakeVid, run=runner(code=1))
    rec = camera.start_recording(str(tmp_path))
    FakeVid.started[0].feed(jpeg())
    assert wait_for(lambda: camera.recording()["frames"] == 1)
    camera.stop_recording()
    assert wait_for(lambda: camera.status()["converting"] == [])
    assert os.listdir(tmp_path) == [rec["name"]]
    camera.stop()


def test_new_names_never_collide_across_photos_and_videos(tmp_path, monkeypatch):
    monkeypatch.setattr(pc.time, "strftime", lambda fmt: "ragnar_20261114_101500")
    (tmp_path / "ragnar_20261114_101500.mp4").write_bytes(b"x")
    assert pc.new_name(str(tmp_path), ".avi") == "ragnar_20261114_101500_2.avi"
    assert pc.save_photo(str(tmp_path), b"jpg") == "ragnar_20261114_101500_2.jpg"
    assert pc.new_name(str(tmp_path), ".avi") == "ragnar_20261114_101500_3.avi"


# ── web ──────────────────────────────────────────────────────────────────────

@pytest.fixture
def web(monkeypatch, tmp_path):
    try:
        import webapp_modern as webapp
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip("webapp_modern unimportable here: %s" % exc)
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: False)
    monkeypatch.setattr(webapp.shared_data, "datadir", str(tmp_path), raising=False)
    monkeypatch.setattr(webapp.shared_data, "save_config", lambda: None, raising=False)
    FakeVid.started = []
    camera = pc.PiCamera(popen=FakeVid, run=runner(),
                         detector=lambda: {"present": True, "model": "imx219"})
    monkeypatch.setattr(pc, "get_camera", lambda *a: camera)
    webapp.camera = camera
    yield webapp
    camera.stop()


def test_web_records_lists_serves_and_deletes_a_video(web, tmp_path):
    client = web.app.test_client()
    assert client.post("/api/camera/record", json={"action": "dance"}).status_code == 400
    started = client.post("/api/camera/record", json={"action": "start"}).get_json()
    name = started["recording"]["name"]
    assert started["success"] and client.get("/api/camera/status").get_json()["recording"]["name"] == name
    FakeVid.started[0].feed(jpeg())
    assert wait_for(lambda: web.camera.recording()["frames"] == 1)
    # The file being written cannot be deleted from under the recording.
    assert client.delete(f"/api/camera/video/{name}").status_code == 409
    stopped = client.post("/api/camera/record", json={"action": "stop"}).get_json()
    assert stopped["video"]["name"] == name and stopped["videos"][0]["name"] == name
    assert stopped["recording"] is None
    served = client.get(f"/api/camera/video/{name}")
    assert served.status_code == 200 and served.data[:4] == b"RIFF"
    assert "attachment" in served.headers["Content-Disposition"]
    part = client.get(f"/api/camera/video/{name}", headers={"Range": "bytes=0-3"})
    assert part.status_code == 206 and part.data == b"RIFF"       # players seek
    assert client.delete(f"/api/camera/video/{name}").get_json() == {"success": True, "videos": []}
    assert client.get(f"/api/camera/video/{name}").status_code == 404


def test_web_mp4_plays_inline(web, tmp_path):
    folder = tmp_path / "camera"
    folder.mkdir()
    (folder / "ragnar_20261114_101500.mp4").write_bytes(b"mp4")
    resp = web.app.test_client().get("/api/camera/video/ragnar_20261114_101500.mp4")
    assert resp.mimetype == "video/mp4" and "attachment" not in resp.headers.get("Content-Disposition", "")


@pytest.mark.parametrize("name", ["notes.txt", "holiday.mp4", "ragnar_20261114_101500.jpg",
                                  "ragnar_20261114_101500.mp4.sh", "..%2Fshared_config.json"])
def test_web_only_serves_ragnars_own_videos(web, tmp_path, name):
    folder = tmp_path / "camera"
    folder.mkdir()
    for existing in ("notes.txt", "holiday.mp4", "ragnar_20261114_101500.jpg"):
        (folder / existing).write_bytes(b"x")
    client = web.app.test_client()
    assert client.get(f"/api/camera/video/{name}").status_code in (400, 404, 405)
    assert client.delete(f"/api/camera/video/{name}").status_code in (400, 404, 405)
    assert len(os.listdir(folder)) == 3


def test_web_flip_is_saved_and_applied(web, monkeypatch):
    saved = []
    monkeypatch.setattr(web.shared_data, "save_config", lambda: saved.append(1), raising=False)
    monkeypatch.setitem(web.shared_data.config, "camera_rotation", "auto")
    client = web.app.test_client()
    assert client.post("/api/camera/settings", json={"rotation": 90}).status_code == 400
    assert client.post("/api/camera/settings", json={"rotation": 180}).get_json() == {
        "success": True, "rotation": 180}
    assert web.shared_data.config["camera_rotation"] == 180 and saved == [1]
    assert web.camera.rotation == 180


# ── the keys ─────────────────────────────────────────────────────────────────

@pytest.fixture
def keys(monkeypatch, tmp_path):
    import cardputer_input as ci
    monkeypatch.setattr(ci, "_KEYMAP_FILE", "/nonexistent/cardputer_keymap.json")
    FakeVid.started = []
    camera = pc.PiCamera(popen=FakeVid, run=runner(stdout=jpeg()))
    monkeypatch.setattr(pc, "get_camera", lambda *a: camera)
    shared = types.SimpleNamespace(screen_reversed=0, config={}, datadir=str(tmp_path),
                                   save_config=lambda: None)
    lst = ci.CardputerInputListener(shared)
    lst._source = "evdev"
    lst.cam = camera
    lst.folder = tmp_path / "camera"
    yield lst
    camera.stop()


def tap(lst, code):
    lst._handle_event(code, True)
    lst._handle_event(code, False)


P, OK, ESC, Z, C, TAB, BKSP, SPACE = 25, 28, 1, 44, 46, 15, 14, 57


def test_p_opens_and_closes_the_camera_screen(keys):
    tap(keys, P)
    assert keys.camera_mode is True
    tap(keys, P)
    assert keys.camera_mode is False
    tap(keys, P)
    tap(keys, ESC)
    assert keys.camera_mode is False


def test_ok_takes_a_photo_into_the_camera_folder(keys):
    tap(keys, P)
    tap(keys, OK)
    assert wait_for(lambda: not keys.camera_busy and keys.folder.exists())
    names = os.listdir(keys.folder)
    assert len(names) == 1 and pc.PHOTO_RE.match(names[0])
    assert (keys.folder / names[0]).read_bytes() == jpeg()
    assert keys.camera_note[0] == "Photo saved"


def test_a_failed_photo_says_so_and_leaves_the_keys_working(keys):
    keys.cam._run = runner(stdout=b"", code=1, stderr=b"ERROR: no cameras available\n")
    tap(keys, P)
    tap(keys, OK)
    assert wait_for(lambda: not keys.camera_busy and keys.camera_note is not None
                    and "no cameras" in keys.camera_note[0])
    assert not keys.folder.exists() or os.listdir(keys.folder) == []


def test_z_or_c_switches_to_video_and_ok_starts_and_stops_it(keys):
    tap(keys, P)
    tap(keys, C)
    assert keys.camera_video is True
    tap(keys, OK)
    assert wait_for(lambda: keys.cam.recording() is not None and not keys.camera_busy)
    tap(keys, Z)                                # no mode change while recording
    assert keys.camera_video is True
    FakeVid.started[0].feed(jpeg())
    assert wait_for(lambda: keys.cam.recording()["frames"] == 1)
    tap(keys, OK)
    assert wait_for(lambda: keys.cam.recording() is None and not keys.camera_busy)
    names = os.listdir(keys.folder)
    assert len(names) == 1 and pc.VIDEO_RE.match(names[0])
    assert keys.camera_note[0] == "Video saved"
    tap(keys, Z)
    assert keys.camera_video is False


def test_leaving_the_camera_screen_ends_the_video(keys):
    tap(keys, P)
    tap(keys, C)
    tap(keys, OK)
    assert wait_for(lambda: keys.cam.recording() is not None)
    FakeVid.started[0].feed(jpeg())
    assert wait_for(lambda: keys.cam.recording()["frames"] == 1)
    tap(keys, ESC)
    assert keys.camera_mode is False
    assert wait_for(lambda: keys.cam.recording() is None)
    assert len(os.listdir(keys.folder)) == 1


def test_other_keys_do_not_leak_through_the_camera_screen(keys):
    from epd_button import PAGE_MAIN
    tap(keys, P)
    for code in (TAB, SPACE, 30):               # next page, diagnostics, autoscroll
        tap(keys, code)
    assert keys.current_page == PAGE_MAIN and keys.camera_mode is True
    assert not keys.shared_data.config.get("network_diagnostic_mode")
    assert keys.autoscroll is False
    tap(keys, BKSP)                             # the screen flip still works
    assert keys.shared_data.screen_reversed == 180


# ── the screen ───────────────────────────────────────────────────────────────

class Panel:
    width, height = 320, 170

    def __init__(self):
        self.frames = []

    def getbuffer(self, image):
        return image.copy()

    def displayPartial(self, image):
        self.frames.append(image)


def screen(monkeypatch, tmp_path, camera, bl):
    from test_cardputer_zero import cz_display
    lc, sd, d = cz_display()
    sd.screen_reversed = sd.web_screen_reversed = 0
    sd.display_should_exit = False
    sd.webdir = str(tmp_path)
    panel = Panel()
    d.epd_helper = types.SimpleNamespace(epd=panel)
    monkeypatch.setattr(pc, "get_camera", lambda *a: camera)
    thread = threading.Thread(target=d._camera_screen, args=(bl, 320, 170), daemon=True)
    thread.start()
    return d, panel, thread


def red(pixel):
    return pixel[0] > 200 and pixel[1] < 120 and pixel[2] < 120


def test_camera_screen_shows_the_live_picture_and_the_state(monkeypatch, tmp_path, cam):
    bl = types.SimpleNamespace(camera_mode=True, camera_video=False, camera_busy=False,
                               camera_note=None, last_key=None, key_label=lambda c: "")
    d, panel, thread = screen(monkeypatch, tmp_path, cam, bl)
    assert wait_for(lambda: FakeVid.started)
    FakeVid.started[0].feed(jpeg((30, 200, 60)))
    assert wait_for(lambda: panel.frames and panel.frames[-1].getpixel((100, 85))[1] > 150)
    frame = panel.frames[-1]
    assert frame.size == (320, 170)
    r, g, b = frame.getpixel((100, 85))
    assert g > 150 and r < 90 and b < 110                 # the camera's picture
    assert frame.getpixel((300, 100)) == (0, 0, 0)        # the text column beside it
    assert not red(frame.getpixel((0, 85)))               # no recording frame
    assert os.path.exists(tmp_path / "screen.png")        # mirrored to the web page
    # Recording: a red frame around the picture.
    cam.start_recording(str(tmp_path / "camera"))
    FakeVid.started[0].feed(jpeg((30, 200, 60)))
    assert wait_for(lambda: red(panel.frames[-1].getpixel((0, 85))))
    cam.stop_recording()
    bl.camera_mode = False
    thread.join(3)
    assert not thread.is_alive() and cam.status()["viewers"] == 0


def test_camera_screen_says_when_there_is_no_camera(monkeypatch, tmp_path):
    monkeypatch.setattr(pc, "_tool", lambda *names: None)
    camera = pc.PiCamera(popen=FakeVid, run=runner())
    bl = types.SimpleNamespace(camera_mode=True, camera_video=False, camera_busy=False,
                               camera_note=None, last_key=None, key_label=lambda c: "")
    d, panel, thread = screen(monkeypatch, tmp_path, camera, bl)
    assert wait_for(lambda: panel.frames)
    side = panel.frames[-1].crop((228, 30, 320, 120))
    assert len(side.getcolors()) > 1                      # the reason is written out
    bl.camera_mode = False
    thread.join(3)
    assert not thread.is_alive()


# ── the Camera folder in the Files tab ───────────────────────────────────────

def test_files_tab_has_a_camera_folder_with_the_photos_and_videos(web, tmp_path):
    client = web.app.test_client()
    roots = client.get("/api/files/list?path=/").get_json()
    assert {"name": "camera", "is_directory": True, "path": "/camera"} in roots
    assert client.post("/api/camera/photo").get_json()["success"]
    photo = os.listdir(tmp_path / "camera")[0]
    (tmp_path / "camera" / "ragnar_20261114_101500.mp4").write_bytes(b"mp4")
    listed = {f["name"]: f for f in client.get("/api/files/list?path=/camera").get_json()}
    assert set(listed) == {photo, "ragnar_20261114_101500.mp4"}
    assert listed[photo]["path"] == "/camera/" + photo and listed[photo]["size"] > 0
    got = client.get(f"/api/files/download?path=/camera/{photo}")
    assert got.status_code == 200 and got.data == (tmp_path / "camera" / photo).read_bytes()
    # Managed like any other folder: rename, then delete.
    moved = client.post("/api/files/rename", json={"path": "/camera/" + photo, "name": "desk.jpg"})
    assert moved.status_code == 200 and (tmp_path / "camera" / "desk.jpg").exists()
    assert client.post("/api/files/delete", json={"path": "/camera/desk.jpg"}).status_code == 200
    assert not (tmp_path / "camera" / "desk.jpg").exists()


def test_files_tab_cannot_leave_the_camera_folder(web, tmp_path):
    (tmp_path / "secret.txt").write_text("x")
    client = web.app.test_client()
    for path in ("/camera/../secret.txt", "/camera/%2e%2e/secret.txt", "/camerax"):
        assert client.get(f"/api/files/download?path={path}").status_code in (400, 404)
        assert client.get(f"/api/files/list?path={path}").status_code in (400, 404)
    assert (tmp_path / "secret.txt").exists()


def test_files_tab_will_not_delete_a_video_that_is_recording(web, tmp_path):
    client = web.app.test_client()
    name = client.post("/api/camera/record", json={"action": "start"}).get_json()["recording"]["name"]
    FakeVid.started[0].feed(jpeg())
    assert wait_for(lambda: web.camera.recording()["frames"] == 1)
    for path in ("/camera/" + name, "/camera"):
        assert client.post("/api/files/delete", json={"path": path}).status_code == 409
    client.post("/api/camera/record", json={"action": "stop"})
    assert client.post("/api/files/delete", json={"path": "/camera/" + name}).status_code == 200
