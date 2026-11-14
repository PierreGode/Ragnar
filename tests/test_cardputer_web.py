"""Web API for the CardputerZero hardware panel and the camera."""
import os
import sys
import time
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

JPEG = b"\xff\xd8photo\xff\xd9"


@pytest.fixture
def web(monkeypatch, tmp_path):
    try:
        import webapp_modern as webapp
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip("webapp_modern unimportable here: %s" % exc)
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: False)
    monkeypatch.setattr(webapp.shared_data, "datadir", str(tmp_path), raising=False)
    monkeypatch.setitem(webapp._cz_hw, "data", None)
    monkeypatch.setitem(webapp._cz_hw, "at", 0.0)
    monkeypatch.setitem(webapp._cz_hw, "busy", False)
    return webapp


def wait_for(predicate, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_other_boards_report_unsupported_and_scan_nothing(web, monkeypatch):
    import cardputer_caps
    monkeypatch.setattr(cardputer_caps, "is_cardputer_zero", lambda cfg=None: False)
    monkeypatch.setattr(cardputer_caps, "detect", lambda *a, **k: pytest.fail("must not scan"))
    resp = web.app.test_client().get("/api/cardputer/hardware")
    assert resp.status_code == 200 and resp.get_json() == {"supported": False}


def test_hardware_scan_runs_in_the_background_and_is_served(web, monkeypatch):
    import cardputer_caps
    import pi_camera
    calls = []

    def detect(config=None, power=True, probe_serial=True, camera=True, reidentify=False,
               free_uart=False):
        calls.append({"probe_serial": probe_serial, "camera": camera, "reidentify": reidentify})
        return {"board": True, "ext5v": True, "cap": "lora_gnss",
                "cap_name": "Cap LoRa-1262 + GNSS", "radios": ["SX1262"], "pins": {},
                "gnss": {"port": "/dev/ttyS0", "baud": 115200, "sentences": 3,
                         "console_conflict": False}, "nfc_spi": None, "camera": None}

    monkeypatch.setattr(cardputer_caps, "is_cardputer_zero", lambda cfg=None: True)
    monkeypatch.setattr(cardputer_caps, "detect", detect)
    monkeypatch.setattr(cardputer_caps, "header_state",
                        lambda: [{"label": "G26", "gpio": 26, "role": "x", "function": "op", "level": 1}])
    monkeypatch.setattr(web, "_cz_gnss_port_in_use", lambda: False)
    monkeypatch.setattr(pi_camera, "get_camera", lambda: types.SimpleNamespace(
        info=lambda: {"present": True, "model": "imx219", "modes": "3280x2464"}))
    client = web.app.test_client()
    first = client.get("/api/cardputer/hardware").get_json()
    assert first["supported"] is True
    assert wait_for(lambda: web._cz_hw["data"] is not None and not web._cz_hw["busy"])
    data = client.get("/api/cardputer/hardware").get_json()
    assert data["pending"] is False and data["cap"] == "lora_gnss"
    assert data["gnss"]["sentences"] == 3 and data["gnss"]["in_use"] is False
    assert data["camera"]["model"] == "imx219" and data["header"][0]["label"] == "G26"
    # Cached: one scan, and a timed scan never re-identifies the Cap.
    assert calls == [{"probe_serial": True, "camera": False, "reidentify": False}]
    client.get("/api/cardputer/hardware?refresh=1")
    assert wait_for(lambda: len(calls) == 2 and not web._cz_hw["busy"])
    assert calls[1]["reidentify"] is True                         # the Refresh button may


def test_gnss_port_is_not_probed_while_gps_has_it(web, monkeypatch):
    import cardputer_caps
    seen = []
    monkeypatch.setattr(cardputer_caps, "is_cardputer_zero", lambda cfg=None: True)
    monkeypatch.setattr(cardputer_caps, "detect", lambda config=None, power=True, probe_serial=True, camera=True, reidentify=False, free_uart=False:
                        seen.append(probe_serial) or {"board": False, "gnss": {"sentences": 0}})
    monkeypatch.setattr(web, "_cz_gnss_port_in_use", lambda: True)
    info = web._cz_detect_now()
    assert seen == [False] and info["gnss"]["in_use"] is True


def camera(monkeypatch, **over):
    import pi_camera
    cam = types.SimpleNamespace(
        status=lambda: {"present": True, "model": "imx219", "streaming": False,
                        "viewers": 0, "error": None},
        photo=lambda: JPEG,
        mjpeg=lambda: iter([b"--frame\r\n\r\n" + JPEG + b"\r\n"]))
    for k, v in over.items():
        setattr(cam, k, v)
    monkeypatch.setattr(pi_camera, "get_camera", lambda: cam)
    return cam


def test_photo_is_saved_listed_served_and_deleted(web, monkeypatch, tmp_path):
    camera(monkeypatch)
    client = web.app.test_client()
    taken = client.post("/api/camera/photo").get_json()
    assert taken["success"] and taken["name"].startswith("ragnar_") and taken["size"] == len(JPEG)
    name = taken["name"]
    assert (tmp_path / "camera" / name).read_bytes() == JPEG
    assert client.get("/api/camera/status").get_json()["photos"][0]["name"] == name
    served = client.get(f"/api/camera/photo/{name}")
    assert served.status_code == 200 and served.data == JPEG and served.mimetype == "image/jpeg"
    assert client.delete(f"/api/camera/photo/{name}").get_json() == {"success": True, "photos": []}
    assert client.get(f"/api/camera/photo/{name}").status_code == 404


def test_two_photos_in_one_second_do_not_overwrite(web, monkeypatch, tmp_path):
    camera(monkeypatch)
    monkeypatch.setattr(web.time, "strftime", lambda fmt: "ragnar_20261114_101500")
    client = web.app.test_client()
    names = [client.post("/api/camera/photo").get_json()["name"] for _ in range(3)]
    assert names == ["ragnar_20261114_101500.jpg", "ragnar_20261114_101500_2.jpg",
                     "ragnar_20261114_101500_3.jpg"]


@pytest.mark.parametrize("name", ["..%2F..%2Fetc%2Fpasswd", "shared_config.json",
                                  "ragnar_20261114_101500.jpg.txt", "ragnar_1_2.jpg"])
def test_only_ragnars_own_photo_names_are_served(web, monkeypatch, tmp_path, name):
    camera(monkeypatch)
    (tmp_path / "shared_config.json").write_text("{}")
    client = web.app.test_client()
    # An encoded slash never reaches the photo route at all (405 from another).
    assert client.get(f"/api/camera/photo/{name}").status_code in (400, 404, 405)
    assert client.delete(f"/api/camera/photo/{name}").status_code in (400, 404, 405)
    assert (tmp_path / "shared_config.json").exists()


def test_camera_failure_is_reported_not_raised(web, monkeypatch):
    def broken():
        raise RuntimeError("no cameras available")
    camera(monkeypatch, photo=broken)
    resp = web.app.test_client().post("/api/camera/photo")
    assert resp.status_code == 503
    assert resp.get_json() == {"success": False, "error": "no cameras available"}


def test_stream_is_multipart_mjpeg(web, monkeypatch):
    camera(monkeypatch)
    resp = web.app.test_client().get("/api/camera/stream")
    assert resp.mimetype == "multipart/x-mixed-replace"
    assert "boundary=frame" in resp.headers["Content-Type"]
    assert JPEG in resp.data and resp.headers["Cache-Control"] == "no-store"


def test_no_camera_hides_the_panel(web, monkeypatch):
    camera(monkeypatch, status=lambda: {"present": False, "reason": "no camera reported",
                                        "streaming": False, "viewers": 0, "error": None})
    data = web.app.test_client().get("/api/camera/status").get_json()
    assert data["supported"] is False and data["photos"] == []


def test_other_files_in_the_camera_folder_are_not_served_or_deleted(web, monkeypatch, tmp_path):
    camera(monkeypatch)
    folder = tmp_path / "camera"
    folder.mkdir()
    (folder / "notes.txt").write_text("private")
    (folder / "holiday.jpg").write_bytes(JPEG)
    client = web.app.test_client()
    for name in ("notes.txt", "holiday.jpg"):
        assert client.get(f"/api/camera/photo/{name}").status_code == 400
        assert client.delete(f"/api/camera/photo/{name}").status_code == 400
        assert (folder / name).exists()
    assert client.get("/api/camera/status").get_json()["photos"] == []


# ── one-tap fixes ────────────────────────────────────────────────────────────

def test_action_runs_the_matching_script_once(web, monkeypatch):
    import cardputer_caps
    import threading
    ran, gate = [], threading.Event()

    def run(cmd, **kw):
        ran.append(cmd)
        gate.wait(5)
        return types.SimpleNamespace(returncode=0, stdout="line\n" * 20 + "done\n", stderr="")

    monkeypatch.setattr(cardputer_caps, "is_cardputer_zero", lambda cfg=None: True)
    monkeypatch.setattr(web.subprocess, "run", run)
    monkeypatch.setattr(web, "_cz_refresh_async", lambda *a, **k: None)
    client = web.app.test_client()
    assert client.post("/api/cardputer/action", json={"action": "rm -rf"}).status_code == 400
    assert ran == []
    first = client.post("/api/cardputer/action", json={"action": "gnss"})
    assert first.status_code == 200 and first.get_json()["task"]["running"] is True
    # A second tap while the first runs is refused, not queued.
    assert client.post("/api/cardputer/action", json={"action": "lora"}).status_code == 409
    gate.set()
    for _ in range(100):
        if not web._cz_task["running"]:
            break
        time.sleep(0.05)
    assert len(ran) == 1 and ran[0][-2:] == [
        os.path.join(web.shared_data.currentdir, "scripts/cardputer_hardware.sh"), "gnss"]
    assert web._cz_task["ok"] is True and web._cz_task["log"].endswith("done")
    assert len(web._cz_task["log"].splitlines()) == 8


def test_action_is_refused_on_other_boards(web, monkeypatch):
    import cardputer_caps
    monkeypatch.setattr(cardputer_caps, "is_cardputer_zero", lambda cfg=None: False)
    monkeypatch.setattr(web.subprocess, "run", lambda *a, **k: pytest.fail("must not run"))
    assert web.app.test_client().post("/api/cardputer/action", json={"action": "gnss"}).status_code == 400
