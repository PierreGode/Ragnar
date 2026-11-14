"""The CardputerZero's boot / start-up / install picture (ragnar_splash.py)
and the three places that show it."""
import os
import subprocess
import sys
import types

import pytest
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ragnar_splash as rs  # noqa: E402


def lit(image, box):
    return sum(1 for p in image.crop(box).getdata() if max(p) > 60)


# ── the picture ──────────────────────────────────────────────────────────────

def test_picture_has_the_name_the_message_and_the_character():
    img = rs.render("Starting up", "Ragnar is loading.", config={"screen_reversed": 0})
    assert img.size == (320, 170) and img.mode == "RGB"
    assert img.getpixel((1, 1)) == rs.BG
    assert lit(img, (8, 8, 180, 44)) > 300            # RAGNAR
    assert lit(img, (8, 52, 180, 100)) > 100          # the message
    assert lit(img, (200, 10, 312, 140)) > 2000       # the viking
    assert lit(img, (8, 150, 312, 168)) == 0          # no progress bar unless asked


def test_progress_bar_fills_with_the_percentage():
    def green(pct):
        img = rs.render("Installing Ragnar", "x", pct, {"screen_reversed": 0})
        return sum(1 for p in img.crop((8, 152, 312, 164)).getdata() if p == rs.BAR)
    assert green(0) == 0 and 0 < green(40) < green(100)
    assert green(250) == green(100)                   # clamped


def test_long_text_stays_clear_of_the_character():
    words = "word " * 80
    full = rs.render(words, words, 50, {"screen_reversed": 0})
    bare = rs.render("", "", 50, {"screen_reversed": 0})
    assert full.crop((205, 0, 320, 148)).tobytes() == bare.crop((205, 0, 320, 148)).tobytes()


def test_it_is_drawn_the_way_up_ragnar_will_draw():
    upright = rs.render("Starting up", "x", config={"screen_reversed": 0})
    flipped = rs.render("Starting up", "x", config={"screen_reversed": 180})
    assert flipped.tobytes() == upright.rotate(180).tobytes()
    # Nothing saved yet (first install): this panel's default is 180.
    assert rs.render("Starting up", "x", config={}).tobytes() == flipped.tobytes()
    assert rs.rotation({"screen_reversed": True}) == 180 and rs.rotation({"screen_reversed": 90}) == 0


def test_the_shieldmaiden_is_shown_when_she_is_the_character():
    him = rs.render("x", "y", config={"screen_reversed": 0})
    her = rs.render("x", "y", config={"screen_reversed": 0, "mesh_viking_gender": "female"})
    assert him.tobytes() != her.tobytes()


# ── only on this board, never over a running Ragnar ──────────────────────────

def test_board_is_taken_from_the_saved_display_setting(tmp_path, monkeypatch):
    monkeypatch.delenv("RAGNAR_SPLASH_BOARD", raising=False)
    assert rs.is_cardputer_zero({"epd_type": "st7789v2"}) is True
    assert rs.is_cardputer_zero({"epd_type": "epd2in13_V4"}) is False
    # No setting yet: the model string and the board's own expander decide.
    model = tmp_path / "proc/device-tree"
    model.mkdir(parents=True)
    (model / "model").write_text("Raspberry Pi Compute Module 0 Rev 1.0\x00")
    monkeypatch.setattr(rs, "expander_answers", lambda *a: True)
    assert rs.is_cardputer_zero({}, root=str(tmp_path)) is True
    monkeypatch.setattr(rs, "expander_answers", lambda *a: False)
    assert rs.is_cardputer_zero({}, root=str(tmp_path)) is False     # a CM0 in another carrier
    (model / "model").write_text("Raspberry Pi 5 Model B Rev 1.0\x00")
    monkeypatch.setattr(rs, "expander_answers", lambda *a: True)
    assert rs.is_cardputer_zero({}, root=str(tmp_path)) is False
    monkeypatch.setenv("RAGNAR_SPLASH_BOARD", "1")                    # the installer's menu choice
    assert rs.is_cardputer_zero({}, root=str(tmp_path)) is True


@pytest.fixture
def shown(monkeypatch):
    calls = []
    monkeypatch.setattr(rs, "show", lambda image, wait=0.0, driver=None: calls.append((image, wait)) or True)
    monkeypatch.setattr(rs, "saved_config", lambda root="": {"epd_type": "st7789v2", "screen_reversed": 0})
    monkeypatch.setattr(rs, "ragnar_is_running", lambda runner=None: False)
    monkeypatch.delenv("RAGNAR_SPLASH_BOARD", raising=False)
    return calls


def test_boot_start_and_install_each_draw(shown):
    assert rs.main(["--boot", "--wait", "20"]) == 0 and shown[-1][1] == 20
    assert rs.main(["--start"]) == 0
    assert rs.main(["--install", "Installing system dependencies", "--progress", "27"]) == 0
    assert len(shown) == 3
    assert len({image.tobytes() for image, _ in shown}) == 3


def test_other_boards_are_never_drawn_on(shown, monkeypatch):
    monkeypatch.setattr(rs, "saved_config", lambda root="": {"epd_type": "epd2in13_V4"})
    for args in (["--boot"], ["--start"], ["--install", "x"]):
        assert rs.main(args) == 0
    assert shown == []


def test_a_running_ragnar_keeps_its_screen(shown, monkeypatch):
    monkeypatch.setattr(rs, "ragnar_is_running", lambda runner=None: True)
    assert rs.main(["--boot"]) == 0 and rs.main(["--install", "x"]) == 0
    assert shown == []
    assert rs.main(["--install", "x", "--force"]) == 0 and len(shown) == 1
    # --start runs from the service's own start-up, when the unit already counts as active.
    assert rs.main(["--start"]) == 0 and len(shown) == 2


def test_running_check_reads_systemd():
    def run(state):
        return lambda cmd, **kw: types.SimpleNamespace(stdout=state + "\n")
    assert rs.ragnar_is_running(run("active")) is True
    assert rs.ragnar_is_running(run("activating")) is False
    assert rs.ragnar_is_running(lambda *a, **k: 1 / 0) is False


def test_png_option_touches_no_hardware(tmp_path, shown):
    out = tmp_path / "s.png"
    assert rs.main(["--install", "Step", "--progress", "50", "--png", str(out)]) == 0
    assert Image.open(out).size == (320, 170) and shown == []


def test_show_retries_while_the_devices_appear(monkeypatch):
    attempts = []

    class EPD:
        def init(self):
            attempts.append(1)
            if len(attempts) < 3:
                raise RuntimeError("no LCD yet")

        def getbuffer(self, image):
            return b"frame"

        def display(self, buf):
            attempts.append(buf)

    monkeypatch.setattr(rs.time, "sleep", lambda s: None)
    img = rs.render("x", "y", config={})
    assert rs.show(img, wait=5, driver=types.SimpleNamespace(EPD=EPD)) is True
    assert attempts == [1, 1, 1, b"frame"]

    class Dead(EPD):
        def init(self):
            raise RuntimeError("no LCD")
    assert rs.show(img, wait=0, driver=types.SimpleNamespace(EPD=Dead)) is False


# ── Ragnar's own start: no white screen, no blank after the panel reset ──────

def driver():
    sys.path.insert(0, os.path.join(ROOT, "resources", "waveshare_epd"))
    import st7789v2
    return st7789v2


def test_panel_init_paints_the_start_picture(monkeypatch):
    drv = driver()
    epd = drv.EPD()
    frames = []
    monkeypatch.setattr(epd, "_init_framebuffer", lambda: False)
    monkeypatch.setattr(epd, "_init_spi", lambda: True)
    monkeypatch.setattr(epd, "_blit", frames.append)
    epd.init()
    assert len(frames) == 1 and len(frames[0]) == 320 * 170 * 2
    assert frames[0] != bytes(len(frames[0]))             # not a black frame
    epd.init()
    assert len(frames) == 1                               # once, not on every loop
    quiet = drv.EPD()
    quiet.boot_screen = False
    monkeypatch.setattr(quiet, "_init_framebuffer", lambda: False)
    monkeypatch.setattr(quiet, "_init_spi", lambda: True)
    monkeypatch.setattr(quiet, "_blit", frames.append)
    quiet.init()
    assert len(frames) == 1


def test_service_start_shows_the_picture_instead_of_wiping_to_white(monkeypatch):
    import wipe_epd
    called = []
    monkeypatch.setattr(wipe_epd, "resolve_epd_type", lambda: "st7789v2")
    monkeypatch.setattr(wipe_epd, "wipe_display", lambda t: called.append(("wipe", t)))
    monkeypatch.setattr(rs, "main", lambda argv=None: called.append(("splash", argv)) or 0)
    assert wipe_epd.main() == 0
    assert called == [("splash", ["--start"])]
    monkeypatch.setattr(wipe_epd, "resolve_epd_type", lambda: "epd2in13_V4")
    wipe_epd.main()
    assert called[-1] == ("wipe", "epd2in13_V4")          # e-paper is still wiped


# ── early in boot: the systemd unit ──────────────────────────────────────────

def hardware(tmp_path, action):
    (tmp_path / "sys/class/leds/ext_5v_out").mkdir(parents=True, exist_ok=True)
    (tmp_path / "sys/class/leds/ext_5v_out/brightness").write_text("1\n")
    (tmp_path / "boot/firmware").mkdir(parents=True, exist_ok=True)
    (tmp_path / "boot/firmware/config.txt").write_text("dtoverlay=imx219\n")
    env = dict(os.environ, RAGNAR_CARDPUTER_ROOT=str(tmp_path), RAGNAR_CARDPUTER_CAP="")
    out = subprocess.run(["bash", os.path.join(ROOT, "scripts", "cardputer_hardware.sh"), action],
                         capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stdout + out.stderr
    return out


def test_setup_installs_the_boot_unit_and_removal_sticks(tmp_path):
    unit = tmp_path / "etc/systemd/system/ragnar-splash.service"
    link = tmp_path / "etc/systemd/system/basic.target.wants/ragnar-splash.service"
    assert "boot screen installed" in hardware(tmp_path, "setup").stdout
    text = unit.read_text()
    assert f"ExecStart=/usr/bin/python3 {ROOT}/ragnar_splash.py --boot --wait 20" in text
    assert "DefaultDependencies=no" in text and "WantedBy=basic.target" in text
    assert "Before=" not in text and "Type=simple" in text      # cannot hold the boot up
    assert link.is_symlink()
    assert "boot screen installed" not in hardware(tmp_path, "setup").stdout   # unchanged
    hardware(tmp_path, "boot-screen-off")
    assert not unit.exists() and not link.is_symlink()
    hardware(tmp_path, "setup")                                  # an update
    assert not unit.exists()
    hardware(tmp_path, "boot-screen")                            # asked for again
    assert unit.exists()


# ── the installer ────────────────────────────────────────────────────────────

def installer(tmp_path, model, cardputer="false", script=""):
    src = open(os.path.join(ROOT, "install_ragnar.sh")).read()
    block = src[src.index("show_progress() {"):src.index("# ── end of the install splash ──")]
    model_file = tmp_path / "model"
    model_file.write_text(model)
    log = tmp_path / "splash.log"
    body = f"""
set -u
BLUE=""; NC=""; TOTAL_STEPS=11; CURRENT_STEP=0
CARDPUTER_MODE={cardputer}
ragnar_PATH={tmp_path}/none
SPLASH_MODEL_FILE={model_file}
SPLASH_DRY_RUN={log}
BASH_SOURCE_DIR={ROOT}
{block}
install_splash "Answer the questions in your terminal"
{script}
CURRENT_STEP=3; show_progress "Installing system dependencies" >/dev/null
CURRENT_STEP=11; show_progress "Finishing" >/dev/null
"""
    path = os.path.join(ROOT, "._splash_test.sh")           # beside the real files it looks for
    with open(path, "w") as f:
        f.write(body)
    try:
        out = subprocess.run(["bash", path], capture_output=True, text=True)
    finally:
        os.remove(path)
    assert out.returncode == 0, out.stderr
    return log.read_text().splitlines() if log.exists() else []


def test_installer_shows_progress_on_a_cardputer_from_the_first_minute(tmp_path):
    lines = installer(tmp_path, "Raspberry Pi Compute Module 0 Rev 1.0")
    assert lines == [
        f"splash: {ROOT} --install Answer the questions in your terminal",
        f"splash: {ROOT} --install Installing system dependencies --progress 27",
        f"splash: {ROOT} --install Finishing --progress 100",
    ]


def test_installer_draws_nothing_on_other_boards(tmp_path):
    assert installer(tmp_path, "Raspberry Pi 5 Model B Rev 1.0") == []


def test_installer_starts_once_the_menu_says_cardputer(tmp_path):
    lines = installer(tmp_path, "Some other carrier", script="CARDPUTER_MODE=true")
    assert len(lines) == 2 and lines[0].endswith("--install Installing system dependencies --progress 27")
