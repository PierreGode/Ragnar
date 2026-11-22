"""Building the CardputerZero OS image: the installer and the hardware script
run in a chroot with no board to look at, and first boot finishes the job."""

import os
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HW = os.path.join(ROOT, "scripts", "cardputer_hardware.sh")
LORA = os.path.join(ROOT, "scripts", "cardputer_lora_meshtastic.sh")

STOCK_CONFIG = """# For more options and information see
#dtparam=i2c_arm=on
#dtparam=spi=on
camera_auto_detect=1
[cm5]
dtoverlay=dwc2,dr_mode=host
[all]
"""
STOCK_CMDLINE = "console=serial0,115200 console=tty1 root=ROOTDEV rootfstype=ext4 fsck.repair=yes rootwait\n"


@pytest.fixture
def root(tmp_path):
    boot = tmp_path / "boot" / "firmware"
    boot.mkdir(parents=True)
    (boot / "config.txt").write_text(STOCK_CONFIG)
    (boot / "cmdline.txt").write_text(STOCK_CMDLINE)
    return tmp_path


def run(script, *args, root=None, **env):
    environ = dict(os.environ, **env)
    if root is not None:
        environ["RAGNAR_CARDPUTER_ROOT"] = str(root)
    return subprocess.run(["bash", script, *args], capture_output=True, text=True, env=environ)


def active(text):
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


def test_image_writes_everything_the_board_needs(root):
    done = run(HW, "image", root=root)
    assert done.returncode == 0, done.stderr
    assert done.stderr == ""
    config = active((root / "boot/firmware/config.txt").read_text())
    for line in ("dtparam=spi=on", "dtparam=i2c_arm=on", "enable_uart=1",
                 "dtoverlay=imx219", "camera_auto_detect=0"):
        assert config.count(line) == 1, line
    assert "camera_auto_detect=1" not in config
    # Our lines must not land inside the [cm5] section of the stock file.
    assert config.index("[all]") < config.index("dtparam=spi=on")
    assert config[config.index("dtparam=spi=on") - 1] == "[all]"
    cmdline = (root / "boot/firmware/cmdline.txt").read_text()
    assert cmdline == "console=tty1 root=ROOTDEV rootfstype=ext4 fsck.repair=yes rootwait\n"
    system = root / "etc/systemd/system"
    assert os.readlink(system / "serial-getty@ttyS0.service") == "/dev/null"
    assert (system / "ragnar-splash.service").is_file()
    assert os.readlink(system / "basic.target.wants/ragnar-splash.service") == "../ragnar-splash.service"
    assert (root / "etc/modules-load.d/ragnar-cardputer.conf").read_text().strip() == "i2c-dev"
    assert (root / "etc/ragnar-cardputer-image").is_file()


def test_image_twice_changes_nothing_more(root):
    run(HW, "image", root=root)
    first = {p: (root / p).read_text() for p in ("boot/firmware/config.txt", "boot/firmware/cmdline.txt")}
    assert run(HW, "image", root=root).returncode == 0
    for path, text in first.items():
        assert (root / path).read_text() == text


def test_image_keeps_lines_that_are_already_there(root):
    (root / "boot/firmware/config.txt").write_text(
        "dtparam=spi=on\ndtparam=i2c_arm=on\nenable_uart=1\ndtoverlay=imx219\ncamera_auto_detect=0\n")
    (root / "boot/firmware/cmdline.txt").write_text("console=tty1 root=ROOTDEV rootwait\n")
    run(HW, "image", root=root)
    assert "Ragnar: CardputerZero buses" not in (root / "boot/firmware/config.txt").read_text()
    assert (root / "boot/firmware/cmdline.txt").read_text() == "console=tty1 root=ROOTDEV rootwait\n"


def test_image_overrides_an_earlier_boot_screen_opt_out(root):
    (root / "etc").mkdir()
    (root / "etc/ragnar-splash-optout").write_text("")
    run(HW, "image", root=root)
    assert (root / "etc/systemd/system/ragnar-splash.service").is_file()


def test_script_runs_clean_on_a_machine_that_is_not_the_board():
    """It once died here on an unset variable, which on plain Raspberry Pi OS
    (where Ragnar's own setting is the only sign of the board) stopped the
    whole setup."""
    done = run(HW, "status")
    assert done.returncode == 0
    assert done.stderr == ""
    text = open(HW).read()
    assert text.count('\nREPO="$(cd') == 1
    assert "SELF_" not in text


def test_meshtasticd_package_only_leaves_it_switched_off(root):
    wants = root / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True)
    (wants / "meshtasticd.service").symlink_to("/lib/systemd/system/meshtasticd.service")
    done = run(LORA, "package", root=root, RAGNAR_FAKE_MESHTASTICD="1")
    assert done.returncode == 0, done.stdout + done.stderr
    assert not os.path.lexists(wants / "meshtasticd.service")
    assert not (root / "etc/meshtasticd/config.d/ragnar-cardputerzero-cap-lora.yaml").exists()
    assert not (root / "etc/ragnar-meshtasticd-optout").exists()


def test_meshtasticd_package_reports_a_missing_daemon(root):
    env = dict(os.environ, RAGNAR_CARDPUTER_ROOT=str(root), PATH="/usr/bin:/bin")
    env.pop("RAGNAR_FAKE_MESHTASTICD", None)
    done = subprocess.run(["bash", LORA, "package"], capture_output=True, text=True, env=env)
    if subprocess.run(["bash", "-c", "command -v meshtasticd"], capture_output=True, env=env).returncode == 0:
        pytest.skip("meshtasticd is installed here")
    assert done.returncode == 1
    assert "could not be installed" in done.stdout


def test_first_boot_finishes_the_setup_only_on_the_cardputer_image():
    text = open(os.path.join(ROOT, "scripts", "ragnar-firstboot.sh")).read()
    step = text[text.index("/etc/ragnar-cardputer-image"):]
    assert 'cardputer_hardware.sh" setup' in step[:400]
    # Before the stamp is written, so a failed first boot tries again.
    assert text.index("/etc/ragnar-cardputer-image") < text.index('> "$STAMP"')
    assert subprocess.run(["bash", "-n", os.path.join(ROOT, "scripts", "ragnar-firstboot.sh")]).returncode == 0


def test_installer_image_build_uses_the_image_mode_and_draws_nothing(tmp_path):
    src = open(os.path.join(ROOT, "install_ragnar.sh")).read()
    assert 'cardputer_hardware.sh" image' in src
    block = src[src.index("show_progress() {"):src.index("# ── end of the install splash ──")]
    log = tmp_path / "splash.log"
    script = tmp_path / "t.sh"
    script.write_text(f"""
set -u
BLUE=""; NC=""; TOTAL_STEPS=11; CURRENT_STEP=0
CARDPUTER_MODE=true
IMAGE_BUILD=true
ragnar_PATH={ROOT}
SPLASH_DRY_RUN={log}
{block}
CURRENT_STEP=3; show_progress "Installing system dependencies" >/dev/null
echo "state=$SPLASH_STATE"
""")
    done = subprocess.run(["bash", str(script)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert "state=no" in done.stdout
    assert not log.exists()


def test_installer_cardputer_profile_is_unattended():
    src = open(os.path.join(ROOT, "install_ragnar.sh")).read()
    profile = src[src.index("cardputer|cardputerzero)"):]
    profile = profile[:profile.index(";;")]
    assert "CARDPUTER_MODE=true" in profile and 'EPD_VERSION="st7789v2"' in profile
