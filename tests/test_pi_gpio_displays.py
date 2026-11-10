"""scripts/pi_gpio_displays.sh — GPIO display support on a Pi that is not
running Raspberry Pi OS (the Kali-based Ulfberht edition).

The config.txt editing and the udev rule are the parts that can silently do the
wrong thing on someone's boot partition, so they are exercised here against
real files. The package installs are covered on hardware, not here.
"""
import os
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, 'scripts', 'pi_gpio_displays.sh')


def _sh(snippet, env=None):
    """Source the script (functions only) and run a snippet."""
    full = f'source "{SCRIPT}"\n{snippet}\n'
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(['bash', '-c', full], capture_output=True, text=True, env=e)


def _enable(tmp_path, content, param='spi'):
    cfg = tmp_path / 'config.txt'
    cfg.write_text(content)
    r = _sh(f'enable_dtparam "{cfg}" {param}; echo "rc=$? reboot=$REBOOT_REQUIRED"')
    return cfg.read_text(), r.stdout.strip()


def test_sourcing_runs_nothing():
    r = _sh('echo sourced')
    assert r.stdout.strip() == 'sourced'


def test_uncomments_the_stock_line(tmp_path):
    text, out = _enable(tmp_path, '#dtparam=i2c_arm=on\n#dtparam=i2s=on\n#dtparam=spi=on\ndtparam=audio=on\n')
    assert text == '#dtparam=i2c_arm=on\n#dtparam=i2s=on\ndtparam=spi=on\ndtparam=audio=on\n'
    assert out == 'rc=0 reboot=true'


def test_already_enabled_is_left_alone(tmp_path):
    for content in ('dtparam=spi=on\n', '  dtparam=spi=on  \n', 'dtparam=i2c_arm=on,spi=on\n',
                    'dtparam=spi=on,i2c_arm=on\n'):
        text, out = _enable(tmp_path, content)
        assert text == content
        assert out == 'rc=0 reboot=false'


def test_appends_under_all_when_absent(tmp_path):
    text, out = _enable(tmp_path, 'dtoverlay=vc4-kms-v3d\n[cm5]\ndtoverlay=dwc2,dr_mode=host\n')
    assert text.startswith('dtoverlay=vc4-kms-v3d\n[cm5]\ndtoverlay=dwc2,dr_mode=host\n')
    tail = text.split('dr_mode=host\n', 1)[1]
    # Must land in an [all] section, not inside the trailing [cm5] filter.
    assert tail.strip().splitlines()[0] == '[all]'
    assert tail.strip().splitlines()[-1] == 'dtparam=spi=on'
    assert out == 'rc=0 reboot=true'


def test_does_not_match_a_different_param(tmp_path):
    # spi=off, a look-alike name and a commented explanation are not "enabled".
    text, out = _enable(tmp_path, 'dtparam=spi=off\ndtparam=xspi=on\n# set dtparam=spi=on to use SPI\n')
    assert text.rstrip().endswith('dtparam=spi=on')
    assert 'dtparam=spi=off\ndtparam=xspi=on\n# set dtparam=spi=on to use SPI\n' in text
    assert out == 'rc=0 reboot=true'


def test_i2c_and_spi_are_independent_and_idempotent(tmp_path):
    cfg = tmp_path / 'config.txt'
    cfg.write_text('#dtparam=i2c_arm=on\n#dtparam=spi=on\n')
    snippet = f'enable_dtparam "{cfg}" spi; enable_dtparam "{cfg}" i2c_arm; '
    _sh(snippet)
    once = cfg.read_text()
    assert once == 'dtparam=i2c_arm=on\ndtparam=spi=on\n'
    r = _sh(snippet + 'echo "reboot=$REBOOT_REQUIRED"')
    assert cfg.read_text() == once
    assert r.stdout.strip() == 'reboot=false'


def test_only_first_commented_line_is_uncommented(tmp_path):
    text, _ = _enable(tmp_path, '#dtparam=spi=on\n[pi4]\n#dtparam=spi=on\n')
    assert text == 'dtparam=spi=on\n[pi4]\n#dtparam=spi=on\n'


def test_gpiochip4_rule_written_once_and_matches_only_rp1(tmp_path):
    rule = tmp_path / 'rules.d' / '99-ragnar-pi5-gpiochip4.rules'
    snippet = f'UDEV_RULE="{rule}"; IMAGE_BUILD=true; ensure_gpiochip4_alias'
    first = _sh(snippet)
    assert 'installed' in first.stdout
    body = rule.read_text()
    lines = [l for l in body.splitlines() if l and not l.startswith('#')]
    assert lines == ['SUBSYSTEM=="gpio", KERNEL=="gpiochip0", KERNELS=="1f000d0000.gpio", SYMLINK+="gpiochip4"']
    second = _sh(snippet)
    assert 'present' in second.stdout
    assert rule.read_text() == body


def test_not_a_pi_is_a_noop():
    if os.path.exists('/proc/device-tree/model') and 'Raspberry Pi' in open('/proc/device-tree/model').read():
        pytest.skip('running on a Raspberry Pi')
    r = subprocess.run(['bash', SCRIPT], capture_output=True, text=True)
    assert r.returncode == 0
    assert 'not a Raspberry Pi' in r.stdout


def test_unprivileged_run_changes_nothing_and_exits_zero():
    if os.geteuid() == 0:
        pytest.skip('running as root')
    r = subprocess.run(['bash', SCRIPT], capture_output=True, text=True,
                       env=dict(os.environ, RAGNAR_FORCE_PI='1'))
    assert r.returncode == 0
    assert 'must run as root' in r.stdout
    assert 'REBOOT_REQUIRED' not in r.stdout


def test_installer_and_updater_both_run_the_script():
    for name in ('install_ragnar.sh', 'update_ragnar.sh'):
        text = open(os.path.join(REPO, name)).read()
        assert 'scripts/pi_gpio_displays.sh' in text, name
    assert os.access(SCRIPT, os.X_OK)
