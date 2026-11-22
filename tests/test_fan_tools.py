"""Cooling-fan helpers (fan_tools.py): presence verdict, curve rules, config.txt."""

import pytest

import fan_tools


@pytest.mark.parametrize('pwm, rpm, tach, state, expect', [
    (175, 7800, True, 3, True),      # turning
    (175, 0, True, 3, False),        # commanded on, tach silent: absent / stalled
    (0, 0, True, 0, None),           # idle: can't tell without a spin test
    (None, None, False, 1, None),    # gpio-fan: no tachometer at all
])
def test_presence(pwm, rpm, tach, state, expect):
    connected, why = fan_tools._presence(pwm, rpm, tach, state)
    assert connected is expect
    assert why


def test_curve_must_ascend_and_stay_in_range():
    assert fan_tools._validate_curve([50, 60, 67.5, 75]) == [50, 60, 67.5, 75]
    with pytest.raises(ValueError):
        fan_tools._validate_curve([60, 55, 65, 70])
    with pytest.raises(ValueError):
        fan_tools._validate_curve([20, 60, 65, 70])
    with pytest.raises(ValueError):
        fan_tools._validate_curve([50, 60, 70, 95])


def test_persist_curve_replaces_only_its_block(tmp_path, monkeypatch):
    cfg = tmp_path / 'config.txt'
    cfg.write_text('dtparam=audio=on\n[pi4]\narm_boost=1\n')
    monkeypatch.setattr(fan_tools, '_boot_cfg', lambda: str(cfg))
    monkeypatch.setattr(fan_tools, '_fan_header_present', lambda: True)

    res = fan_tools.persist_curve([45, 55, 65, 72], [5, 5, 5, 5])
    assert res['success']
    text = cfg.read_text()
    # Appended under an explicit [all], never inside the trailing [pi4] filter.
    assert text.index('[all]') > text.index('arm_boost=1')
    assert 'dtparam=fan_temp0=45000' in text
    assert 'dtparam=fan_temp3_hyst=5000' in text
    assert fan_tools.persisted_curve() == {
        'fan_temp0': 45.0, 'fan_temp1': 55.0, 'fan_temp2': 65.0, 'fan_temp3': 72.0}

    # Saving again doesn't pile up lines; removing restores the original.
    fan_tools.persist_curve([50, 60, 67.5, 75], [5, 5, 5, 5])
    assert cfg.read_text().count('fan_temp0=') == 1
    fan_tools.persist_curve(None)
    assert cfg.read_text() == 'dtparam=audio=on\n[pi4]\narm_boost=1\n'
    assert fan_tools.persisted_curve() is None


def test_persist_refused_without_pi5_header(monkeypatch):
    monkeypatch.setattr(fan_tools, '_fan_header_present', lambda: False)
    assert fan_tools.persist_curve([50, 60, 67.5, 75])['success'] is False
