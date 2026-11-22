"""Supported-channel parsing from `iw phy <phy> info` (wardriving.py).

Newer iw prints frequencies with a decimal ('* 2412.0 MHz [1]'); the parser
only matched '* 2412 MHz', so every adapter fell back to "let the kernel pick
channels" and split-band mode could not assign bands.
"""

import types

import pytest

import wardriving

IW_NEW = """Wiphy phy1
	Band 1:
		Frequencies:
			* 2412.0 MHz [1] (20.0 dBm)
			* 2437.0 MHz [6] (20.0 dBm)
			* 2484.0 MHz [14] (disabled)
	Band 2:
		Frequencies:
			* 5180.0 MHz [36] (23.0 dBm)
			* 5260.0 MHz [52] (23.0 dBm) (radar detection)
"""
IW_OLD = IW_NEW.replace('.0 MHz', ' MHz')


@pytest.mark.parametrize('iw_out', [IW_NEW, IW_OLD], ids=['decimal', 'integer'])
def test_supported_freqs_parse_both_iw_formats(monkeypatch, iw_out):
    e = wardriving.WardrivingEngine.__new__(wardriving.WardrivingEngine)
    e._iface_freq_cache = {}
    e.band_mode = 'redundant'
    monkeypatch.setattr(e, '_iface_phy', lambda iface: 'phy1')
    monkeypatch.setattr(wardriving.subprocess, 'run',
                        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=iw_out, stderr=''))
    assert e._iface_supported_freqs('wlan1') == [2412, 2437, 5180, 5260]
