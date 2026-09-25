"""Tests for the Advanced Vulnerability Scanning / OWASP ZAP hardware gate.

Advanced Vuln used to ride on full server mode (7.5GB RAM), which hid the whole
tab on smaller boards. That was too blunt: nuclei / nikto / sqlmap / nmap /
whatweb are light CLI tools that run fine on a 4GB Pi. Only OWASP ZAP — a Java
daemon that holds ~1GB+ resident — genuinely needs a server-class box.

So the tab is now gated on nmap alone, while ZAP keeps its own RAM floor
(ZAP_MIN_RAM_GB) and greys out beneath it. These tests pin that split.
"""

import pytest

from server_capabilities import ServerCapabilities, SystemCapabilities


def caps_for(ram_gb, nmap=True, is_server_capable=False):
    """A ServerCapabilities describing a made-up board, no hardware detection."""
    sc = ServerCapabilities.__new__(ServerCapabilities)
    sc.shared_data = None
    sc.capabilities = SystemCapabilities(
        architecture='aarch64',
        total_ram_gb=ram_gb,
        cpu_cores=4,
        is_server_capable=is_server_capable,
        available_tools={'nmap': nmap},
    )
    return sc


def test_advanced_vuln_runs_on_a_4gb_board_with_nmap():
    """A 4GB Pi is not 'server capable' but should still get the Adv Scan tab:
    the light scanners cost almost nothing."""
    sc = caps_for(3.9, nmap=True, is_server_capable=False)
    sc._determine_feature_flags()
    assert sc.get_feature_status()['advanced_vuln_assessment'] is True


def test_advanced_vuln_needs_nmap():
    """No nmap, no Adv Scan — nmap is the one hard dependency."""
    sc = caps_for(15.0, nmap=False, is_server_capable=True)
    sc._determine_feature_flags()
    assert sc.get_feature_status()['advanced_vuln_assessment'] is False


@pytest.mark.parametrize("ram_gb,expected_zap", [
    (0.42, False),   # Pi Zero 2 W
    (3.9, False),    # Pi 5 4GB — Adv Scan yes, ZAP no
    (7.4, False),    # just under the 7.5GB floor
    (7.87, True),    # Pi 5 8GB reports ~7.87GB after reservations
    (15.8, True),    # Pi 5 16GB
])
def test_zap_is_gated_on_ram_not_the_whole_tab(ram_gb, expected_zap):
    sc = caps_for(ram_gb, nmap=True, is_server_capable=(ram_gb >= 7.5))
    sc._determine_feature_flags()
    f = sc.get_feature_status()
    # The tab itself is available on every one of these boards...
    assert f['advanced_vuln_assessment'] is True
    # ...but ZAP only lights up once there is enough RAM.
    assert f['zap'] is expected_zap
    assert sc.capabilities.zap_enabled is expected_zap


@pytest.mark.parametrize("ram_gb,expected_nuclei", [
    (0.42, False),   # Pi Zero 2 W (~430MB) — greyed out, steered to mesh
    (0.85, False),   # ~870MB, just under the 900MB floor
    (0.90, True),    # ~921MB, just over
    (1.0, True),     # 1GB Pi 3 — the board that already works
    (8.0, True),     # big board
])
def test_nuclei_is_gated_at_900mb(ram_gb, expected_nuclei):
    sc = caps_for(ram_gb, nmap=True, is_server_capable=(ram_gb >= 7.5))
    sc._determine_feature_flags()
    f = sc.get_feature_status()
    # The tab and the light scanners stay available on every board...
    assert f['advanced_vuln_assessment'] is True
    # ...but Nuclei greys out below ~900MB so a tiny board can't crash on it.
    assert f['nuclei'] is expected_nuclei
    assert sc.capabilities.nuclei_enabled is expected_nuclei
