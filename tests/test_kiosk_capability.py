"""Tests for the on-screen kiosk hardware gate.

The kiosk drives a full Chromium, which needs roughly 1GB resident on its own.
A Pi Zero 2 W has 512MB total, so a kiosk there swaps continuously: the display
lags and it takes Ragnar's scanning down with it. The kiosk is therefore a
Ragnar Pi server feature, gated in server_capabilities and enforced by the web
API and the installer.

What matters here is where the line falls: a real 2GB Pi 4 reports ~1.9GB after
firmware reservations, so a naive `>= 2.0` test would refuse a board that runs
the kiosk perfectly well.
"""

import pytest

from server_capabilities import ServerCapabilities, SystemCapabilities


def verdict(ram_gb, cores=4, is_pi_zero=False):
    """Run the kiosk gate against a made-up board, without touching this host."""
    sc = ServerCapabilities.__new__(ServerCapabilities)   # no hardware detection
    sc.capabilities = SystemCapabilities(
        total_ram_gb=ram_gb, cpu_cores=cores, is_pi_zero=is_pi_zero
    )
    return sc._evaluate_kiosk_support()


@pytest.mark.parametrize("ram_gb,cores,is_pi_zero", [
    (0.42, 4, True),    # Pi Zero 2 W: 512MB board, ~415MB usable
    (0.9, 4, False),    # Pi 4 1GB
    (1.5, 4, False),    # anything under the 2GB class
    (0.0, 4, False),    # RAM unreadable - fail closed rather than guess
    (4.0, 1, False),    # single core
])
def test_underpowered_boards_are_refused(ram_gb, cores, is_pi_zero):
    capable, reason = verdict(ram_gb, cores, is_pi_zero)
    assert capable is False
    # The reason is shown verbatim in the UI and the installer, so it has to say
    # something; "not supported" with no numbers sends people hunting.
    assert reason.strip()


@pytest.mark.parametrize("ram_gb", [
    1.9,    # a real 2GB Pi 4 reports ~1.9GB - must NOT be refused
    3.9,    # Pi 5 4GB
    7.87,   # Pi 5 8GB (the same board server mode calls capable)
    15.8,   # 16GB Pi 5
])
def test_capable_boards_are_allowed(ram_gb):
    capable, reason = verdict(ram_gb)
    assert capable is True
    assert reason == ""


def test_pi_zero_is_refused_even_with_reported_ram_above_the_floor():
    """Model wins over the RAM number.

    A Zero that somehow reports plenty of RAM (a bad read, a spoofed
    /proc/meminfo, a future Zero) is still a Zero-class board.
    """
    capable, reason = verdict(4.0, cores=4, is_pi_zero=True)
    assert capable is False
    assert 'Zero' in reason


def test_flags_land_on_the_capabilities_object():
    """_determine_feature_flags must publish the gate, since that is what the
    API (`/api/kiosk/status`, `/api/server/capabilities`) reports."""
    sc = ServerCapabilities.__new__(ServerCapabilities)
    sc.shared_data = None
    sc.capabilities = SystemCapabilities(total_ram_gb=0.42, cpu_cores=4, is_pi_zero=True)
    sc._determine_feature_flags()
    assert sc.capabilities.kiosk_capable is False
    assert sc.capabilities.kiosk_block_reason
    assert sc.get_feature_status()['kiosk'] is False

    sc.capabilities = SystemCapabilities(total_ram_gb=3.9, cpu_cores=4)
    sc._determine_feature_flags()
    assert sc.capabilities.kiosk_capable is True
    assert sc.get_feature_status()['kiosk'] is True


def test_kiosk_gate_is_independent_of_full_server_mode():
    """A 4GB Pi 5 is not 'server capable' (that bar is 7.5GB for OpenVAS-class
    work) but it hosts a kiosk fine. The two gates must not be the same flag."""
    sc = ServerCapabilities.__new__(ServerCapabilities)
    sc.shared_data = None
    sc.capabilities = SystemCapabilities(total_ram_gb=3.9, cpu_cores=4,
                                         is_server_capable=False)
    sc._determine_feature_flags()
    assert sc.capabilities.is_server_capable is False
    assert sc.capabilities.kiosk_capable is True
