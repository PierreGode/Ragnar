"""Tests for RAM-aware nuclei resource tuning.

Nuclei loads its whole matched template set into memory and runs 25 templates
concurrently by default. On a 512MB Pi Zero 2 W that OOMs and locks the board
up. _nuclei_resource_tuning() scales concurrency / template-load / heap down on
small boards while leaving capable boards at full tilt.
"""

import advanced_vuln_scanner as mod
from advanced_vuln_scanner import AdvancedVulnScanner


def _tuning(monkeypatch, total, avail):
    scanner = AdvancedVulnScanner.__new__(AdvancedVulnScanner)
    scanner.shared_data = None

    class _Caps:
        pass

    caps = _Caps()
    caps.capabilities = _Caps()
    caps.capabilities.total_ram_gb = total
    caps.capabilities.available_ram_gb = avail
    monkeypatch.setattr(mod, "get_server_capabilities", lambda shared_data=None: caps)
    return scanner._nuclei_resource_tuning(150, "low,medium,high,critical")


def _flag(flags, name):
    return flags[flags.index(name) + 1] if name in flags else None


def test_pi_zero_tier_is_aggressively_limited(monkeypatch):
    flags, env, severity, note = _tuning(monkeypatch, 0.42, 0.25)
    assert _flag(flags, "-c") == "8"
    assert _flag(flags, "-template-loading-concurrency") == "5"
    assert int(_flag(flags, "-rate-limit")) <= 50
    assert "-no-interactsh" in flags
    # heap capped and Go GC made aggressive
    assert env["GOMEMLIMIT"].endswith("MiB")
    assert env["GOMAXPROCS"] == "2"
    # default severity tightened to shrink the loaded template set
    assert severity == "high,critical"
    assert note


def test_one_gb_tier_is_moderate(monkeypatch):
    flags, env, severity, note = _tuning(monkeypatch, 1.0, 0.6)
    assert _flag(flags, "-c") == "15"
    assert "GOMEMLIMIT" in env
    # coverage not reduced on this tier
    assert severity == "low,medium,high,critical"
    assert note


def test_capable_board_runs_full_tilt(monkeypatch):
    flags, env, severity, note = _tuning(monkeypatch, 8.0, 6.0)
    assert _flag(flags, "-c") == "25"
    assert _flag(flags, "-rate-limit") == "150"
    assert env == {}            # no Go runtime cap
    assert severity == "low,medium,high,critical"
    assert note == ""           # nothing to warn about


def test_user_severity_choice_is_respected_on_small_boards(monkeypatch):
    # If the caller picked a non-default severity, don't override it.
    scanner = AdvancedVulnScanner.__new__(AdvancedVulnScanner)
    scanner.shared_data = None

    class _Caps:
        pass

    caps = _Caps()
    caps.capabilities = _Caps()
    caps.capabilities.total_ram_gb = 0.42
    caps.capabilities.available_ram_gb = 0.25
    monkeypatch.setattr(mod, "get_server_capabilities", lambda shared_data=None: caps)

    _flags, _env, severity, _note = scanner._nuclei_resource_tuning(150, "critical")
    assert severity == "critical"


def test_disable_update_check_always_present(monkeypatch):
    for total, avail in [(0.42, 0.25), (1.0, 0.6), (8.0, 6.0)]:
        flags, _env, _sev, _note = _tuning(monkeypatch, total, avail)
        assert "-disable-update-check" in flags
