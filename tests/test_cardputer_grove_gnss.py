"""A plain UART GPS on the CardputerZero's Grove port (an M5Stack GPS Unit, no
Cap) is found and handed the GNSS UART the same way the LoRa Cap's GNSS is, so
wardriving and the Meshtastic node get a fix.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import cardputer_caps as cc  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_cache():
    cc.reset_grove_gnss()
    yield
    cc.reset_grove_gnss()


@pytest.fixture
def env(monkeypatch):
    """A CardputerZero with no Cap and a login prompt on the UART, with the
    systemctl/getty/free calls faked and the getty state tracked."""
    state = {"getty": True, "systemctl": [], "freed": False, "cap": (cc.CAP_NONE, None)}
    monkeypatch.setattr(cc, "is_cardputer_zero", lambda config=None: True)
    monkeypatch.setattr(cc, "identify_cap", lambda force=False: state["cap"])
    monkeypatch.setattr(cc, "serial_getty_active", lambda *a, **k: state["getty"])
    monkeypatch.setattr(cc, "serial_console_on", lambda *a, **k: False)

    def fake_systemctl(*args, runner=None):
        state["systemctl"].append(args)
        if args[:1] == ("stop",):
            state["getty"] = False
        elif args[:1] == ("start",):
            state["getty"] = True
        return 0, ""

    monkeypatch.setattr(cc, "_systemctl", fake_systemctl)

    def fake_free(*a, **k):
        state["freed"] = True
        state["getty"] = False
        return True, "freed"

    monkeypatch.setattr(cc, "free_gnss_uart", fake_free)
    return state


def found(baud=9600):
    return lambda port: baud


def silent(port):
    return None


def _acts(state):
    return [a[:1] for a in state["systemctl"]]


# ── detect_grove_gnss ────────────────────────────────────────────────────────

def test_a_grove_gps_is_found_and_the_uart_handed_over(env):
    g = cc.detect_grove_gnss(config={}, free_uart=True, baud_probe=found(9600))
    assert g["present"] is True and g["baud"] == 9600 and g["freed"] == "freed"
    assert g["source"] == "grove" and g["port"] == cc.GNSS_PORT
    assert env["freed"] is True
    assert ("stop", cc._getty_unit()) in [a[:2] for a in env["systemctl"]]
    assert cc.grove_gnss_standby() == (cc.GNSS_PORT, 9600)


def test_without_a_gps_the_login_prompt_is_put_back(env):
    g = cc.detect_grove_gnss(config={}, free_uart=True, baud_probe=silent)
    assert g["present"] is False and env["freed"] is False
    assert ("stop",) in _acts(env) and ("start",) in _acts(env)
    assert cc.grove_gnss_standby() == (None, None)


def test_the_console_is_never_touched_when_free_uart_is_off(env):
    g = cc.detect_grove_gnss(config={}, free_uart=False, baud_probe=found())
    assert g["console_conflict"] is True and g["present"] is False
    assert env["systemctl"] == [] and env["freed"] is False


def test_a_free_port_is_probed_without_stopping_anything(env):
    env["getty"] = False
    g = cc.detect_grove_gnss(config={}, free_uart=True, baud_probe=found(38400))
    assert g["present"] is True and g["baud"] == 38400
    assert env["freed"] is False and env["systemctl"] == []


def test_a_lora_gnss_cap_keeps_the_uart(env):
    env["cap"] = (cc.CAP_LORA_GNSS, None)
    assert cc.detect_grove_gnss(config={}, baud_probe=found()) is None
    assert env["systemctl"] == []


def test_switched_off_by_config(env):
    assert cc.detect_grove_gnss(config={"cardputer_grove_gnss": "false"},
                                baud_probe=found()) is None


def test_not_a_cardputerzero_is_none(monkeypatch):
    monkeypatch.setattr(cc, "is_cardputer_zero", lambda config=None: False)
    assert cc.detect_grove_gnss(config={}) is None


def test_the_result_is_cached_until_reset(env):
    calls = []

    def probe(port):
        calls.append(port)
        return 9600

    cc.detect_grove_gnss(config={}, free_uart=True, baud_probe=probe)
    cc.detect_grove_gnss(config={}, free_uart=True, baud_probe=probe)
    assert len(calls) == 1                       # the second call used the cache
    cc.reset_grove_gnss()
    cc.detect_grove_gnss(config={}, free_uart=True, baud_probe=probe)
    assert len(calls) == 2


# ── detect() integration ─────────────────────────────────────────────────────

def test_detect_surfaces_the_grove_gps(env, monkeypatch):
    monkeypatch.setattr(cc, "power_on_cap", lambda: True)
    monkeypatch.setattr(cc, "grove5v_state", lambda *a, **k: True)
    monkeypatch.setattr(cc, "detect_grove_gnss",
                        lambda config=None, free_uart=True: {
                            "present": True, "port": cc.GNSS_PORT, "baud": 9600,
                            "sentences": 3, "console_conflict": False,
                            "freed": "freed", "source": "grove"})
    info = cc.detect(config={}, grove=True, free_uart=True, camera=False)
    assert info["cap"] == cc.CAP_NONE and info["grove_gnss"] is True
    assert info["gnss"]["source"] == "grove" and info["gnss"]["baud"] == 9600
    assert info["gnss"]["sentences"] == 3


def test_detect_without_grove_leaves_gnss_alone(env, monkeypatch):
    monkeypatch.setattr(cc, "power_on_cap", lambda: True)
    monkeypatch.setattr(cc, "grove5v_state", lambda *a, **k: True)
    monkeypatch.setattr(cc, "detect_grove_gnss",
                        lambda *a, **k: pytest.fail("grove probe ran without grove=True"))
    info = cc.detect(config={}, free_uart=True, camera=False)
    assert info.get("gnss") is None and "grove_gnss" not in info
