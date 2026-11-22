#!/usr/bin/env python3
"""Headless 24/7 background watcher for the ESP32 attack-tool correlation.

The WiFi Defense panel's "Check for ESP32 attack tool" button is a one-shot
spot-check. This runs the *same* fusion continuously with no browser open: a
daemon thread periodically captures a Wi-Fi window, refreshes a cached BLE
snapshot on a slower cadence, scores it through ``halehound_watch.assess`` and
emits into the Watchtower feed / incident engine (and thus Pushover) whenever
the verdict crosses the alert threshold.

This module is only the **lifecycle** — a persistent, crash-safe interval runner.
The app-specific work (capture + BLE + assess + emit) is injected as a single
``run_once`` callable by ``network_diagnostics``, so the loop stays testable with
a fake and carries no import of the heavy subsystems. "If enabled" survives a
restart: the enabled flag + config are persisted, and ``resume_if_enabled`` is
called at app startup.
"""

import json
import os
import threading
import time

_STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "data", "halehound_daemon.json")

# Defaults (seconds). The capture itself dominates the cycle; ``interval`` is the
# gap between cycles, ``ble_interval`` how often the cached BLE snapshot is
# refreshed (BLE briefly claims the controller, so it runs far less often than
# the Wi-Fi capture). SubGHz is never auto (it holds the shared SDR).
# Defaults are deliberately SLOW — this must be gentle on a Pi Zero 2 W. A short
# capture then a long idle gap keeps CPU and the radio mostly free; BLE refreshes
# rarely. Tune faster per-request if running on a beefier board.
_DEFAULTS = {
    "interface": None,      # monitor iface; required to actually capture
    "seconds": 12,          # per-window Wi-Fi capture length (short)
    "channel": None,        # None => hop
    "interval": 90,         # long idle gap between cycles (~every ~1.5-2 min)
    "ble_interval": 300,    # BLE snapshot refresh only every 5 min
    "subghz": False,        # opt-in only; the loop never grabs the SDR by default
}

_lock = threading.RLock()
_thread = None
_stop = None
_run_once = None
_state = {
    "enabled": False, "running": False, "cycles": 0, "errors": 0,
    "started_at": None, "last_cycle_at": None, "last_error": None,
    "last_verdict": None, "config": dict(_DEFAULTS),
}


# --------------------------------------------------------------------------
# Persistence (enabled flag + config survive a restart)
# --------------------------------------------------------------------------

def _save_persist():
    try:
        os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
        with open(_STATE_FILE, "w") as fh:
            json.dump({"enabled": _state["enabled"],
                       "config": _state["config"]}, fh)
    except Exception:
        pass                                     # persistence is best-effort


def _load_persist():
    try:
        with open(_STATE_FILE) as fh:
            d = json.load(fh)
        if isinstance(d, dict):
            return bool(d.get("enabled")), {**_DEFAULTS, **(d.get("config") or {})}
    except (OSError, ValueError):
        pass
    return False, dict(_DEFAULTS)


def _merge_config(config):
    cfg = dict(_DEFAULTS)
    for k, v in (config or {}).items():
        if k in _DEFAULTS and v is not None:
            cfg[k] = v
    # Clamp to sane bounds so a bad request can't wedge or hammer the radio.
    cfg["seconds"] = max(5, min(120, int(cfg["seconds"])))
    cfg["interval"] = max(0, min(3600, int(cfg["interval"])))
    cfg["ble_interval"] = max(10, min(3600, int(cfg["ble_interval"])))
    cfg["subghz"] = bool(cfg["subghz"])
    return cfg


# --------------------------------------------------------------------------
# The loop
# --------------------------------------------------------------------------

def _loop(run_once, stop_event, cfg):
    backoff = 0
    while not stop_event.is_set():
        started = time.time()
        try:
            verdict = run_once(cfg)
            with _lock:
                _state["cycles"] += 1
                _state["last_cycle_at"] = time.time()
                _state["last_error"] = None
                if isinstance(verdict, dict):
                    _state["last_verdict"] = {
                        "verdict": verdict.get("verdict"),
                        "score": verdict.get("score"),
                        "domains": verdict.get("domains"),
                        "ts": _state["last_cycle_at"],
                    }
            backoff = 0
        except Exception as exc:                 # never let the thread die
            with _lock:
                _state["errors"] += 1
                _state["last_error"] = str(exc)[:300]
                _state["last_cycle_at"] = time.time()
            backoff = min(120, (backoff or cfg["interval"] or 10) * 2)
        # Sleep the cycle gap (or the backoff after an error), but wake promptly
        # on stop. Guarantee at least a small yield so a 0-interval can't spin.
        gap = backoff if backoff else cfg["interval"]
        stop_event.wait(max(1, gap))
    with _lock:
        _state["running"] = False


# --------------------------------------------------------------------------
# Public control
# --------------------------------------------------------------------------

def start(run_once, config=None, persist=True):
    """Start (or restart) the watcher with ``run_once(cfg)``. Idempotent."""
    global _thread, _stop, _run_once
    with _lock:
        cfg = _merge_config(config if config is not None else _state["config"])
        _run_once = run_once
        # Restart cleanly if already running (e.g. a config change).
        if _thread is not None and _thread.is_alive():
            _stop.set()
        _stop = threading.Event()
        _state.update({"enabled": True, "running": True, "config": cfg,
                       "started_at": time.time(), "last_error": None})
        if persist:
            _save_persist()
        _thread = threading.Thread(target=_loop, args=(run_once, _stop, cfg),
                                   name="halehound-watch", daemon=True)
        _thread.start()
    return status()


def stop(persist=True):
    """Signal the watcher to stop. Non-blocking (thread is a daemon)."""
    global _stop
    with _lock:
        if _stop is not None:
            _stop.set()
        _state["enabled"] = False
        _state["running"] = False
        if persist:
            _save_persist()
    return status()


def status():
    with _lock:
        st = dict(_state)
        st["config"] = dict(_state["config"])
        st["alive"] = bool(_thread is not None and _thread.is_alive())
    return st


def resume_if_enabled(run_once):
    """At app startup: relaunch the watcher iff it was left enabled."""
    enabled, cfg = _load_persist()
    with _lock:
        _state["config"] = cfg
    if enabled:
        return start(run_once, cfg, persist=False)
    return status()


# --------------------------------------------------------------------------
# Self-test (drives the loop with a fake run_once — no radio)
# --------------------------------------------------------------------------

def selftest():
    global _STATE_FILE
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    import tempfile
    orig_file = _STATE_FILE
    _STATE_FILE = os.path.join(tempfile.mkdtemp(), "hh_daemon.json")
    try:
        # A fake run_once that counts calls and returns a verdict.
        calls = {"n": 0}

        def fake(cfg):
            calls["n"] += 1
            return {"verdict": "trace", "score": 12, "domains": ["wifi"]}

        start(fake, {"interface": "mon0", "interval": 1, "seconds": 5},
              persist=True)
        time.sleep(0.3)
        st = status()
        check("start => running + enabled", st["running"] and st["enabled"], str(st))
        check("config clamped/merged (seconds>=5)", st["config"]["seconds"] == 5)
        check("persist file written with enabled=True", _load_persist()[0] is True)
        # Give the loop a moment to turn over at least once.
        for _ in range(20):
            if status()["cycles"] >= 1:
                break
            time.sleep(0.1)
        check("loop executed run_once at least once", status()["cycles"] >= 1,
              str(status()["cycles"]))
        check("last_verdict captured", (status()["last_verdict"] or {}).get("score") == 12)

        stop()
        time.sleep(0.2)
        check("stop => not enabled", status()["enabled"] is False)
        check("persist file now enabled=False", _load_persist()[0] is False)

        # An exception in run_once must NOT kill the thread; it records an error.
        def boom(cfg):
            raise RuntimeError("capture blew up")

        start(boom, {"interface": "mon0", "interval": 1}, persist=False)
        for _ in range(20):
            if status()["errors"] >= 1:
                break
            time.sleep(0.1)
        check("run_once exception is caught + counted, thread survives",
              status()["errors"] >= 1 and status()["alive"], str(status()["last_error"]))
        stop(persist=False)

        # resume_if_enabled honours a persisted enabled flag.
        _save_state_enabled(True, {"interface": "mon0", "interval": 1})
        resume_if_enabled(fake)
        time.sleep(0.2)
        check("resume_if_enabled restarts when persisted enabled",
              status()["running"], str(status()))
        stop(persist=False)

        _save_state_enabled(False, {})
        resume_if_enabled(fake)
        check("resume_if_enabled stays off when persisted disabled",
              not status()["running"])
    finally:
        try:
            if _stop is not None:
                _stop.set()
        except Exception:
            pass
        _STATE_FILE = orig_file

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


def _save_state_enabled(enabled, config):
    """Test helper: write a persist file directly."""
    try:
        os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
        with open(_STATE_FILE, "w") as fh:
            json.dump({"enabled": bool(enabled), "config": config}, fh)
    except Exception:
        pass


if __name__ == "__main__":
    import sys
    r = selftest()
    print("PASS" if r["pass"] else "FAIL", r["passed"], "/", r["total"])
    for x in r["results"]:
        if not x["pass"]:
            print("  FAIL:", x["name"], "::", x.get("detail", ""))
    sys.exit(0 if r["pass"] else 1)
