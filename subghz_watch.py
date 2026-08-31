#!/usr/bin/env python3
"""SubGHz (300-439 MHz) attack sensor for the HaleHound / ESP32 correlation.

An ESP32 attack multitool (HaleHound-CYD, Flipper-style CC1101 boards) doesn't
just do Wi-Fi/BLE — it also replays and brute-forces SubGHz remotes (garage/gate
openers, car fobs, alarm sensors). Ragnar already carries an RTL-SDR, which
covers ~24 MHz-1.7 GHz, so 300-439 MHz is in range: this module demodulates the
SubGHz ISM bands via ``rtl_433`` and flags the two shapes an attack tool makes:

  * REPLAY  — one captured code (same model+id+payload) re-sent many times in a
              tight window, far above any real remote's cadence.
  * BRUTE   — a burst of many DISTINCT codes from one protocol (a gate/garage
              brute, or a de Bruijn rolling-code sweep).

``rtl_433`` does the heavy DSP; this is the thin capture + heuristics layer.
Everything except ``scan()`` (which shells out) is pure, so ``selftest()`` drives
it with captured JSON.

HONESTY: this is HARDWARE-UNVALIDATED against a real CC1101/HaleHound emitter.
Thresholds are deliberately conservative so ordinary 433 MHz telemetry (weather
stations, TPMS, doorbells) — which legitimately repeats a few frames per burst —
does not read as an attack. The RTL-SDR is shared with ADS-B/ACARS/VDL2/the
waterfall, so ``scan()`` refuses to grab the radio when another SDR job is live.
"""

import json
import re
import shutil
import subprocess

try:
    import rtl_sdr as _rtl                       # non-intrusive USB presence probe
except Exception:                                # pragma: no cover
    _rtl = None

# --------------------------------------------------------------------------
# Tunables (per scan window)
# --------------------------------------------------------------------------
_DEFAULT_FREQS = ["433.92M", "315M"]   # the two busiest SubGHz remote bands
_DEFAULT_DURATION = 20                 # seconds of capture
_MAX_DURATION = 120

# Same identical payload repeated this many times in one window = replay. A
# redundant remote/sensor sends a frame ~2-4x per press; 8 clears that floor.
_REPLAY_MIN = 8
# Distinct codes from ONE protocol in one window = brute / rolling-code sweep.
_BRUTE_MIN = 16

_RTL_433 = shutil.which("rtl_433")

# rtl_433 JSON fields that are per-reception noise, not part of the code itself.
_NOISE_FIELDS = {"time", "rssi", "snr", "noise", "freq", "freq1", "freq2",
                 "mod", "mic", "count", "num_rows", "mfg"}


# --------------------------------------------------------------------------
# Pure parsing + analysis
# --------------------------------------------------------------------------

def parse_rtl433_lines(text):
    """Parse newline-delimited ``rtl_433 -F json`` output into event dicts.

    Tolerates non-JSON status lines (rtl_433 prints a banner + tuning noise on
    stderr, but stray lines can appear on stdout too). Pure."""
    events = []
    for raw in (text or "").splitlines():
        raw = raw.strip()
        if not raw or raw[0] != "{":
            continue
        try:
            obj = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict) and obj.get("model"):
            events.append(obj)
    return events


def _payload_key(ev):
    """A stable identity for a decoded frame's *content* (model + id + payload).

    Strips per-reception noise (RSSI/SNR/time) so two receptions of the SAME
    transmission collapse to one key — that's what makes a replay countable."""
    model = str(ev.get("model") or "")
    ident = str(ev.get("id", ev.get("address", "")))
    payload = {k: ev[k] for k in ev
               if k not in _NOISE_FIELDS and k not in ("model", "id", "address")}
    # A compact, order-independent digest of the remaining fields.
    body = json.dumps(payload, sort_keys=True, default=str)
    return (model, ident, body)


def analyze(events, replay_min=None, brute_min=None):
    """Flag SubGHz replay / brute bursts in one capture window (pure).

    ``events`` is a list of ``rtl_433`` JSON dicts. The scan window IS the
    grouping window (capture is short and bounded), so we count within it rather
    than tracking per-event time. Returns a list of detection dicts
    ``{type, severity, ...}`` shaped for ``halehound_watch.score``."""
    replay_min = int(replay_min or _REPLAY_MIN)
    brute_min = int(brute_min or _BRUTE_MIN)

    payload_counts = {}          # exact-frame repeats  -> replay
    model_codes = {}             # distinct codes / model -> brute
    for ev in events or []:
        key = _payload_key(ev)
        payload_counts[key] = payload_counts.get(key, 0) + 1
        model = key[0]
        model_codes.setdefault(model, set()).add(key)

    detections = []

    # REPLAY: the single most-repeated identical frame, if it clears the floor.
    if payload_counts:
        (model, ident, _body), n = max(payload_counts.items(), key=lambda kv: kv[1])
        if n >= replay_min:
            detections.append({
                "type": "subghz_replay", "severity": "flood",
                "model": model, "id": ident, "count": n,
                "detail": f"{model} code {ident} re-sent {n}x in one window "
                          "— SubGHz replay (captured remote played back)",
            })

    # BRUTE: a protocol sprayed with many distinct codes.
    for model, codes in model_codes.items():
        if len(codes) >= brute_min:
            detections.append({
                "type": "subghz_brute", "severity": "flood",
                "model": model, "count": len(codes),
                "detail": f"{len(codes)} distinct {model} codes in one window "
                          "— SubGHz brute-force / rolling-code sweep",
            })

    # Otherwise, note that SubGHz activity WAS heard (weak corroboration only).
    if not detections and events:
        models = sorted({str(e.get("model")) for e in events if e.get("model")})
        detections.append({
            "type": "subghz_active", "severity": "seen",
            "count": len(events), "models": models[:8],
            "detail": f"{len(events)} SubGHz frames from {len(models)} protocol(s) "
                      "— normal ISM telemetry, no attack pattern",
        })
    return detections


# --------------------------------------------------------------------------
# Capture (shells out to rtl_433) — the only impure part
# --------------------------------------------------------------------------

def _sdr_present():
    """True if an RTL-SDR is on the USB bus (non-intrusive lsusb probe)."""
    if _rtl is None:
        return False
    try:
        usb_id, _desc = _rtl.probe_usb()
        return bool(usb_id)
    except Exception:
        return False


def _sdr_busy():
    """True if another SDR consumer (ADS-B/ACARS/VDL2/waterfall) holds the radio.

    We must never yank the RTL-SDR out from under a live job, so a quick process
    scan gates the capture. Best-effort; never raises."""
    try:
        out = subprocess.run(["ps", "-eo", "cmd"], capture_output=True,
                             text=True, timeout=4).stdout or ""
    except Exception:
        return False
    busy_re = re.compile(r"\b(dump1090|dump978|acarsdec|dumpvdl2|rtl_fm|rtl_tcp|"
                         r"rtl_power|rtl_adsb|sdr_spectrum)\b|rtl_sdr\b")
    for ln in out.splitlines():
        if "rtl_433" in ln:          # our own probe / another subghz scan — skip
            continue
        if busy_re.search(ln):
            return True
    return False


def detect():
    """Report SubGHz-capture readiness: {available, reason, sdr, tool}."""
    sdr = _sdr_present()
    tool = _RTL_433 is not None
    if not tool:
        return {"available": False, "sdr": sdr, "tool": False,
                "reason": "rtl_433 not installed"}
    if not sdr:
        return {"available": False, "sdr": False, "tool": True,
                "reason": "no RTL-SDR on the USB bus"}
    return {"available": True, "sdr": True, "tool": True, "reason": "ready"}


def scan(freqs=None, duration=None, replay_min=None, brute_min=None):
    """Capture a SubGHz window off the RTL-SDR and analyse it.

    Returns ``{scanned, detections, events, freqs, duration, reason}``. When the
    radio is absent/busy or the tool is missing, ``scanned`` is False with a
    human ``reason`` (so the blind-spot list can say WHY)."""
    try:
        duration = max(6, min(_MAX_DURATION, int(duration or _DEFAULT_DURATION)))
    except (TypeError, ValueError):
        duration = _DEFAULT_DURATION
    freqs = list(freqs or _DEFAULT_FREQS)

    rdy = detect()
    if not rdy["available"]:
        return {"scanned": False, "detections": [], "events": 0,
                "freqs": freqs, "duration": duration, "reason": rdy["reason"]}
    if _sdr_busy():
        return {"scanned": False, "detections": [], "events": 0,
                "freqs": freqs, "duration": duration,
                "reason": "RTL-SDR busy with another job (ADS-B/ACARS/waterfall)"}

    cmd = [_RTL_433, "-F", "json", "-M", "time:iso"]
    for f in freqs:
        cmd += ["-f", f]
    if len(freqs) > 1:
        cmd += ["-H", str(max(3, duration // len(freqs)))]   # hop dwell
    # rtl_433 has no clean "stop after N seconds", so we time it out ourselves.
    cmd += ["-T", str(duration)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=duration + 12)
        out = proc.stdout or ""
        # rtl_433 exits non-zero when it can't open a busy/absent device.
        if not out and proc.returncode not in (0, None):
            err = (proc.stderr or "").strip().splitlines()[-1:] or [""]
            return {"scanned": False, "detections": [], "events": 0,
                    "freqs": freqs, "duration": duration,
                    "reason": f"rtl_433 could not capture: {err[0][:120]}"}
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"")
        out = out.decode("utf-8", "replace") if isinstance(out, bytes) else out
    except Exception as exc:
        return {"scanned": False, "detections": [], "events": 0,
                "freqs": freqs, "duration": duration,
                "reason": f"rtl_433 launch failed: {exc}"}

    events = parse_rtl433_lines(out)
    dets = analyze(events, replay_min=replay_min, brute_min=brute_min)
    return {"scanned": True, "detections": dets, "events": len(events),
            "freqs": freqs, "duration": duration, "reason": "ok"}


# --------------------------------------------------------------------------
# Selftest — synthetic rtl_433 JSON (no radio needed)
# --------------------------------------------------------------------------

_SAMPLE_JSON = "\n".join([
    # a benign weather station repeats an identical frame a few times (redundancy)
    '{"time":"2024-01-01T00:00:01","model":"Acurite-Tower","id":1234,'
    '"temperature_C":21.1,"humidity":40,"rssi":-3.1}',
    '{"time":"2024-01-01T00:00:02","model":"Acurite-Tower","id":1234,'
    '"temperature_C":21.1,"humidity":40,"rssi":-3.4}',
    '{"time":"2024-01-01T00:00:03","model":"Acurite-Tower","id":1234,'
    '"temperature_C":21.1,"humidity":40,"rssi":-3.0}',
    "rtl_433 version 25.02 tuning...",           # stray non-JSON status line
])


def _replay_json(n=10):
    return "\n".join(
        '{"time":"2024-01-01T00:00:%02d","model":"Nexa-Security","id":42,'
        '"cmd":"unlock","code":"a1b2c3","rssi":-5.0}' % i for i in range(n))


def _brute_json(n=20):
    return "\n".join(
        '{"time":"2024-01-01T00:00:%02d","model":"Gate-Remote","id":7,'
        '"code":"%06x","rssi":-6.0}' % (i, 0x100000 + i * 7) for i in range(n))


def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    # --- parsing ---
    evs = parse_rtl433_lines(_SAMPLE_JSON)
    check("parse: 3 JSON frames, stray status line skipped", len(evs) == 3,
          str(len(evs)))

    # --- benign telemetry is NOT an attack ---
    dets = analyze(evs)
    check("benign repeats (3x) => no replay flag",
          not any(d["type"] == "subghz_replay" for d in dets), json.dumps(dets))
    check("benign telemetry => 'subghz_active' note only",
          len(dets) == 1 and dets[0]["type"] == "subghz_active", json.dumps(dets))

    # --- replay ---
    rdets = analyze(parse_rtl433_lines(_replay_json(10)))
    rp = next((d for d in rdets if d["type"] == "subghz_replay"), None)
    check("replay: 10x identical code => subghz_replay",
          rp is not None and rp["count"] == 10, json.dumps(rdets))
    check("replay: just under threshold (7x) => no flag",
          not any(d["type"] == "subghz_replay"
                  for d in analyze(parse_rtl433_lines(_replay_json(7)))))

    # --- brute ---
    bdets = analyze(parse_rtl433_lines(_brute_json(20)))
    bp = next((d for d in bdets if d["type"] == "subghz_brute"), None)
    check("brute: 20 distinct codes => subghz_brute",
          bp is not None and bp["count"] == 20, json.dumps(bdets))
    check("brute: 12 distinct codes (under floor) => no flag",
          not any(d["type"] == "subghz_brute"
                  for d in analyze(parse_rtl433_lines(_brute_json(12)))))

    # --- empty ---
    check("no events => no detections", analyze([]) == [])

    # --- payload key ignores per-reception noise ---
    a = _payload_key({"model": "X", "id": 1, "code": "aa", "rssi": -1})
    b = _payload_key({"model": "X", "id": 1, "code": "aa", "rssi": -9, "snr": 3})
    check("payload key ignores RSSI/SNR (same frame => same key)", a == b)

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


if __name__ == "__main__":
    import sys
    if "--scan" in sys.argv:
        print(json.dumps(scan(), indent=2))
    else:
        st = selftest()
        print(f"subghz_watch selftest: {st['passed']}/{st['total']}")
        for r in st["results"]:
            if not r["pass"]:
                print("  FAIL:", r["name"], "::", r["detail"])
        sys.exit(0 if st["pass"] else 1)
