"""pineap_active.py — the ONE active PineAP test (it transmits).

Everything else in Ragnar's wireless IDS is strictly receive-only:
``wifi_defense.py`` "never transmits a frame", ``wifi_analyzer.py`` "never
transmits a probe request". This module is the deliberate, isolated exception —
which is exactly why it is a *separate* module, opt-in, and never runs on its
own. It performs the single strongest PineAP discriminator (the BSidesSLC 2020
method):

    Transmit a probe request for a **random, never-before-seen SSID**, then
    listen. A legitimate AP only answers probes for networks it actually serves,
    so it stays silent. A Wi-Fi Pineapple running PineAP with "Impersonate All
    Networks" / allow-associations **answers anyway** — that response is a
    near-definitive positive identification.

The detection it produces (``severity='answers_random_probe'``) is scored by
``pineap_watch`` as a confirm-floor tell.

What it transmits: a handful of ordinary probe-request frames — the same frames
every phone emits constantly — from a randomized locally-administered source MAC.
It does NOT deauthenticate, flood, associate, or send data. Still: only run it on
RF you are authorized to test.

Design note: the radio I/O (``_default_send`` / ``_default_sniff``) is injectable
so the decision core (``evaluate``) and the round loop (``run``) are unit-testable
without hardware. ``run`` never raises — it returns an ``{"error": ...}`` dict
when scapy or a monitor interface is unavailable.
"""

import random
import string
import time

# A random SSID this long, from this alphabet, has ~62^12 possibilities — no real
# network is called this, so any response to it is an impersonation.
_SSID_LEN = 12
_SSIDS_PER_ROUND = 4


def random_ssids(n=_SSIDS_PER_ROUND, length=_SSID_LEN, _rng=None):
    """Return ``n`` random SSIDs no legitimate network would advertise."""
    rng = _rng or random.SystemRandom()
    alpha = string.ascii_letters + string.digits
    return ["".join(rng.choice(alpha) for _ in range(length)) for _ in range(n)]


def random_la_mac(_rng=None):
    """A random locally-administered, unicast MAC (0x02 in the first octet) — so
    the probe isn't sourced from, or spoofing, any real burned-in address."""
    rng = _rng or random.SystemRandom()
    octets = [0x02] + [rng.randint(0, 255) for _ in range(5)]
    return ":".join("%02x" % o for o in octets)


def evaluate(sent, responses):
    """Pure decision core: which random SSIDs got answered, and by whom.

    Args:
        sent: iterable of the (random) SSIDs we probed for.
        responses: iterable of ``(ssid, bssid)`` pairs actually observed in
            probe-responses / beacons during the listen window.

    Returns a list of ``wifi_defense``-shaped detection dicts, one per random
    SSID that was answered — each an ``answers_random_probe`` tell naming the
    responder BSSID(s). Empty when nothing answered (the expected result in clean
    RF).
    """
    sent_set = {s for s in sent if s}
    by_ssid = {}
    for ssid, bssid in responses or []:
        if ssid in sent_set:
            by_ssid.setdefault(ssid, set()).add(bssid)
    detections = []
    for ssid in sorted(by_ssid):
        bssids = sorted(b for b in by_ssid[ssid] if b)
        detections.append({
            "type": "rogue_ap",
            "severity": "answers_random_probe",
            "ssid": ssid,
            "bssids": bssids,
            "bssid": bssids[0] if bssids else None,
            "detail": ("responded to a probe for random SSID '%s' (never "
                       "advertised) from %s — Karma/PineAP impersonation"
                       % (ssid, ", ".join(bssids) if bssids else "an unknown BSSID")),
        })
    return detections


# --------------------------------------------------------------------------
# Radio I/O shell (scapy) — injectable so ``run`` is testable without hardware.
# --------------------------------------------------------------------------

def _default_send(mon_iface, ssid, src_mac, count=2):
    """Send ``count`` probe-request frames for ``ssid`` from ``src_mac``."""
    from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt, sendp
    ssid_bytes = ssid.encode("utf-8", "replace")
    pkt = (RadioTap()
           / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                   addr2=src_mac, addr3="ff:ff:ff:ff:ff:ff")
           / Dot11ProbeReq()
           / Dot11Elt(ID=0, info=ssid_bytes)          # SSID
           / Dot11Elt(ID=1, info=b"\x02\x04\x0b\x16"))  # supported rates
    sendp(pkt, iface=mon_iface, count=count, inter=0.05, verbose=0)


def _default_sniff(mon_iface, seconds):
    """Listen ``seconds`` and return ``(ssid, bssid)`` for every probe-response
    and beacon heard."""
    from scapy.all import sniff, Dot11, Dot11Elt, Dot11ProbeResp, Dot11Beacon
    out = []

    def _cb(pkt):
        if not pkt.haslayer(Dot11):
            return
        if not (pkt.haslayer(Dot11ProbeResp) or pkt.haslayer(Dot11Beacon)):
            return
        bssid = getattr(pkt.getlayer(Dot11), "addr2", None)
        el = pkt.getlayer(Dot11Elt)
        while el is not None and isinstance(el, Dot11Elt):
            if el.ID == 0:                      # SSID element
                try:
                    ssid = el.info.decode("utf-8", "replace")
                except Exception:
                    ssid = ""
                out.append((ssid, bssid))
                break
            el = el.payload.getlayer(Dot11Elt)

    try:
        sniff(iface=mon_iface, prn=_cb, timeout=seconds, store=False,
              filter="type mgt", monitor=True)
    except Exception:
        sniff(iface=mon_iface, prn=_cb, timeout=seconds, store=False)
    return out


def run(interface, rounds=3, listen_seconds=2, channels=None, auto_enable=True,
        _resolve=None, _tune=None, _send=None, _sniff=None, _rng=None):
    """Run the active probe-response test and return a result dict.

    For each round: pick fresh random SSIDs, (optionally) tune each channel,
    transmit a probe for each SSID, then listen for responses. Any response to a
    random SSID is an impersonation.

    Returns ``{ok, detections, answered, sent, rounds, channels, monitor,
    listen_seconds}`` — or ``{"error": ...}`` if scapy/monitor is unavailable.
    ``detections`` are ``wifi_defense``-shaped and can be appended straight to a
    scan's ``detections`` before ``pineap_watch.assess``.
    """
    # Late-bound deps so this module imports with no scapy present and stays
    # unit-testable with fakes.
    if _resolve is None or _tune is None:
        import wifi_defense as _wd
        _resolve = _resolve or _wd._resolve_monitor
        _tune = _tune or _wd._set_channel
    _send = _send or _default_send
    _sniff = _sniff or _default_sniff

    mon = _resolve(interface, auto_enable=auto_enable)
    if isinstance(mon, dict):                    # {"error": ...}
        return mon
    if not mon:
        return {"error": "no monitor interface"}

    rounds = max(1, min(10, int(rounds)))
    listen_seconds = max(1, min(10, int(listen_seconds)))
    src_mac = random_la_mac(_rng)
    all_sent = set()
    responses = []

    try:
        for _ in range(rounds):
            for chan in (channels or [None]):
                if chan is not None:
                    try:
                        _tune(mon, chan)
                    except Exception:
                        pass
                ssids = random_ssids(_rng=_rng)
                for ssid in ssids:
                    all_sent.add(ssid)
                    try:
                        _send(mon, ssid, src_mac)
                    except Exception as exc:
                        return {"error": "probe transmit failed: %s" % exc,
                                "hint": "needs scapy + a monitor-mode adapter; "
                                        "the Pi's onboard radio cannot transmit "
                                        "802.11 mgmt frames"}
                    time.sleep(0.05)
                responses.extend(_sniff(mon, listen_seconds) or [])
    except Exception as exc:
        return {"error": "active probe test failed: %s" % exc}

    detections = evaluate(all_sent, responses)
    return {
        "ok": True,
        "detections": detections,
        "answered": len(detections),
        "sent": sorted(all_sent),
        "rounds": rounds,
        "channels": channels,
        "monitor": mon,
        "listen_seconds": listen_seconds,
        "timestamp": int(time.time()),
    }


# --------------------------------------------------------------------------
# Self-test (pure — no radio)
# --------------------------------------------------------------------------

def selftest():
    results = []

    def check(name, cond, detail=""):
        results.append({"name": name, "pass": bool(cond), "detail": detail})

    import json

    # random_ssids / random_la_mac shape.
    ss = random_ssids(4, 12)
    check("random_ssids returns n distinct SSIDs of the right length",
          len(ss) == 4 and len(set(ss)) == 4 and all(len(s) == 12 for s in ss))
    mac = random_la_mac()
    first = int(mac.split(":")[0], 16)
    check("random_la_mac is locally-administered + unicast",
          (first & 0x02) and not (first & 0x01), mac)

    # evaluate(): a response to a sent random SSID is a hit.
    sent = ["Zx9Qk2Vw7Lp1", "Ab12Cd34Ef56"]
    dets = evaluate(sent, [("Zx9Qk2Vw7Lp1", "00:13:37:00:00:01"),
                           ("MyHomeWiFi", "aa:bb:cc:00:00:01")])
    check("evaluate flags a random SSID that was answered",
          len(dets) == 1 and dets[0]["severity"] == "answers_random_probe"
          and dets[0]["ssid"] == "Zx9Qk2Vw7Lp1"
          and dets[0]["bssid"] == "00:13:37:00:00:01", json.dumps(dets))
    # A real network answering its OWN beacon/probe is not a hit (not in sent).
    check("evaluate ignores responses for SSIDs we did not probe",
          evaluate(sent, [("Starbucks", "aa:bb:cc:00:00:02")]) == [])
    # Clean air: nothing answers our random probes.
    check("evaluate returns nothing when no random SSID is answered",
          evaluate(sent, []) == [])
    # Two BSSIDs answering the same random SSID are both named.
    multi = evaluate(["Rnd1"], [("Rnd1", "02:00:00:00:00:01"),
                               ("Rnd1", "02:00:00:00:00:02")])
    check("evaluate collects every responder BSSID",
          multi and multi[0]["bssids"] == ["02:00:00:00:00:01", "02:00:00:00:00:02"],
          json.dumps(multi))

    # run() with injected fakes — a Pineapple that answers everything => a hit.
    def fake_resolve(iface, auto_enable=True):
        return "ragmon0"
    sent_log = []
    def fake_send(mon, ssid, src_mac, count=2):
        sent_log.append(ssid)
    def fake_sniff_answers_all(mon, seconds):
        # Impersonate-all Pineapple: echo back every SSID just probed.
        return [(s, "00:c0:ca:00:00:01") for s in sent_log[-_SSIDS_PER_ROUND:]]
    res = run("wlan1", rounds=1, listen_seconds=1, _resolve=fake_resolve,
              _tune=lambda m, c: None, _send=fake_send,
              _sniff=fake_sniff_answers_all)
    check("run(): a Pineapple answering all probes => detections",
          res.get("ok") and res.get("answered", 0) >= 1
          and res["detections"][0]["severity"] == "answers_random_probe",
          json.dumps({"answered": res.get("answered"), "err": res.get("error")}))

    # run() in clean RF (nothing answers) => no detections, still ok.
    res2 = run("wlan1", rounds=2, listen_seconds=1, _resolve=fake_resolve,
               _tune=lambda m, c: None, _send=lambda *a, **k: None,
               _sniff=lambda m, s: [])
    check("run(): clean RF => ok, zero detections",
          res2.get("ok") and res2.get("answered") == 0, json.dumps(res2.get("answered")))

    # run() surfaces a monitor error instead of raising.
    res3 = run("wlan1", _resolve=lambda i, auto_enable=True: {"error": "no monitor"})
    check("run(): monitor error is returned, not raised",
          res3.get("error") == "no monitor", json.dumps(res3))

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


if __name__ == "__main__":
    r = selftest()
    print("PASS" if r["pass"] else "FAIL", r["passed"], "/", r["total"])
    for x in r["results"]:
        if not x["pass"]:
            print("  FAIL:", x["name"], "::", x.get("detail", ""))
