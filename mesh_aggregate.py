#!/usr/bin/env python3
"""
mesh_aggregate.py — fuse SDR data from several Ragnar units into one deduped view.

Several Ragnar units in a Ragnar Mesh (Tailscale) each receive RF locally. Point
them at one "master" and it pulls every unit's local catch over the tailnet and
merges it into a single, **de-duplicated** picture — wider coverage, no doubles.

Dedup is natural because every entity has a stable unique key:

  * ADS-B aircraft  -> ICAO hex        (adsb.aircraft)
  * APRS station    -> callsign-SSID   (aprs.stations)
  * Meshtastic node -> node id (!hex)  (meshtastic_node.nodes)
  * ISM device      -> model + id      (rtl_sdr.ism_devices)

For each key the master keeps the single best report (positioned + freshest /
strongest signal) and records **who heard it** (`heard_by`), so two units seeing
the same aircraft become one row that says "heard by: gothenburg, stockholm".

Pull model: no changes on the other units. The master GETs each peer's
``/api/mesh/sdr/<kind>`` snapshot (peer-readable over the tailnet, like the scan
delegation) and merges it with its own. The merge core is pure and unit-tested;
the network fan-out is best-effort.

CLI
---
    python3 mesh_aggregate.py selftest
"""

import os
import socket
import sys
import time

KINDS = ("adsb", "aprs", "mesh", "ism")

# Natural unique key per kind — dedup is "merge by this".
_KEY = {
    "adsb": lambda r: r.get("icao"),
    "aprs": lambda r: (r.get("call") or r.get("source")),
    "mesh": lambda r: r.get("id"),
    "ism":  lambda r: (None if r.get("model") is None else
                       "%s/%s" % (r.get("model"), "" if r.get("id") is None else r.get("id"))),
}

# Which of two reports of the same entity to keep (higher score wins): prefer a
# positioned report, then the freshest / strongest.
def _score_adsb(r):
    return (1e12 if r.get("lat") is not None else 0) - float(r.get("seen") or 999)
def _score_aprs(r):
    return float(r.get("ts") or 0)
def _score_mesh(r):
    return (1e12 if r.get("lat") is not None else 0) + float(r.get("last_heard") or 0)
def _score_ism(r):
    return float(r.get("last_ts") or r.get("ts") or 0) * 1.0 + float(r.get("rssi") or -999) / 1e6
_SCORE = {"adsb": _score_adsb, "aprs": _score_aprs, "mesh": _score_mesh, "ism": _score_ism}


# --------------------------------------------------------------------------
# Local snapshot — this unit's own catch for one kind
# --------------------------------------------------------------------------

def _unit_name():
    """Short name of this unit (mesh short_name, else hostname)."""
    try:
        import mesh_manager
        st = mesh_manager.status()
        self_node = st.get("self") or st.get("self_node") or {}
        if self_node.get("short_name"):
            return self_node["short_name"]
    except Exception:
        pass
    return socket.gethostname().split(".")[0]


def _local_list(kind):
    """This unit's raw records for a kind (empty on any error / no hardware)."""
    try:
        if kind == "adsb":
            import adsb
            return (adsb.aircraft() or {}).get("aircraft", [])
        if kind == "aprs":
            import aprs
            return (aprs.stations() or {}).get("stations", [])
        if kind == "mesh":
            import meshtastic_node
            return (meshtastic_node.nodes() or {}).get("nodes", [])
        if kind == "ism":
            import rtl_sdr
            return (rtl_sdr.ism_devices() or {}).get("devices", [])
    except Exception:
        return []
    return []


def local_snapshot(kind, unit=None):
    """This unit's records for a kind, each tagged with its dedup key + unit."""
    if kind not in KINDS:
        return {"unit": unit or _unit_name(), "kind": kind, "records": []}
    unit = unit or _unit_name()
    keyfn = _KEY[kind]
    out = []
    for r in _local_list(kind):
        try:
            k = keyfn(r)
        except Exception:
            k = None
        if k in (None, "", "None/"):
            continue
        rr = dict(r)
        rr["key"] = k
        out.append(rr)
    return {"unit": unit, "kind": kind, "records": out}


# --------------------------------------------------------------------------
# Merge / dedup — pure, drives the selftest
# --------------------------------------------------------------------------

def merge(kind, snapshots):
    """Merge many {unit, records} snapshots into one deduped list.

    Returns {kind, units, records, reports, deduped}: one record per unique key,
    each carrying heard_by (units that reported it) + units count. ``reports`` is
    the total pre-merge count, ``deduped`` how many duplicates were collapsed.
    """
    score = _SCORE.get(kind, lambda r: 0)
    best = {}          # key -> (score, record, unit)
    heard = {}         # key -> set(units)
    reports = 0
    units = set()
    for snap in (snapshots or []):
        unit = snap.get("unit") or "?"
        units.add(unit)
        for r in (snap.get("records") or []):
            k = r.get("key")
            if k in (None, ""):
                continue
            reports += 1
            heard.setdefault(k, set()).add(unit)
            try:
                s = score(r)
            except Exception:
                s = 0
            if k not in best or s > best[k][0]:
                best[k] = (s, r, unit)
    records = []
    for k, (s, r, unit) in best.items():
        rr = dict(r)
        rr["key"] = k
        rr["heard_by"] = sorted(heard[k])
        rr["units"] = len(heard[k])
        rr["best_unit"] = unit
        records.append(rr)
    return {"kind": kind, "units": sorted(units), "records": records,
            "reports": reports, "deduped": max(0, reports - len(records))}


# --------------------------------------------------------------------------
# Peer fan-out (best-effort; the merge core above stays pure/testable)
# --------------------------------------------------------------------------

_PORT = int(os.environ.get("RAGNAR_WEB_PORT", "0") or 0)


def _peers():
    """Online Ragnar-mesh peers (excluding self) as [{name, node}], or []."""
    try:
        import mesh_manager
        st = mesh_manager.status()
        peers = st.get("peers") or []
        out = []
        for n in peers:
            if not n.get("online"):
                continue
            tags = " ".join(n.get("tags") or [])
            if "ragnar-mesh" not in tags:        # only real Ragnar units
                continue
            out.append({"name": n.get("short_name") or n.get("hostname") or n.get("ip"), "node": n})
        return out
    except Exception:
        return []


def _fetch_peer(node, kind, timeout=3.0):
    """GET a peer's /api/mesh/sdr/<kind> snapshot over the tailnet, or None."""
    try:
        import requests
        import mesh_manager
        port = _PORT or getattr(mesh_manager, "DEFAULT_NODE_PORT", 8000)
        url = mesh_manager.peer_url(node, port, "/api/mesh/sdr/%s" % kind)
        if not url:
            return None
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": "Ragnar-mesh-aggregate"})
        if r.status_code != 200:
            return None
        d = r.json()
        if isinstance(d, dict) and isinstance(d.get("records"), list):
            return {"unit": d.get("unit") or node.get("short_name") or "peer", "records": d["records"]}
    except Exception:
        return None
    return None


def aggregate(kind, fetch=None):
    """Merge this unit's snapshot with every reachable peer's, deduped by key."""
    if kind not in KINDS:
        return {"error": "unknown kind", "kind": kind}
    snaps = [local_snapshot(kind)]
    peers = _peers()
    fetch = fetch or _fetch_peer
    reached = []
    for p in peers:
        snap = fetch(p["node"], kind)
        if snap:
            snaps.append(snap)
            reached.append(p["name"])
    res = merge(kind, snaps)
    res["peers_seen"] = [p["name"] for p in peers]
    res["peers_reached"] = reached
    return res


def status():
    """Aggregation status: mesh state, peers, and this unit's per-kind counts."""
    mesh_on = False
    try:
        import shared
        mesh_on = bool(getattr(shared, "shared_data", None)
                       and shared.shared_data.config.get("mesh_enabled"))
    except Exception:
        mesh_on = False
    peers = _peers()
    return {"unit": _unit_name(), "mesh_enabled": mesh_on,
            "peers": [p["name"] for p in peers], "peer_count": len(peers),
            "local": {k: len(local_snapshot(k)["records"]) for k in KINDS}}


# --------------------------------------------------------------------------
# Selftest (pure merge/dedup, no network)
# --------------------------------------------------------------------------

def selftest():
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    def snap(unit, kind, recs):
        keyfn = _KEY[kind]
        return {"unit": unit, "records": [dict(r, key=keyfn(r)) for r in recs]}

    # ADS-B: same plane heard by 2 units -> one row, positioned+freshest wins, heard_by both
    a1 = snap("goteborg", "adsb", [{"icao": "4ca7b1", "callsign": "SAS123", "lat": 57.7, "lon": 11.9, "seen": 12},
                                   {"icao": "3c6dd2", "callsign": "DLH9", "seen": 3}])
    a2 = snap("stockholm", "adsb", [{"icao": "4ca7b1", "callsign": "SAS123", "lat": 57.71, "lon": 11.95, "seen": 2},
                                    {"icao": "abc001", "callsign": "RYR1", "lat": 59.3, "lon": 18.0, "seen": 5}])
    m = merge("adsb", [a1, a2])
    byk = {r["key"]: r for r in m["records"]}
    check("adsb: deduped by ICAO (3 unique from 4 reports)",
          len(m["records"]) == 3 and m["reports"] == 4 and m["deduped"] == 1, str(m["deduped"]))
    check("adsb: shared plane merged, heard_by both, freshest kept",
          byk["4ca7b1"]["units"] == 2 and byk["4ca7b1"]["heard_by"] == ["goteborg", "stockholm"]
          and abs(byk["4ca7b1"]["lat"] - 57.71) < 1e-6, str(byk["4ca7b1"]))
    check("adsb: unique planes stay single-unit",
          byk["abc001"]["units"] == 1 and byk["3c6dd2"]["units"] == 1)

    # APRS: dedup by callsign, freshest ts wins
    p = merge("aprs", [snap("a", "aprs", [{"call": "G0ABC", "lat": 51, "lon": 0, "ts": 100}]),
                       snap("b", "aprs", [{"call": "G0ABC", "lat": 51.1, "lon": 0.1, "ts": 200}])])
    check("aprs: dedup by callsign, latest kept, heard_by both",
          len(p["records"]) == 1 and p["records"][0]["ts"] == 200 and p["records"][0]["units"] == 2, str(p))

    # Mesh: dedup by node id; positioned report preferred over position-less
    mm = merge("mesh", [snap("a", "mesh", [{"id": "!7c00", "long_name": "Base", "last_heard": 5}]),
                        snap("b", "mesh", [{"id": "!7c00", "long_name": "Base", "lat": 59.3, "lon": 18.0, "last_heard": 4}])])
    check("mesh: dedup by id, positioned report wins",
          len(mm["records"]) == 1 and mm["records"][0].get("lat") == 59.3 and mm["records"][0]["units"] == 2, str(mm))

    # ISM: dedup by model+id
    i = merge("ism", [snap("a", "ism", [{"model": "Acurite", "id": 42, "rssi": -70, "last_ts": 10}]),
                      snap("b", "ism", [{"model": "Acurite", "id": 42, "rssi": -55, "last_ts": 20},
                                        {"model": "TPMS", "id": 7, "rssi": -60, "last_ts": 15}])])
    check("ism: dedup by model+id (2 unique from 3), freshest kept",
          len(i["records"]) == 2 and i["deduped"] == 1, str(i))
    check("ism: key builder handles model/id", _KEY["ism"]({"model": "X", "id": 9}) == "X/9"
          and _KEY["ism"]({"model": None, "id": 1}) is None)

    # empty / unknown kind
    check("merge: no snapshots -> empty", merge("adsb", [])["records"] == [] and merge("adsb", [])["reports"] == 0)
    check("aggregate: unknown kind guarded", aggregate("nope").get("error") is not None)

    passed = sum(1 for r in results if r["pass"])
    return {"pass": passed == len(results), "passed": passed,
            "total": len(results), "results": results}


def _main(argv):
    import json
    cmd = argv[1] if len(argv) > 1 else "status"
    if cmd == "status":
        print(json.dumps(status(), indent=2))
    elif cmd == "snapshot":
        print(json.dumps(local_snapshot(argv[2] if len(argv) > 2 else "adsb"), indent=2)[:2000])
    elif cmd == "selftest":
        r = selftest()
        for x in r["results"]:
            print("  [%s] %s%s" % ("PASS" if x["pass"] else "FAIL", x["name"],
                                   "" if x["pass"] else "  -> " + x["detail"]))
        print("\n%d/%d checks pass — %s" % (r["passed"], r["total"],
                                            "OK" if r["pass"] else "FAILURES"))
        return 0 if r["pass"] else 1
    else:
        print("usage: mesh_aggregate.py [status|snapshot <kind>|selftest]")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
