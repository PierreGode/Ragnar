"""Mesh scan delegation.

A small board (a 512MB Pi Zero 2 W) can't run Nuclei or ZAP without OOMing, so
those scanners are greyed out there. Rather than a dead end, this module lets
the small board stay the cockpit: it discovers which Ragnar units in the mesh
*can* run the heavy scanners, delegates the scan to the best one, and streams
the remote progress + findings back so the operator watches it on the Zero.

Two halves:
  * Pure decision logic (build_roster / pick_delegate / build_banner) — no I/O,
    fully unit-tested. This is what drives the "ylva can run Nuclei" banner.
  * MeshScanDelegator — orchestrates the actual delegation and the relay poll,
    with all peer I/O injected so it's testable and so webapp owns the wiring.

Only the RAM-gated scanners are ever delegated. The light CLI scanners
(nikto/sqlmap/nmap/whatweb) run locally on any board and are never routed away.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("mesh_scan")

# Scanner families. A scan_type maps to the heavy tool it needs (or None when
# it's a light scanner that always runs locally). "full" needs nuclei; its ZAP
# leg is optional and simply skipped when the delegate lacks ZAP.
_ZAP_TYPES = {"zap_spider", "zap_active", "zap_full"}
_NUCLEI_TYPES = {"nuclei", "full"}


def required_tool(scan_type: str) -> Optional[str]:
    """The heavy tool a scan_type needs ('nuclei' | 'zap'), or None if light."""
    if scan_type in _ZAP_TYPES:
        return "zap"
    if scan_type in _NUCLEI_TYPES:
        return "nuclei"
    return None


def capability(viking: str, unit_id: int = 0, ram_gb: float = 0.0,
               nuclei: bool = False, zap: bool = False, node_id: str = "",
               ip: str = "", reachable: bool = True) -> Dict:
    """One unit's scan capability record. `nuclei`/`zap` mean *can actually run*
    it — the tool is both installed and above its RAM gate."""
    return {
        "viking": viking, "unit_id": unit_id, "ram_gb": round(ram_gb, 2),
        "nuclei": bool(nuclei), "zap": bool(zap),
        "node_id": node_id, "ip": ip, "reachable": bool(reachable),
    }


def build_roster(peer_caps: List[Dict]) -> List[Dict]:
    """Keep only reachable peers that can run at least one heavy scanner."""
    return [c for c in peer_caps
            if c.get("reachable", True) and (c.get("nuclei") or c.get("zap"))]


def pick_delegate(roster: List[Dict], need: str) -> Optional[Dict]:
    """Best peer that can run `need` ('nuclei'|'zap'): prefer one that can run
    *both* heavy scanners, then most RAM, then name — stable and predictable."""
    cands = [c for c in roster if c.get(need) and c.get("reachable", True)]
    if not cands:
        return None
    cands.sort(key=lambda c: (
        not (c.get("nuclei") and c.get("zap")),   # both-capable first
        -float(c.get("ram_gb") or 0),             # then most RAM
        (c.get("viking") or "").lower(),          # then name, for stability
    ))
    return cands[0]


def _join_human(items: List[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return " and ".join([", ".join(items[:-1]), items[-1]]) if len(items) > 2 \
        else " and ".join(items)


def build_banner(local: Dict, roster: List[Dict]) -> Dict:
    """Decide what the Adv Scan banner should say on this board.

    `local` is {'nuclei': bool, 'zap': bool} for THIS unit. Mirrors the
    operator's scenarios exactly:
      * local can run everything          -> no banner
      * local can't, a peer can           -> name the peer(s) and what they run
      * local can't and no peer can either -> "not compatible, none found"
    """
    label = {"nuclei": "Nuclei", "zap": "ZAP"}
    missing = [s for s in ("nuclei", "zap") if not local.get(s)]
    if not missing:
        return {"show": False, "kind": "local", "text": "",
                "missing": [], "delegates": {}, "recommended": None}

    delegates = {s: pick_delegate(roster, s) for s in ("nuclei", "zap")}
    covered = [s for s in missing if delegates[s]]
    missing_labels = _join_human([label[s] for s in missing])

    if not covered:
        return {
            "show": True, "kind": "none",
            "text": (f"This device can't run {missing_labels}, and no compatible "
                     f"Ragnar was found in the mesh."),
            "missing": missing, "delegates": {}, "recommended": None,
        }

    # Prefer a single unit that covers everything this board is missing.
    recommended = None
    for cand in build_roster(roster):
        if all(cand.get(s) for s in missing):
            recommended = pick_delegate(roster, missing[0])  # stable best
            if all(recommended.get(s) for s in missing):
                break
            recommended = cand
            break
    if recommended and all(recommended.get(s) for s in missing):
        runs = _join_human([label[s] for s in missing])
        text = (f"This device can't run {missing_labels} — but "
                f"{recommended['viking']} can run {runs}. Run your scan here; "
                f"{recommended['viking']} does the work and the results come back here.")
    else:
        # Different units cover different scanners.
        parts = []
        for s in missing:
            d = delegates[s]
            if d:
                parts.append(f"{d['viking']} can run {label[s]}")
        text = (f"This device can't run {missing_labels}. " + "; ".join(parts) +
                ". Run your scan here; the results come back here.")
        recommended = delegates[covered[0]]

    return {
        "show": True, "kind": "delegate", "text": text,
        "missing": missing,
        "delegates": {s: delegates[s] for s in ("nuclei", "zap")},
        "recommended": recommended,
    }


class MeshScanDelegator:
    """Runs a scan on a capable peer and relays its progress/findings home.

    All peer I/O is injected so this stays testable and webapp owns the mesh
    plumbing:
      * start_fn(node, target, scan_type, options)  -> {'success', 'scan_id'|'error'}
      * status_fn(node, remote_id)                  -> {'reachable','scan'|...}
      * findings_fn(node, remote_id)                -> {'findings': [...]}
      * cancel_fn(node, remote_id)                  -> {'success': bool}
    Each `node` is the peer's mesh node dict (has ip/id), carried on the
    capability record as `_node`.
    """

    POLL_INTERVAL = 2.0
    # Stop relaying a scan that never reports terminal status, so a wedged peer
    # can't leave a poller thread running forever.
    MAX_RELAY_SECONDS = 3 * 3600

    def __init__(self, start_fn: Callable, status_fn: Callable,
                 findings_fn: Callable, cancel_fn: Callable):
        self._start_fn = start_fn
        self._status_fn = status_fn
        self._findings_fn = findings_fn
        self._cancel_fn = cancel_fn
        self._lock = threading.Lock()
        self._scans: Dict[str, Dict] = {}

    def start(self, node: Dict, viking: str, target: str, scan_type: str,
              options: Optional[Dict] = None) -> Dict:
        """Delegate a scan to `node`. Returns {'success', 'delegated_id'|'error'}."""
        reply = self._start_fn(node, target, scan_type, options or {})
        if not reply.get("success") or not reply.get("scan_id"):
            return {"success": False,
                    "error": reply.get("error") or "peer refused the scan"}
        local_id = f"MESH-{uuid.uuid4().hex[:10]}"
        rec = {
            "delegated_id": local_id,
            "remote_scan_id": reply["scan_id"],
            "_node": node,  # kept so relay + cancel reach the same peer
            "viking": viking, "target": target, "scan_type": scan_type,
            "status": "running", "progress_percent": 0,
            "current_check": f"Delegated to {viking}…",
            "findings_count": 0, "findings": [], "error_message": "",
            "started_at": time.time(), "updated_at": time.time(),
        }
        with self._lock:
            self._scans[local_id] = rec
        t = threading.Thread(target=self._relay, args=(local_id, node), daemon=True)
        t.start()
        return {"success": True, "delegated_id": local_id,
                "remote_scan_id": reply["scan_id"], "viking": viking}

    def _relay(self, local_id: str, node: Dict):
        remote_id = self._scans[local_id]["remote_scan_id"]
        deadline = time.time() + self.MAX_RELAY_SECONDS
        while time.time() < deadline:
            time.sleep(self.POLL_INTERVAL)
            reply = self._status_fn(node, remote_id)
            scan = reply.get("scan") if isinstance(reply, dict) else None
            with self._lock:
                rec = self._scans.get(local_id)
                if rec is None:
                    return
                if not reply.get("reachable", False):
                    rec["current_check"] = "Peer unreachable — retrying…"
                    rec["updated_at"] = time.time()
                    continue
                if scan:
                    rec["progress_percent"] = scan.get("progress_percent", rec["progress_percent"])
                    rec["current_check"] = scan.get("current_check", rec["current_check"])
                    rec["findings_count"] = scan.get("findings_count", rec["findings_count"])
                    rec["status"] = scan.get("status", rec["status"])
                    rec["error_message"] = scan.get("error_message", rec["error_message"])
                    rec["updated_at"] = time.time()
                status = rec["status"]
            if status in ("completed", "failed", "cancelled"):
                self._finish(local_id, node, remote_id, status)
                return
        # Timed out relaying.
        with self._lock:
            rec = self._scans.get(local_id)
            if rec and rec["status"] == "running":
                rec["status"] = "failed"
                rec["error_message"] = "Relay timed out — peer stopped reporting."
                rec["updated_at"] = time.time()

    def _finish(self, local_id: str, node: Dict, remote_id: str, status: str):
        findings = []
        if status == "completed":
            try:
                fr = self._findings_fn(node, remote_id)
                findings = (fr or {}).get("findings", []) or []
            except Exception as exc:
                logger.warning("Mesh scan %s: could not fetch findings: %s", local_id, exc)
        with self._lock:
            rec = self._scans.get(local_id)
            if rec is not None:
                rec["findings"] = findings
                rec["findings_count"] = len(findings) or rec["findings_count"]
                if rec["status"] == "running":
                    rec["status"] = status
                rec["updated_at"] = time.time()

    def cancel(self, local_id: str) -> Dict:
        with self._lock:
            rec = self._scans.get(local_id)
            if rec is None:
                return {"success": False, "error": "unknown delegated scan"}
            remote_id, node = rec["remote_scan_id"], rec.get("_node")
        if not node:
            return {"success": False, "error": "delegate no longer reachable"}
        reply = self._cancel_fn(node, remote_id)
        if reply.get("success"):
            with self._lock:
                if local_id in self._scans:
                    self._scans[local_id]["status"] = "cancelled"
                    self._scans[local_id]["updated_at"] = time.time()
        return {"success": bool(reply.get("success")),
                "error": reply.get("error", "")}

    @staticmethod
    def _public(rec: Dict, include_findings: bool) -> Dict:
        d = dict(rec)
        d.pop("_node", None)  # never serialise the peer node object
        if not include_findings:
            d.pop("findings", None)
        return d

    def list_scans(self, include_findings: bool = False) -> List[Dict]:
        with self._lock:
            out = [self._public(rec, include_findings) for rec in self._scans.values()]
        out.sort(key=lambda r: r["started_at"], reverse=True)
        return out

    def get_scan(self, local_id: str) -> Optional[Dict]:
        with self._lock:
            rec = self._scans.get(local_id)
            return self._public(rec, include_findings=True) if rec else None

    def prune(self, keep: int = 40):
        """Drop the oldest finished scans so the table doesn't grow forever."""
        with self._lock:
            if len(self._scans) <= keep:
                return
            done = sorted(
                [r for r in self._scans.values()
                 if r["status"] in ("completed", "failed", "cancelled")],
                key=lambda r: r["updated_at"])
            for rec in done[:len(self._scans) - keep]:
                self._scans.pop(rec["delegated_id"], None)
