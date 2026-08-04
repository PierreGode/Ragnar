"""Mesh scan delegation.

A small board (a 512MB Pi Zero 2 W) can't run Nuclei or ZAP without OOMing, so
those scanners are greyed out there. Rather than a dead end, this module lets
the small board stay the cockpit: it discovers which Ragnar units in the mesh
*can* run the heavy scanners, delegates the scan to the best one, and streams
the remote progress + findings back so the operator watches it on the Zero.

Pure decision logic only (build_roster / pick_delegate / required_tool) — no
I/O, fully unit-tested. It decides which mesh peer can run a heavy scanner; the
actual relay lives in AdvancedVulnScanner.start_delegated_scan, which mirrors
the remote scan into normal local scan state so the whole UI treats a delegated
scan exactly like a local one.

Only the RAM-gated scanners are ever delegated. The light CLI scanners
(nikto/sqlmap/nmap/whatweb) run locally on any board and are never routed away.
"""

from __future__ import annotations

from typing import Dict, List, Optional

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
