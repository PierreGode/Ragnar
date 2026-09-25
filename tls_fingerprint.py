"""
TLS / JA3 fingerprint collector for Ragnar (server mode).

Architecture
------------
A `JA3Collector` runs `tshark` as a sidecar subprocess that streams every
TLS ClientHello on the wire as line-delimited fields. We aggregate the
fingerprints per (src_ip, ja3, sni) tuple, classify them against a static
signature database (data/ja3_signatures.yaml), and surface notable matches
(known malware C2, suspicious IoT, etc.) by calling an alert callback.

The collector is fully decoupled from `TrafficAnalyzer` and can be
unit-tested by feeding lines into `process_line()` directly.

The tshark command (only spawned when `start()` is called):

    tshark -i <iface> -l -n
        -Y "tls.handshake.type==1"
        -T fields -E separator=|
        -e frame.time_epoch
        -e ip.src -e ip.dst -e tcp.dstport
        -e tls.handshake.ja3
        -e tls.handshake.extensions_server_name

This module degrades gracefully: if `tshark` is missing, `start()` returns
False and the rest of Ragnar is unaffected.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Default location of the bundled signature DB (relative to project root).
_DEFAULT_SIG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'data', 'ja3_signatures.yaml'
)

_TSHARK_FIELDS = [
    'frame.time_epoch',
    'ip.src', 'ip.dst', 'tcp.dstport',
    'tls.handshake.ja3',
    'tls.handshake.extensions_server_name',
]


@dataclass
class JA3Match:
    """A signature hit for a given JA3 hash."""
    ja3: str
    label: str
    confidence: str  # 'high' | 'medium' | 'low'
    source: str
    category: str    # e.g. 'malware', 'iot', 'browser', 'tool'


@dataclass
class FingerprintRecord:
    """Per (src_ip, ja3, sni) aggregate."""
    src_ip: str
    ja3: str
    sni: str
    dst_ips: set = field(default_factory=set)
    dst_ports: set = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    count: int = 0
    match: Optional[JA3Match] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'src_ip': self.src_ip,
            'ja3': self.ja3,
            'sni': self.sni,
            'dst_ips': sorted(self.dst_ips)[:25],
            'dst_ports': sorted(self.dst_ports),
            'first_seen': datetime.fromtimestamp(self.first_seen).isoformat()
                          if self.first_seen else None,
            'last_seen': datetime.fromtimestamp(self.last_seen).isoformat()
                         if self.last_seen else None,
            'count': self.count,
            'match': asdict(self.match) if self.match else None,
        }


def load_signatures(path: str = _DEFAULT_SIG_PATH) -> Dict[str, JA3Match]:
    """Load JA3 -> JA3Match mapping from a YAML file.

    Format (list of entries):

        - ja3: e7d705a3286e19ea42f587b344ee6865
          label: "Cobalt Strike (default profile)"
          confidence: high
          source: SSLBL
          category: malware

    Returns an empty dict if the file is missing or PyYAML is unavailable —
    the collector still works, just without classification.
    """
    if not os.path.exists(path):
        logger.debug("JA3 signature file not found at %s", path)
        return {}
    try:
        import yaml  # type: ignore
    except ImportError:
        logger.warning("PyYAML not installed; JA3 classification disabled.")
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = yaml.safe_load(fh) or []
    except Exception as exc:
        logger.error("Failed to load JA3 signatures from %s: %s", path, exc)
        return {}

    out: Dict[str, JA3Match] = {}
    for entry in data:
        if not isinstance(entry, dict):
            continue
        ja3 = (entry.get('ja3') or '').strip().lower()
        if not _looks_like_md5(ja3):
            continue
        out[ja3] = JA3Match(
            ja3=ja3,
            label=str(entry.get('label', 'unknown')),
            confidence=str(entry.get('confidence', 'low')),
            source=str(entry.get('source', 'local')),
            category=str(entry.get('category', 'unknown')),
        )
    return out


_MD5_RE = re.compile(r'^[a-f0-9]{32}$')


def _looks_like_md5(s: str) -> bool:
    return bool(_MD5_RE.match(s or ''))


class JA3Collector:
    """Streams TLS ClientHellos via tshark and aggregates JA3 fingerprints."""

    # The number of distinct fingerprints we keep in memory. Old entries
    # are evicted FIFO when this is exceeded.
    MAX_RECORDS = 5000

    def __init__(
        self,
        interface: str = 'any',
        signatures: Optional[Dict[str, JA3Match]] = None,
        on_match: Optional[Callable[[FingerprintRecord], None]] = None,
        on_new: Optional[Callable[[FingerprintRecord], None]] = None,
        tshark_path: Optional[str] = None,
    ) -> None:
        self.interface = interface
        self.signatures = signatures if signatures is not None else load_signatures()
        self._on_match = on_match
        self._on_new = on_new
        self._tshark = tshark_path or shutil.which('tshark')

        self._records: Dict[Tuple[str, str, str], FingerprintRecord] = {}
        self._lock = threading.Lock()

        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def is_available(self) -> bool:
        return bool(self._tshark)

    def start(self) -> bool:
        if not self.is_available():
            logger.warning("tshark not found; JA3 collection disabled.")
            return False
        if self._running:
            return True
        self._running = True
        self._thread = threading.Thread(
            target=self._capture_loop, name="JA3Collector", daemon=True
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        self._running = False
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    # ------------------------------------------------------------------ #
    # Capture
    # ------------------------------------------------------------------ #

    def _build_cmd(self) -> List[str]:
        cmd = ['sudo', self._tshark, '-i', self.interface, '-l', '-n',
               '-Y', 'tls.handshake.type==1',
               '-T', 'fields', '-E', 'separator=|']
        for f in _TSHARK_FIELDS:
            cmd += ['-e', f]
        return cmd

    def _capture_loop(self) -> None:
        try:
            self._proc = subprocess.Popen(
                self._build_cmd(),
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1,
            )
        except Exception as exc:
            logger.error("Failed to spawn tshark: %s", exc)
            self._running = False
            return

        try:
            assert self._proc.stdout is not None
            for line in self._proc.stdout:
                if not self._running:
                    break
                line = line.rstrip('\n')
                if line:
                    try:
                        self.process_line(line)
                    except Exception as exc:
                        logger.debug("JA3 line parse error: %s", exc)
        finally:
            self.stop()

    # ------------------------------------------------------------------ #
    # Parsing (public for tests)
    # ------------------------------------------------------------------ #

    def process_line(self, line: str) -> Optional[FingerprintRecord]:
        """Parse one '|'-separated tshark output line and update state.

        Returns the updated FingerprintRecord, or None if the line is
        malformed / lacks a JA3 hash.
        """
        parts = line.split('|')
        # tshark emits all configured fields even when empty.
        if len(parts) < len(_TSHARK_FIELDS):
            return None
        ts_str, src, dst, dport, ja3, sni = parts[:6]

        ja3 = (ja3 or '').strip().lower()
        if not _looks_like_md5(ja3):
            return None

        try:
            ts = float(ts_str) if ts_str else time.time()
        except ValueError:
            ts = time.time()
        try:
            port = int(dport) if dport else 0
        except ValueError:
            port = 0
        sni = (sni or '').strip().lower()
        src = (src or '').strip()
        dst = (dst or '').strip()

        key = (src, ja3, sni)
        with self._lock:
            is_new = key not in self._records
            if is_new:
                if len(self._records) >= self.MAX_RECORDS:
                    # FIFO evict
                    oldest_key = next(iter(self._records))
                    self._records.pop(oldest_key, None)
                rec = FingerprintRecord(
                    src_ip=src, ja3=ja3, sni=sni,
                    first_seen=ts, last_seen=ts,
                )
                rec.match = self.signatures.get(ja3)
                self._records[key] = rec
            else:
                rec = self._records[key]
            if dst:
                rec.dst_ips.add(dst)
            if port:
                rec.dst_ports.add(port)
            rec.last_seen = ts
            rec.count += 1

        if is_new:
            if self._on_new:
                try:
                    self._on_new(rec)
                except Exception as exc:
                    logger.debug("on_new callback failed: %s", exc)
            if rec.match and self._on_match:
                try:
                    self._on_match(rec)
                except Exception as exc:
                    logger.debug("on_match callback failed: %s", exc)
        return rec

    # ------------------------------------------------------------------ #
    # Accessors
    # ------------------------------------------------------------------ #

    def get_records(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return fingerprint records, classified entries first."""
        with self._lock:
            recs = list(self._records.values())
        recs.sort(key=lambda r: (r.match is None, -r.last_seen))
        return [r.to_dict() for r in recs[:limit]]

    def lookup(self, ja3: str) -> Optional[JA3Match]:
        """Direct signature lookup (no aggregation)."""
        return self.signatures.get((ja3 or '').strip().lower())

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
