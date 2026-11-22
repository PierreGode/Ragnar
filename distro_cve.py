#!/usr/bin/env python3
# distro_cve.py
"""Distro revision-aware CVE enrichment for the Nmap vulnerability scanner.

The vulners NSE script matches a service against its *upstream* CPE
(``cpe:/a:openbsd:openssh:9.2p1``) and returns every CVE ever filed against that
upstream version. Debian and Ubuntu backport security fixes without changing
the upstream version, so a fully patched host still lights up with CVEs that
were fixed years ago.

The service banner usually carries the distro patch level
(``OpenSSH 9.2p1 Debian 2+deb12u10``). This module uses it:

1. ``parse_service_banner`` recognises the product and the distro revision
   marker (``+debNuM``, ``~debN``, ``ubuntuN``; ``elN`` / ``amznN`` are
   recognised but have no tracker here).
2. Each CVE is cross-referenced with the distro security tracker:
   * Debian  - https://security-tracker.debian.org/tracker/data/json
     (one snapshot, cached locally, trimmed to the packages Ragnar can
     fingerprint, so a scan works offline after the first sync).
   * Ubuntu  - https://ubuntu.com/security/cves/<CVE>.json (per CVE, cached).
3. Findings are *tagged*, never dropped:
   * ``distro-fixed``         the detected revision already contains the fix
   * ``distro-not-affected``  the distro marks its package as not affected
   * ``distro-deferred``      vulnerable, the distro postponed/ignored the fix
   * ``distro-open``          vulnerable (no fix yet, or the host is behind)
   * ``exploit-ref``          an exploit reference with no CVE id on a service
                              whose CVEs were distro-verified
   * ``unverified``           no revision in the banner / no tracker data;
                              behaviour is unchanged

``is_suppressed`` decides what the default view hides: fixed, not-affected and
unmapped exploit references - unless the CVE is in the CISA KEV catalogue.

Opt-in via the ``distro_cve_enrichment`` config key. Only CVE ids and public
package names ever leave the box; nothing about the scanned host is sent.
"""

import json
import logging
import mmap
import os
import re
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

try:  # requests is a core Ragnar dependency, but keep the parser importable without it
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore

logger = logging.getLogger("distro_cve")

DEBIAN_JSON_URL = "https://security-tracker.debian.org/tracker/data/json"
DEBIAN_CVE_URL = "https://security-tracker.debian.org/tracker/{cve}"
UBUNTU_CVE_API = "https://ubuntu.com/security/cves/{cve}.json"
UBUNTU_CVE_URL = "https://ubuntu.com/security/{cve}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "Ragnar-distro-cve/1.0"

STATUS_FIXED = "distro-fixed"
STATUS_NOT_AFFECTED = "distro-not-affected"
STATUS_DEFERRED = "distro-deferred"
STATUS_OPEN = "distro-open"
STATUS_EXPLOIT_REF = "exploit-ref"
STATUS_UNVERIFIED = "unverified"

# Hidden from the default view (still stored, still expandable in the UI).
SUPPRESSED_STATUSES = frozenset({STATUS_FIXED, STATUS_NOT_AFFECTED, STATUS_EXPLOIT_REF})

DEBIAN_RELEASES = {
    "8": "jessie", "9": "stretch", "10": "buster", "11": "bullseye",
    "12": "bookworm", "13": "trixie", "14": "forky", "15": "duke",
}
UBUNTU_RELEASES = {
    "14.04": "trusty", "16.04": "xenial", "18.04": "bionic", "20.04": "focal",
    "22.04": "jammy", "23.10": "mantic", "24.04": "noble", "24.10": "oracular",
    "25.04": "plucky", "25.10": "questing", "26.04": "resolute",
}

# (regex on the lower-cased banner, regex on the distro *source package* name).
# Order matters: MariaDB announces itself as "MySQL 5.5.5-10.11.6-MariaDB-...".
PRODUCTS: List[Tuple[str, str, str]] = [
    ("openssh", r"\bopenssh\b", r"openssh"),
    ("apache", r"\bapache httpd\b|\bapache/\d", r"apache2"),
    ("nginx", r"\bnginx\b", r"nginx"),
    ("mariadb", r"mariadb", r"mariadb(-\d+\.\d+)?"),
    ("mysql", r"\bmysql\b", r"mysql-\d+\.\d+"),
    ("postgresql", r"\bpostgresql\b", r"postgresql-\d+"),
    ("bind", r"\bbind\b", r"bind9"),
    ("samba", r"\bsamba\b", r"samba"),
    ("exim", r"\bexim\b", r"exim4"),
    ("postfix", r"\bpostfix\b", r"postfix"),
    ("dovecot", r"\bdovecot\b", r"dovecot"),
    ("proftpd", r"\bproftpd\b", r"proftpd-dfsg"),
    ("vsftpd", r"\bvsftpd\b", r"vsftpd"),
    ("pure-ftpd", r"\bpure-ftpd\b", r"pure-ftpd"),
    ("lighttpd", r"\blighttpd\b", r"lighttpd"),
    ("dnsmasq", r"\bdnsmasq\b", r"dnsmasq"),
    ("squid", r"\bsquid\b", r"squid"),
    ("cups", r"\bcups\b", r"cups"),
    ("dropbear", r"\bdropbear\b", r"dropbear"),
    ("unbound", r"\bunbound\b", r"unbound"),
    ("haproxy", r"\bhaproxy\b", r"haproxy"),
    ("redis", r"\bredis\b", r"redis"),
    ("memcached", r"\bmemcached\b", r"memcached"),
    ("mosquitto", r"\bmosquitto\b", r"mosquitto"),
    ("openvpn", r"\bopenvpn\b", r"openvpn"),
    ("xrdp", r"\bxrdp\b", r"xrdp"),
    ("rsync", r"\brsync\b", r"rsync"),
    ("php", r"\bphp\b", r"php\d+\.\d+"),
]
_PRODUCT_RES = [(name, re.compile(prod), re.compile(r"^(?:%s)$" % pkg)) for name, prod, pkg in PRODUCTS]
_WANTED_PKG_RE = re.compile(r"^(?:%s)$" % "|".join("(?:%s)" % pkg for _, _, pkg in PRODUCTS))

_CVE_RE = re.compile(r"CVE[-_](\d{4})[-_](\d{4,})", re.IGNORECASE)
# A revision token carrying a distro marker: 2+deb12u10, 1~deb12u1, 3ubuntu0.10, 0ubuntu0.22.04.1
_REV_MARKER_RE = re.compile(r"(?<![\w.+~])(\d[\w.+~]*?(?:[+~]deb\d+\w*|ubuntu[\w.+~]*))(?![\w+~])", re.IGNORECASE)
_DEB_MARKER_RE = re.compile(r"[+~]deb(\d+)", re.IGNORECASE)
_PLAIN_REV_RE = re.compile(r"\b(debian|ubuntu)[ _-](\d[\w.+~]*)", re.IGNORECASE)
_RPM_MARKER_RE = re.compile(r"\.(el|amzn)(\d+)", re.IGNORECASE)
_UPSTREAM_RE = re.compile(r"(?<![A-Za-z0-9.])(\d+(?:\.\d+)+[a-z]*\d*)")


# ---------------------------------------------------------------------------
# Debian version comparison (dpkg algorithm, pure Python - python-apt is not
# guaranteed on every board Ragnar runs on).
# ---------------------------------------------------------------------------

def _order(ch: str) -> int:
    if ch == "~":
        return -1
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _cmp_fragment(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        # non-digit prefix
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return -1 if ac < bc else 1
            if i < len(a) and not a[i].isdigit():
                i += 1
            if j < len(b) and not b[j].isdigit():
                j += 1
        # digit run
        si = i
        while i < len(a) and a[i].isdigit():
            i += 1
        sj = j
        while j < len(b) and b[j].isdigit():
            j += 1
        an = int(a[si:i] or 0)
        bn = int(b[sj:j] or 0)
        if an != bn:
            return -1 if an < bn else 1
    return 0


def split_version(version: str) -> Tuple[int, str, str]:
    """Split a Debian version into (epoch, upstream, revision)."""
    version = (version or "").strip()
    epoch = 0
    if ":" in version:
        head, _, rest = version.partition(":")
        if head.isdigit():
            epoch, version = int(head), rest
    if "-" in version:
        upstream, _, revision = version.rpartition("-")
    else:
        upstream, revision = version, ""
    return epoch, upstream, revision


def compare_versions(a: str, b: str) -> int:
    """dpkg --compare-versions: negative if a < b, 0 if equal, positive if a > b."""
    ea, ua, ra = split_version(a)
    eb, ub, rb = split_version(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _cmp_fragment(ua, ub) or _cmp_fragment(ra, rb)


def _numeric_parts(upstream: str) -> List[str]:
    m = re.match(r"\d+(?:\.\d+)*", upstream or "")
    return m.group(0).split(".") if m else []


def _upstream_match(a: str, b: str) -> int:
    """How many leading numeric components two upstream versions share (0-2)."""
    pa, pb = _numeric_parts(a), _numeric_parts(b)
    if not pa or not pb or pa[0] != pb[0]:
        return 0
    if len(pa) > 1 and len(pb) > 1 and pa[1] != pb[1]:
        return 1
    return 2


# ---------------------------------------------------------------------------
# Banner parsing
# ---------------------------------------------------------------------------

def extract_cve(text: str) -> Optional[str]:
    """Return the first CVE id in a vulners line (also CVE_2026_123 spellings)."""
    m = _CVE_RE.search(text or "")
    return "CVE-%s-%s" % (m.group(1), m.group(2)) if m else None


def identify_product(text: str) -> Optional[Tuple[str, "re.Pattern"]]:
    low = (text or "").lower().replace("_", " ")  # raw banners: "OpenSSH_9.2p1"
    for name, prod_re, pkg_re in _PRODUCT_RES:
        if prod_re.search(low):
            return name, pkg_re
    return None


def parse_service_banner(version_text: str, raw_banner: str = "") -> Optional[Dict[str, Any]]:
    """Fingerprint a service from the nmap VERSION column and/or its raw banner.

    Returns None when no known product is recognised. Otherwise a dict with
    ``product``, ``upstream``, and - when a distro revision is present -
    ``distro``, ``release`` (may be None, inferred later), ``revision`` and
    ``packaged`` (True when upstream and revision came as one package version,
    e.g. ``8.0.36-0ubuntu0.22.04.1``). The VERSION column wins; the raw banner
    is used when only it carries the revision.
    """
    first = None
    for text in (version_text, raw_banner):
        fp = _parse_one((text or "").strip())
        if fp and fp.get("revision"):
            return fp
        first = first or fp
    return first


def _parse_one(text: str) -> Optional[Dict[str, Any]]:
    ident = identify_product(text) if text else None
    if not ident:
        return None
    product, pkg_re = ident
    fp: Dict[str, Any] = {
        "product": product, "pkg_re": pkg_re, "banner": text[:200],
        "upstream": None, "distro": None, "release": None,
        "revision": None, "packaged": False,
    }

    rev = _REV_MARKER_RE.search(text)
    plain = None if rev else _PLAIN_REV_RE.search(text)
    rev_start = None
    if rev:
        fp["revision"] = rev.group(1)
        rev_start = rev.start(1)
        deb = _DEB_MARKER_RE.search(rev.group(1))
        if deb:
            fp["distro"] = "debian"
            fp["release"] = DEBIAN_RELEASES.get(deb.group(1))
            fp["release_number"] = deb.group(1)
        else:
            fp["distro"] = "ubuntu"
            lts = re.search(r"(\d\d\.\d\d)", rev.group(1).lower().split("ubuntu", 1)[1])
            if lts:
                fp["release"] = UBUNTU_RELEASES.get(lts.group(1))
    elif plain:
        # "OpenSSH 10.0p1 Debian 7" - a release's first upload has no +debN marker
        fp["distro"] = plain.group(1).lower()
        fp["revision"] = plain.group(2)
        rev_start = plain.start(2)
    else:
        rpm = _RPM_MARKER_RE.search(text)
        if rpm:
            fp["distro"] = "rhel" if rpm.group(1).lower() == "el" else "amazon"
            fp["release"] = rpm.group(1).lower() + rpm.group(2)

    # Upstream version: the last dotted number before the revision token
    # (so "(protocol 2.0)" after it is never mistaken for the version).
    head = text if rev_start is None else text[:rev_start]
    candidates = list(_UPSTREAM_RE.finditer(head))
    if product == "mariadb":
        m = re.search(r"(\d+\.\d+\.\d+)-mariadb", text, re.IGNORECASE)
        if m:
            fp["upstream"] = m.group(1)
            fp["packaged"] = bool(fp["revision"])
    if not fp["upstream"] and candidates:
        pick = candidates[-1] if rev_start is not None else candidates[0]
        fp["upstream"] = pick.group(1)
        # "9.18.28-0ubuntu0.22.04.1": upstream glued to the revision
        fp["packaged"] = rev_start is not None and head[pick.end():] == "-"
    return fp


# ---------------------------------------------------------------------------
# Small disk-cache helpers
# ---------------------------------------------------------------------------

def _read_json(path: str) -> Optional[Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _write_json(path: str, data: Any) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, separators=(",", ":"))
    os.replace(tmp, path)


class _Backoff:
    """After a failed fetch, do not retry for a while (keeps offline scans fast)."""

    def __init__(self, seconds: int = 1800):
        self.seconds = seconds
        self.until = 0.0

    def blocked(self) -> bool:
        return time.time() < self.until

    def trip(self) -> None:
        self.until = time.time() + self.seconds


# ---------------------------------------------------------------------------
# Debian security tracker (one snapshot, trimmed)
# ---------------------------------------------------------------------------

_DEB_TOPKEY_RE = re.compile(rb'(?:\A\{|\}\}\}\},)"([^"\\]{1,80})":\{')


def extract_debian_packages(path: str, wanted: Callable[[str], bool]) -> Dict[str, Any]:
    """Pull the wanted source packages out of the ~90 MB tracker JSON.

    The file is scanned through mmap and only the wanted package objects are
    decoded, so the heap peaks at about 3 MB where a plain ``json.load`` of the
    snapshot peaks near 360 MB (too much for a Pi Zero 2 W).
    """
    out: Dict[str, Any] = {}
    with open(path, "rb") as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            for m in _DEB_TOPKEY_RE.finditer(mm):
                name = m.group(1).decode("utf-8", "replace")
                if not wanted(name):
                    continue
                start = m.end() - 1
                end = mm.find(b'}}}},"', start)
                if end == -1:
                    blob = mm[start:mm.rfind(b"}")]
                else:
                    blob = mm[start:end + 4]
                try:
                    out[name] = _trim_debian_package(json.loads(blob))
                except Exception as exc:
                    logger.debug("distro_cve: could not decode Debian package %s: %s", name, exc)
        finally:
            mm.close()
    return out


def _trim_debian_package(pkg: Dict[str, Any]) -> Dict[str, Any]:
    repo: Dict[str, str] = {}
    cves: Dict[str, Any] = {}
    for cve, entry in pkg.items():
        rels = {}
        for rel, info in (entry.get("releases") or {}).items():
            if rel == "sid":
                continue
            for ver in (info.get("repositories") or {}).values():
                if rel not in repo or compare_versions(ver, repo[rel]) > 0:
                    repo[rel] = ver
            slim = {"s": info.get("status")}
            if "fixed_version" in info:
                slim["f"] = info["fixed_version"]
            if info.get("urgency") in ("unimportant", "end-of-life"):
                slim["u"] = info["urgency"]
            if "nodsa" in info:
                slim["n"] = info.get("nodsa_reason") or "no-dsa"
                slim["t"] = (info.get("nodsa") or "")[:120]
            rels[rel] = slim
        if rels:
            cves[cve] = rels
    return {"repo": repo, "cves": cves}


class DebianTracker:
    def __init__(self, cache_dir: str, max_age_hours: float = 24.0, session=None):
        self.cache_file = os.path.join(cache_dir, "debian_tracker.json")
        self.cache_dir = cache_dir
        self.max_age = max_age_hours * 3600
        self.session = session
        self._data: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()
        self._backoff = _Backoff()

    def _load(self) -> Dict[str, Any]:
        if self._data is None:
            data = _read_json(self.cache_file)
            self._data = data if isinstance(data, dict) and "packages" in data else {"meta": {}, "packages": {}}
        return self._data

    def age(self) -> Optional[float]:
        fetched = (self._load().get("meta") or {}).get("fetched")
        return (time.time() - fetched) if fetched else None

    def ensure_fresh(self) -> None:
        age = self.age()
        if age is not None and age < self.max_age:
            return
        if self._backoff.blocked():
            return
        with self._lock:
            age = self.age()
            if age is not None and age < self.max_age:
                return
            try:
                self.refresh()
            except Exception as exc:
                self._backoff.trip()
                state = "using the cached snapshot" if age is not None else "no cached snapshot yet"
                logger.warning("distro_cve: Debian tracker sync failed (%s) - %s", exc, state)

    def refresh(self) -> bool:
        """Download the snapshot and rebuild the trimmed cache. Raises on failure."""
        if requests is None:
            raise RuntimeError("requests not available")
        data = self._load()
        meta = dict(data.get("meta") or {})
        headers = {"User-Agent": USER_AGENT}
        if meta.get("last_modified") and data.get("packages"):
            headers["If-Modified-Since"] = meta["last_modified"]
        http = self.session or requests
        os.makedirs(self.cache_dir, exist_ok=True)
        tmp = os.path.join(self.cache_dir, "debian_tracker.download")
        try:
            with http.get(DEBIAN_JSON_URL, headers=headers, stream=True, timeout=(8, 120)) as resp:
                if resp.status_code == 304:
                    meta["fetched"] = time.time()
                    data["meta"] = meta
                    _write_json(self.cache_file, data)
                    return False
                resp.raise_for_status()
                size = 0
                with open(tmp, "wb") as fh:
                    for chunk in resp.iter_content(chunk_size=262144):
                        size += len(chunk)
                        if size > 600 * 1024 * 1024:
                            raise RuntimeError("tracker snapshot unexpectedly large")
                        fh.write(chunk)
                last_modified = resp.headers.get("Last-Modified")
            packages = extract_debian_packages(tmp, lambda n: bool(_WANTED_PKG_RE.match(n)))
            if not packages:
                raise RuntimeError("no packages found in tracker snapshot")
            self._data = {
                "meta": {"fetched": time.time(), "last_modified": last_modified, "bytes": size},
                "packages": packages,
            }
            _write_json(self.cache_file, self._data)
            logger.info("distro_cve: Debian tracker synced (%d packages, %.0f MB snapshot)",
                        len(packages), size / 1048576.0)
            return True
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass

    # -- lookups ----------------------------------------------------------
    def resolve(self, fp: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Pick the source package + release + full host version for a fingerprint."""
        packages = self._load().get("packages") or {}
        upstream = fp.get("upstream") or ""
        best = None
        for name, pkg in packages.items():
            if not fp["pkg_re"].match(name):
                continue
            repo = pkg.get("repo") or {}
            releases = [fp["release"]] if fp.get("release") else [r for r in repo]
            for rel in releases:
                ver = repo.get(rel)
                if not ver:
                    continue
                epoch, repo_up, repo_rev = split_version(ver)
                score = _upstream_match(upstream, repo_up)
                if not score or not repo_rev:
                    continue
                if not fp.get("release") and repo_rev.split("+")[0].split("~")[0] != \
                        (fp.get("revision") or "").split("+")[0].split("~")[0]:
                    # no +debN marker: the release must ship the same base revision
                    continue
                cand = (score, name, rel, epoch, repo_up)
                if best is None or cand[0] > best[0]:
                    best, tie = cand, False
                elif cand[0] == best[0] and (cand[1], cand[2]) != (best[1], best[2]):
                    tie = True
        if best is None or (tie and not fp.get("release")):
            return None
        score, name, rel, epoch, repo_up = best
        # "OpenSSH 10.0p2 Debian 7+deb13u4" is package 1:10.0p1-7+deb13u4: the
        # binary's own version string can differ from the package upstream.
        up = upstream if fp.get("packaged") or score < 2 else repo_up
        host = "%s%s-%s" % ("%d:" % epoch if epoch else "", up, fp["revision"])
        return {"package": name, "release": rel, "host_version": host}

    def classify(self, resolved: Dict[str, Any], cve: str) -> Dict[str, Any]:
        pkg = (self._load().get("packages") or {}).get(resolved["package"]) or {}
        info = ((pkg.get("cves") or {}).get(cve) or {}).get(resolved["release"])
        if not info:
            return {"status": STATUS_UNVERIFIED,
                    "note": "Debian tracker has no entry for this CVE in %s/%s"
                            % (resolved["package"], resolved["release"])}
        status, fixed = info.get("s"), info.get("f")
        if status == "resolved":
            if fixed == "0":
                return {"status": STATUS_NOT_AFFECTED, "note": "Debian: package not affected"}
            if fixed and compare_versions(resolved["host_version"], fixed) >= 0:
                return {"status": STATUS_FIXED, "fixed_version": fixed,
                        "note": "Fixed in %s; host runs %s" % (fixed, resolved["host_version"])}
            if fixed:
                return {"status": STATUS_OPEN, "fixed_version": fixed,
                        "note": "Fix available in %s; host still runs %s - update the package"
                                % (fixed, resolved["host_version"])}
        if status == "open":
            if info.get("u") == "unimportant":
                return {"status": STATUS_NOT_AFFECTED,
                        "note": "Debian: marked unimportant (no security impact as packaged)"}
            if "n" in info:
                why = info.get("t") or ""
                return {"status": STATUS_DEFERRED,
                        "note": ("Debian: vulnerable, no security update planned (%s)%s"
                                 % (info["n"], ": " + why if why else ""))}
            return {"status": STATUS_OPEN, "note": "Debian: vulnerable, no fix released yet"}
        return {"status": STATUS_UNVERIFIED, "note": "Debian tracker status undetermined"}


# ---------------------------------------------------------------------------
# Ubuntu CVE tracker (per-CVE API, cached)
# ---------------------------------------------------------------------------

class UbuntuTracker:
    def __init__(self, cache_dir: str, max_age_hours: float = 24.0, session=None,
                 max_lookups: int = 80, time_budget: float = 60.0):
        self.cache_dir = cache_dir
        self.cache_file = os.path.join(cache_dir, "ubuntu_cves.json")
        self.max_age = max_age_hours * 3600
        self.session = session
        self.max_lookups = max_lookups
        self.time_budget = time_budget
        self._data: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()
        self._backoff = _Backoff()

    def _load(self) -> Dict[str, Any]:
        if self._data is None:
            data = _read_json(self.cache_file)
            self._data = data if isinstance(data, dict) else {}
        return self._data

    def _fetch(self, cve: str) -> Optional[Dict[str, Any]]:
        if requests is None:
            return None
        http = self.session or requests
        resp = http.get(UBUNTU_CVE_API.format(cve=cve), headers={"User-Agent": USER_AGENT}, timeout=(6, 15))
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        packages: Dict[str, Any] = {}
        for pkg in (resp.json().get("packages") or []):
            name = pkg.get("name")
            if not name or not _WANTED_PKG_RE.match(name):
                continue
            packages[name] = {
                st.get("release_codename"): [st.get("status"), (st.get("description") or "")[:80]]
                for st in (pkg.get("statuses") or []) if st.get("release_codename")
            }
        return packages

    def fetch_many(self, cves: Iterable[str]) -> Dict[str, Dict[str, Any]]:
        """Return {cve: packages} from cache, fetching stale/missing ones within budget."""
        with self._lock:
            data = self._load()
            now = time.time()
            started = now
            lookups = 0
            dirty = False
            out: Dict[str, Dict[str, Any]] = {}
            for cve in cves:
                entry = data.get(cve)
                fresh = entry and (now - entry.get("t", 0)) < self.max_age
                if not fresh and not self._backoff.blocked() \
                        and lookups < self.max_lookups and (time.time() - started) < self.time_budget:
                    lookups += 1
                    try:
                        packages = self._fetch(cve)
                        if packages is not None:
                            entry = {"t": time.time(), "p": packages}
                            data[cve] = entry
                            dirty = True
                    except Exception as exc:
                        self._backoff.trip()
                        logger.warning("distro_cve: Ubuntu CVE lookup failed (%s) - using cache only", exc)
                if entry:
                    out[cve] = entry.get("p") or {}
            if dirty:
                try:
                    os.makedirs(self.cache_dir, exist_ok=True)
                    _write_json(self.cache_file, data)
                except Exception as exc:
                    logger.debug("distro_cve: could not save Ubuntu cache: %s", exc)
            return out

    @staticmethod
    def _stem(revision: str) -> str:
        return re.sub(r"\d+$", "", revision or "")

    def resolve(self, fp: Dict[str, Any], records: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Infer package, release and full host version from the fetched CVE records.

        An Ubuntu revision (``3ubuntu0.10``) does not name its release, so the
        release is the one whose published fixes share the banner's upstream
        version and revision stem.
        """
        upstream = fp.get("upstream") or ""
        stem = self._stem(fp.get("revision") or "")
        votes: Dict[Tuple[str, str], int] = {}
        sample: Dict[Tuple[str, str], Tuple[int, str]] = {}
        for packages in records.values():
            for name, statuses in packages.items():
                if not fp["pkg_re"].match(name):
                    continue
                for rel, (status, desc) in statuses.items():
                    if status != "released" or rel == "upstream" or "-" not in desc:
                        continue
                    if fp.get("release") and rel != fp["release"]:
                        continue
                    epoch, fix_up, fix_rev = split_version(desc)
                    score = _upstream_match(upstream, fix_up)
                    if not score:
                        continue
                    weight = score + (4 if self._stem(fix_rev) == stem else 0)
                    key = (name, rel)
                    votes[key] = votes.get(key, 0) + weight
                    sample.setdefault(key, (epoch, fix_up))
        if not votes:
            return None
        ranked = sorted(votes.items(), key=lambda kv: kv[1], reverse=True)
        if len(ranked) > 1 and ranked[0][1] == ranked[1][1] and not fp.get("release"):
            return None  # ambiguous release - stay unverified rather than guess
        (name, rel), _ = ranked[0]
        epoch, fix_up = sample[(name, rel)]
        up = upstream if fp.get("packaged") or _upstream_match(upstream, fix_up) < 2 else fix_up
        host = "%s%s-%s" % ("%d:" % epoch if epoch else "", up, fp["revision"])
        return {"package": name, "release": rel, "host_version": host}

    def classify(self, resolved: Dict[str, Any], cve: str, records: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        info = ((records.get(cve) or {}).get(resolved["package"]) or {}).get(resolved["release"])
        if not info:
            return {"status": STATUS_UNVERIFIED,
                    "note": "Ubuntu tracker has no entry for this CVE in %s/%s"
                            % (resolved["package"], resolved["release"])}
        status, desc = info[0], info[1]
        if status == "released":
            if re.match(r"^(\d+:)?\d\S*$", desc or ""):
                if compare_versions(resolved["host_version"], desc) >= 0:
                    return {"status": STATUS_FIXED, "fixed_version": desc,
                            "note": "Fixed in %s; host runs %s" % (desc, resolved["host_version"])}
                return {"status": STATUS_OPEN, "fixed_version": desc,
                        "note": "Fix available in %s; host still runs %s - update the package"
                                % (desc, resolved["host_version"])}
            return {"status": STATUS_UNVERIFIED, "note": "Ubuntu: released, fixed version not published"}
        if status == "not-affected":
            return {"status": STATUS_NOT_AFFECTED,
                    "note": "Ubuntu: not affected%s" % (" (%s)" % desc if desc else "")}
        if status in ("deferred", "ignored"):
            return {"status": STATUS_DEFERRED,
                    "note": "Ubuntu: vulnerable, fix %s%s" % (status, " (%s)" % desc if desc else "")}
        if status in ("needed", "pending", "in-progress"):
            return {"status": STATUS_OPEN, "note": "Ubuntu: vulnerable, fix %s" % status}
        return {"status": STATUS_UNVERIFIED, "note": "Ubuntu tracker status: %s" % (status or "unknown")}


# ---------------------------------------------------------------------------
# CISA KEV (ids only)
# ---------------------------------------------------------------------------

class KevCatalog:
    def __init__(self, cache_dir: str, max_age_hours: float = 24.0, session=None):
        self.cache_dir = cache_dir
        self.cache_file = os.path.join(cache_dir, "cisa_kev_ids.json")
        self.max_age = max_age_hours * 3600
        self.session = session
        self._ids: Optional[set] = None
        self._fetched = 0.0
        self._lock = threading.Lock()
        self._backoff = _Backoff()

    def ids(self) -> set:
        with self._lock:
            if self._ids is None:
                data = _read_json(self.cache_file) or {}
                self._ids = set(data.get("cves") or [])
                self._fetched = data.get("t", 0)
            if (time.time() - self._fetched) >= self.max_age and not self._backoff.blocked() and requests:
                try:
                    http = self.session or requests
                    resp = http.get(KEV_URL, headers={"User-Agent": USER_AGENT}, timeout=(6, 30))
                    resp.raise_for_status()
                    ids = {v.get("cveID") for v in resp.json().get("vulnerabilities", []) if v.get("cveID")}
                    if ids:
                        self._ids, self._fetched = ids, time.time()
                        os.makedirs(self.cache_dir, exist_ok=True)
                        _write_json(self.cache_file, {"t": self._fetched, "cves": sorted(ids)})
                except Exception as exc:
                    self._backoff.trip()
                    logger.warning("distro_cve: CISA KEV sync failed (%s) - using cache", exc)
            return self._ids


# ---------------------------------------------------------------------------
# Enricher
# ---------------------------------------------------------------------------

class DistroCveEnricher:
    """Tags the vulners lines of one scanned service with their distro status."""

    def __init__(self, cache_dir: str, max_age_hours: float = 24.0, session=None):
        self.cache_dir = cache_dir
        self.debian = DebianTracker(cache_dir, max_age_hours, session)
        self.ubuntu = UbuntuTracker(cache_dir, max_age_hours, session)
        self.kev = KevCatalog(cache_dir, max_age_hours, session)

    def enrich_service(self, version_text: str, raw_banner: str,
                       lines: Iterable[str]) -> Dict[str, Dict[str, Any]]:
        """Return {vulners line: tag} for one port. Never raises."""
        lines = list(lines)
        try:
            return self._enrich_service(version_text, raw_banner, lines)
        except Exception as exc:
            logger.warning("distro_cve: enrichment failed, findings left unverified: %s", exc)
            return {line: {"status": STATUS_UNVERIFIED, "note": "enrichment error"} for line in lines}

    def _enrich_service(self, version_text, raw_banner, lines):
        fp = parse_service_banner(version_text, raw_banner)
        by_line = {line: extract_cve(line) for line in lines}
        cves = sorted({c for c in by_line.values() if c})
        try:
            kev_ids = self.kev.ids() if cves else set()
        except Exception:
            kev_ids = set()

        base: Dict[str, Any] = {"checked": datetime.now().isoformat(timespec="seconds")}
        resolved = None
        classify: Callable[[str], Dict[str, Any]] = lambda cve: {}
        reason = "service banner carries no distro revision"
        if fp is None:
            reason = "service not recognised for distro matching"
        elif fp.get("distro") == "debian" and fp.get("revision"):
            base.update(distro="debian", revision=fp["revision"])
            if fp.get("release_number") and not fp.get("release"):
                reason = "unknown Debian release (deb%s)" % fp["release_number"]
            else:
                self.debian.ensure_fresh()
                resolved = self.debian.resolve(fp)
                classify = lambda cve: self.debian.classify(resolved, cve)
                reason = ("Debian tracker has no data for this package/release "
                          "(release out of support, or tracker not synced yet)")
        elif fp.get("distro") == "ubuntu" and fp.get("revision"):
            base.update(distro="ubuntu", revision=fp["revision"])
            records = self.ubuntu.fetch_many(cves)
            resolved = self.ubuntu.resolve(fp, records)
            classify = lambda cve: self.ubuntu.classify(resolved, cve, records)
            reason = "could not determine the Ubuntu release from the tracker data"
        elif fp.get("distro"):
            base.update(distro=fp["distro"], release=fp.get("release"))
            reason = "no security tracker integration for %s" % fp["distro"]

        if resolved:
            base.update(release=resolved["release"], package=resolved["package"],
                        host_version=resolved["host_version"])

        out: Dict[str, Dict[str, Any]] = {}
        verified_any = False
        for line, cve in by_line.items():
            tag = dict(base)
            if cve:
                tag["cve"] = cve
                tag["kev"] = cve in kev_ids
                if resolved:
                    tag.update(classify(cve))
                    url = DEBIAN_CVE_URL if base["distro"] == "debian" else UBUNTU_CVE_URL
                    tag["tracker_url"] = url.format(cve=cve)
                    verified_any = verified_any or tag["status"] != STATUS_UNVERIFIED
                else:
                    tag.update(status=STATUS_UNVERIFIED, note=reason)
            else:
                tag.update(status=STATUS_UNVERIFIED, note=reason, kev=False)
            out[line] = tag

        if verified_any:
            # Exploit references (githubexploit / PacketStorm / EDB ...) duplicate
            # the CVEs above but do not name one, so they cannot be checked.
            for line, cve in by_line.items():
                if not cve:
                    out[line].update(
                        status=STATUS_EXPLOIT_REF,
                        note="Exploit reference without a CVE id - not checkable against the "
                             "distro tracker; this service's CVEs were verified individually")
        return out


# ---------------------------------------------------------------------------
# Presentation helpers (used by network_intelligence / the web API)
# ---------------------------------------------------------------------------

def distro_info(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """The distro tag stored on a finding ({} when it was never enriched)."""
    details = vuln.get("details") if isinstance(vuln, dict) else None
    tag = details.get("distro") if isinstance(details, dict) else None
    return tag if isinstance(tag, dict) else {}


def is_suppressed(vuln: Dict[str, Any], enabled: bool = True) -> bool:
    """True when the default view should hide this finding.

    Fixed / not-affected / unmapped exploit references are hidden; a CVE in the
    CISA KEV catalogue is always kept visible.
    """
    if not enabled:
        return False
    tag = distro_info(vuln)
    return tag.get("status") in SUPPRESSED_STATUSES and not tag.get("kev")


def rank_key(vuln: Dict[str, Any], enabled: bool = True) -> Tuple[int, int, int]:
    """Sort key: visible before suppressed, KEV first, confirmed-open next, then severity."""
    tag = distro_info(vuln) if enabled else {}
    severity = {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(vuln.get("severity"), 4)
    status_rank = {STATUS_OPEN: 0, STATUS_DEFERRED: 1}.get(tag.get("status"), 2)
    return (1 if is_suppressed(vuln, enabled) else 0, 0 if tag.get("kev") else 1,
            severity * 10 + status_rank)


_ENRICHERS: Dict[str, DistroCveEnricher] = {}
_ENRICHERS_LOCK = threading.Lock()


def get_enricher(shared_data) -> DistroCveEnricher:
    """One enricher per cache dir (``data/distro_cve``), shared by all scans."""
    datadir = getattr(shared_data, "datadir", None) or os.path.join(
        getattr(shared_data, "currentdir", os.getcwd()), "data")
    cache_dir = os.path.join(datadir, "distro_cve")
    try:
        hours = float((getattr(shared_data, "config", {}) or {}).get("distro_cve_cache_hours", 24))
    except (TypeError, ValueError):
        hours = 24.0
    with _ENRICHERS_LOCK:
        enr = _ENRICHERS.get(cache_dir)
        if enr is None:
            enr = _ENRICHERS[cache_dir] = DistroCveEnricher(cache_dir, hours)
        return enr


def enrichment_enabled(shared_data) -> bool:
    try:
        return bool((getattr(shared_data, "config", {}) or {}).get("distro_cve_enrichment", False))
    except Exception:
        return False


if __name__ == "__main__":  # manual check: distro_cve.py "<nmap version text>" CVE-... CVE-...
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 3:
        print('usage: distro_cve.py "OpenSSH 9.2p1 Debian 2+deb12u10" CVE-2024-6387 [...]')
        sys.exit(2)
    here = os.path.dirname(os.path.abspath(__file__))
    enricher = DistroCveEnricher(os.path.join(here, "data", "distro_cve"))
    for line, tag in enricher.enrich_service(sys.argv[1], "", sys.argv[2:]).items():
        print("%-18s %-20s %s" % (line, tag.get("status"), tag.get("note", "")))
