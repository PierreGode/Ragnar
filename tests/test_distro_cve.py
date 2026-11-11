"""Distro revision-aware CVE enrichment (issue #1051). Fully offline.

The tracker fixtures mirror real entries from the Debian security tracker and
the Ubuntu CVE API for OpenSSH (the scenario in the issue: a Debian 12 host on
OpenSSH 1:9.2p1-2+deb12u10 flagged with ~120 upstream CVEs).
"""
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import distro_cve as dc  # noqa: E402


class NoNetwork:
    """A requests-like session that fails every call (offline box)."""
    calls = 0

    def get(self, *args, **kwargs):
        NoNetwork.calls += 1
        raise ConnectionError("offline")


def _rel(status, repo, fixed=None, urgency="not yet assigned", **extra):
    info = {"status": status, "repositories": repo, "urgency": urgency}
    if fixed is not None:
        info["fixed_version"] = fixed
    info.update(extra)
    return info


BOOKWORM = {"bookworm": "1:9.2p1-2+deb12u10", "bookworm-security": "1:9.2p1-2+deb12u9"}
TRIXIE = {"trixie": "1:10.0p1-7+deb13u4", "trixie-security": "1:10.0p1-7+deb13u2"}
SID = {"sid": "1:10.3p1-1"}

DEBIAN_SNAPSHOT = {
    "aaa-first": {"CVE-2000-0001": {"description": "x", "releases": {
        "bookworm": _rel("resolved", {"bookworm": "1.0-1"}, "1.0-1")}}},
    "openssh": {
        "CVE-2023-38408": {"description": 'mentions "openssh":{ in \\"text\\"', "releases": {
            "bookworm": _rel("resolved", BOOKWORM, "1:9.2p1-2+deb12u1"),
            "trixie": _rel("resolved", TRIXIE, "1:9.3p2-1"),
            "sid": _rel("resolved", SID, "1:9.3p2-1")}},
        "CVE-2024-6387": {"releases": {
            "bookworm": _rel("resolved", BOOKWORM, "1:9.2p1-2+deb12u3"),
            "trixie": _rel("resolved", TRIXIE, "1:9.7p1-7")}},
        "CVE-2026-35386": {"releases": {
            "bookworm": _rel("resolved", BOOKWORM, "1:9.2p1-2+deb12u10"),
            "trixie": _rel("resolved", TRIXIE, "1:10.0p1-7+deb13u3")}},
        "CVE-2026-123158": {"releases": {
            "bookworm": _rel("open", BOOKWORM, urgency="unimportant"),
            "trixie": _rel("open", TRIXIE, urgency="unimportant")}},
        "CVE-2026-60002": {"releases": {
            "bookworm": _rel("open", BOOKWORM, nodsa="Minor issue", nodsa_reason="postponed"),
            "trixie": _rel("open", TRIXIE, nodsa="Minor issue", nodsa_reason="")}},
        "CVE-2026-70001": {"releases": {"bookworm": _rel("open", BOOKWORM)}},
        "CVE-2016-0001": {"releases": {"bookworm": _rel("resolved", BOOKWORM, "0")}},
        "CVE-2026-70002": {"releases": {"bookworm": _rel("undetermined", BOOKWORM)}},
    },
    "not-wanted": {"CVE-2001-0001": {"releases": {"bookworm": _rel("open", {"bookworm": "2-1"})}}},
    "zzz-last-vsftpd-decoy": {"CVE-2002-0001": {"releases": {"bookworm": _rel("open", {"bookworm": "3-1"})}}},
    "vsftpd": {"CVE-2021-3618": {"releases": {"bookworm": _rel("resolved", {"bookworm": "3.0.3-13"}, "3.0.3-13")}}},
}

UBUNTU_RECORDS = {
    "CVE-2024-6387": {"openssh": {
        "focal": ["not-affected", "introduced in v8.5p1"],
        "jammy": ["released", "1:8.9p1-3ubuntu0.10"],
        "noble": ["released", "1:9.6p1-3ubuntu13.3"],
        "upstream": ["released", "9.8p1"]}},
    "CVE-2023-38408": {"openssh": {
        "jammy": ["released", "1:8.9p1-3ubuntu0.3"],
        "noble": ["released", "1:9.3p1-1ubuntu2"]}},
    "CVE-2025-26465": {"openssh": {
        "jammy": ["released", "1:8.9p1-3ubuntu0.11"],
        "noble": ["released", "1:9.6p1-3ubuntu13.8"]}},
    "CVE-2026-0001": {"openssh": {"jammy": ["deferred", ""], "noble": ["needed", ""]}},
    "CVE-2026-0002": {"openssh": {"jammy": ["not-affected", "code not present"]}},
    "CVE-2026-0003": {"openssh": {"jammy": ["needs-triage", ""]}},
}


@pytest.fixture
def cache_dir(tmp_path):
    """A cache dir with fresh Debian + Ubuntu + KEV data (so nothing is fetched)."""
    raw = tmp_path / "snapshot.json"
    raw.write_text(json.dumps(DEBIAN_SNAPSHOT, separators=(",", ":")))
    packages = dc.extract_debian_packages(str(raw), lambda n: bool(dc._WANTED_PKG_RE.match(n)))
    cdir = tmp_path / "distro_cve"
    cdir.mkdir()
    now = time.time()
    (cdir / "debian_tracker.json").write_text(json.dumps({"meta": {"fetched": now}, "packages": packages}))
    (cdir / "ubuntu_cves.json").write_text(json.dumps(
        {cve: {"t": now, "p": pkgs} for cve, pkgs in UBUNTU_RECORDS.items()}))
    (cdir / "cisa_kev_ids.json").write_text(json.dumps({"t": now, "cves": ["CVE-2024-6387"]}))
    return str(cdir)


@pytest.fixture
def enricher(cache_dir):
    NoNetwork.calls = 0
    return dc.DistroCveEnricher(cache_dir, session=NoNetwork())


def line(ident, score="8.1", exploit=False):
    return "%s\t%s\thttps://vulners.com/x/%s%s" % (ident, score, ident, "\t*EXPLOIT*" if exploit else "")


# --------------------------------------------------------------------------- parsing

@pytest.mark.parametrize("text,expect", [
    ("OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)",
     ("openssh", "9.2p1", "debian", "bookworm", "2+deb12u10", False)),
    ("OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)",
     ("openssh", "10.0p2", "debian", "trixie", "7+deb13u4", False)),
    ("OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)",
     ("openssh", "8.9p1", "ubuntu", None, "3ubuntu0.10", False)),
    ("MySQL 5.5.5-10.11.6-MariaDB-0+deb12u1",
     ("mariadb", "10.11.6", "debian", "bookworm", "0+deb12u1", True)),
    ("MySQL 8.0.36-0ubuntu0.22.04.1",
     ("mysql", "8.0.36", "ubuntu", "jammy", "0ubuntu0.22.04.1", True)),
    ("ISC BIND 9.18.28-0ubuntu0.22.04.1-Ubuntu",
     ("bind", "9.18.28", "ubuntu", "jammy", "0ubuntu0.22.04.1", True)),
    ("OpenSSH 10.0p1 Debian 7 (protocol 2.0)",
     ("openssh", "10.0p1", "debian", None, "7", False)),
    ("nginx 1.22.1~bpo11+1 something 1.22.1-9~deb12u1",
     ("nginx", "1.22.1", "debian", "bookworm", "9~deb12u1", True)),
])
def test_parse_banner_with_revision(text, expect):
    fp = dc.parse_service_banner(text)
    assert (fp["product"], fp["upstream"], fp["distro"], fp["release"],
            fp["revision"], fp["packaged"]) == expect


def test_parse_banner_without_revision_is_recognised_but_unmarked():
    fp = dc.parse_service_banner("Apache httpd 2.4.57 ((Debian))")
    assert fp["product"] == "apache" and fp["upstream"] == "2.4.57"
    assert fp["distro"] is None and fp["revision"] is None
    assert dc.parse_service_banner("OpenSSH 8.7 (protocol 2.0)")["upstream"] == "8.7"


def test_parse_banner_unknown_product():
    assert dc.parse_service_banner("Microsoft IIS httpd 10.0") is None
    assert dc.parse_service_banner("", "") is None


def test_raw_banner_supplies_the_revision_nmap_truncated():
    fp = dc.parse_service_banner("OpenSSH 9.2p1 (protocol 2.0)",
                                 "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10")
    assert fp["revision"] == "2+deb12u10" and fp["release"] == "bookworm"
    assert fp["upstream"] == "9.2p1"


def test_rpm_markers_recognised():
    fp = dc.parse_service_banner("OpenSSH 8.7p1-38.el9 (protocol 2.0)")
    assert fp["distro"] == "rhel" and fp["release"] == "el9" and fp["revision"] is None
    assert dc.parse_service_banner("nginx 1.24.0-1.amzn2023")["distro"] == "amazon"


@pytest.mark.parametrize("text,cve", [
    ("CVE-2024-6387\t8.1\thttps://vulners.com/cve/CVE-2024-6387", "CVE-2024-6387"),
    ("KS:SCANNER-SSH-OPENSSH_CVE_2026_123158_DETECT\t8.1\tx\t*EXPLOIT*", "CVE-2026-123158"),
    ("C7BEBF2B-9C42-5FA8-80E1-3D371B3C964F\t8.1\tx\t*EXPLOIT*", None),
    ("PACKETSTORM:173661\t9.8\tx\t*EXPLOIT*", None),
])
def test_extract_cve(text, cve):
    assert dc.extract_cve(text) == cve


# --------------------------------------------------------------------------- versions

@pytest.mark.parametrize("a,b,sign", [
    ("1:9.2p1-2+deb12u10", "1:9.2p1-2+deb12u3", 1),   # u10 > u3 (numeric, not lexical)
    ("1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u3", 0),
    ("1:9.2p1-2", "1:9.2p1-2+deb12u1", -1),
    ("1.0~rc1-1", "1.0-1", -1),                       # tilde sorts before everything
    ("2.4.57-2", "2.4.57-2~deb12u1", 1),
    ("1:10.0p1-7+deb13u4", "1:9.9p2-1", 1),
    ("1.0-1", "2:0.1-1", -1),                         # epoch wins
    ("1:8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.6", 1),
    ("9.2p1", "9.2p1-1", -1),
])
def test_compare_versions(a, b, sign):
    result = dc.compare_versions(a, b)
    assert (result > 0) - (result < 0) == sign
    back = dc.compare_versions(b, a)
    assert (back > 0) - (back < 0) == -sign


# --------------------------------------------------------------------------- snapshot extraction

def test_extract_only_wanted_packages_from_compact_snapshot(tmp_path):
    raw = tmp_path / "snap.json"
    raw.write_text(json.dumps(DEBIAN_SNAPSHOT, separators=(",", ":")))
    packages = dc.extract_debian_packages(str(raw), lambda n: bool(dc._WANTED_PKG_RE.match(n)))
    # the decoy key inside a description and the unwanted packages are ignored;
    # the LAST package in the file (no trailing separator) is still decoded
    assert sorted(packages) == ["openssh", "vsftpd"]
    ssh = packages["openssh"]
    assert ssh["repo"] == {"bookworm": "1:9.2p1-2+deb12u10", "trixie": "1:10.0p1-7+deb13u4"}
    assert "sid" not in ssh["cves"]["CVE-2023-38408"]
    assert ssh["cves"]["CVE-2024-6387"]["bookworm"] == {"s": "resolved", "f": "1:9.2p1-2+deb12u3"}
    assert ssh["cves"]["CVE-2026-60002"]["bookworm"]["n"] == "postponed"
    assert ssh["cves"]["CVE-2026-60002"]["trixie"]["n"] == "no-dsa"
    assert packages["vsftpd"]["cves"]["CVE-2021-3618"]["bookworm"]["f"] == "3.0.3-13"


# --------------------------------------------------------------------------- Debian

DEB12U10 = "OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)"


def _statuses(tags):
    return {ln.split("\t")[0]: tag["status"] for ln, tag in tags.items()}


def test_issue_1051_scenario_debian12_openssh(enricher):
    lines = [line("CVE-2023-38408", "9.8"), line("CVE-2024-6387"), line("CVE-2026-35386"),
             line("CVE-2026-123158"), line("CVE-2026-60002", "9.4"), line("CVE-2026-70001"),
             line("CVE-2016-0001"), line("CVE-2026-70002"), line("CVE-1999-9999"),
             line("KS:SCANNER-SSH-OPENSSH_CVE_2026_123158_DETECT", exploit=True),
             line("C7BEBF2B-9C42-5FA8-80E1-3D371B3C964F", exploit=True),
             line("PACKETSTORM:173661", "9.8", exploit=True)]
    tags = enricher.enrich_service(DEB12U10, "", lines)
    assert _statuses(tags) == {
        "CVE-2023-38408": dc.STATUS_FIXED,          # fixed since deb12u1
        "CVE-2024-6387": dc.STATUS_FIXED,           # regreSSHion, fixed since deb12u3
        "CVE-2026-35386": dc.STATUS_FIXED,          # fixed in deb12u10 itself
        "CVE-2026-123158": dc.STATUS_NOT_AFFECTED,  # Debian: unimportant
        "CVE-2026-60002": dc.STATUS_DEFERRED,       # the genuinely open one (postponed)
        "CVE-2026-70001": dc.STATUS_OPEN,           # open, no fix
        "CVE-2016-0001": dc.STATUS_NOT_AFFECTED,    # fixed_version "0"
        "CVE-2026-70002": dc.STATUS_UNVERIFIED,     # undetermined
        "CVE-1999-9999": dc.STATUS_UNVERIFIED,      # tracker never heard of it
        "KS:SCANNER-SSH-OPENSSH_CVE_2026_123158_DETECT": dc.STATUS_NOT_AFFECTED,  # CVE in the id
        "C7BEBF2B-9C42-5FA8-80E1-3D371B3C964F": dc.STATUS_EXPLOIT_REF,
        "PACKETSTORM:173661": dc.STATUS_EXPLOIT_REF,
    }
    tag = tags[line("CVE-2024-6387")]
    assert tag["host_version"] == "1:9.2p1-2+deb12u10"
    assert tag["fixed_version"] == "1:9.2p1-2+deb12u3"
    assert tag["package"] == "openssh" and tag["release"] == "bookworm"
    assert tag["tracker_url"] == "https://security-tracker.debian.org/tracker/CVE-2024-6387"
    assert tag["kev"] is True
    assert tags[line("CVE-2023-38408", "9.8")]["kev"] is False
    assert NoNetwork.calls == 0, "fresh caches must not touch the network"


def test_outdated_host_is_open_with_the_fix_named(enricher):
    tags = enricher.enrich_service("OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)", "",
                                   [line("CVE-2023-38408"), line("CVE-2024-6387")])
    assert _statuses(tags) == {"CVE-2023-38408": dc.STATUS_FIXED, "CVE-2024-6387": dc.STATUS_OPEN}
    tag = tags[line("CVE-2024-6387")]
    assert tag["fixed_version"] == "1:9.2p1-2+deb12u3" and "update the package" in tag["note"]


def test_package_upstream_wins_over_the_binary_version_string(enricher):
    # trixie's sshd announces 10.0p2 but the package is 1:10.0p1-7+deb13u4
    tags = enricher.enrich_service("OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)", "",
                                   [line("CVE-2026-35386"), line("CVE-2023-38408")])
    tag = tags[line("CVE-2026-35386")]
    assert tag["host_version"] == "1:10.0p1-7+deb13u4" and tag["status"] == dc.STATUS_FIXED
    assert tags[line("CVE-2023-38408")]["status"] == dc.STATUS_FIXED  # fixed upstream long before


def test_release_without_marker_is_inferred_from_base_revision(enricher):
    # first upload of a release has no +debN marker: "Debian 7" -> trixie (1:10.0p1-7...)
    tags = enricher.enrich_service("OpenSSH 10.0p1 Debian 7 (protocol 2.0)", "", [line("CVE-2026-35386")])
    tag = tags[line("CVE-2026-35386")]
    assert tag["release"] == "trixie" and tag["host_version"] == "1:10.0p1-7"
    assert tag["status"] == dc.STATUS_OPEN  # fix is in 7+deb13u3, host still on 7


@pytest.mark.parametrize("banner", [
    "OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)",   # release not in the tracker snapshot
    "OpenSSH 8.7 (protocol 2.0)",                      # no revision
    "OpenSSH 8.7p1-38.el9 (protocol 2.0)",             # RHEL: recognised, no tracker
    "Microsoft IIS httpd 10.0",                        # unknown product
    "",
])
def test_unverifiable_services_keep_current_behaviour(enricher, banner):
    lines = [line("CVE-2024-6387"), line("PACKETSTORM:173661", exploit=True)]
    tags = enricher.enrich_service(banner, "", lines)
    assert set(_statuses(tags).values()) == {dc.STATUS_UNVERIFIED}
    assert all(tag.get("note") for tag in tags.values())
    assert not any(dc.is_suppressed({"details": {"distro": tag}}) for tag in tags.values())


def test_exploit_refs_only_collapse_when_the_service_was_verified(enricher):
    # every CVE unknown to the tracker -> nothing was verified -> refs stay unverified
    tags = enricher.enrich_service(DEB12U10, "", [line("CVE-1999-9999"), line("EDB-ID:1", exploit=True)])
    assert set(_statuses(tags).values()) == {dc.STATUS_UNVERIFIED}


# --------------------------------------------------------------------------- Ubuntu

def test_ubuntu_release_inferred_and_classified(enricher):
    lines = [line(c) for c in UBUNTU_RECORDS] + [line("EDB-ID:51234", exploit=True)]
    tags = enricher.enrich_service("OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)", "", lines)
    assert _statuses(tags) == {
        "CVE-2024-6387": dc.STATUS_FIXED,          # fixed in exactly 3ubuntu0.10
        "CVE-2023-38408": dc.STATUS_FIXED,
        "CVE-2025-26465": dc.STATUS_OPEN,          # needs 3ubuntu0.11
        "CVE-2026-0001": dc.STATUS_DEFERRED,
        "CVE-2026-0002": dc.STATUS_NOT_AFFECTED,
        "CVE-2026-0003": dc.STATUS_UNVERIFIED,     # needs-triage is not a verdict
        "EDB-ID:51234": dc.STATUS_EXPLOIT_REF,
    }
    tag = tags[line("CVE-2025-26465")]
    assert tag["release"] == "jammy" and tag["host_version"] == "1:8.9p1-3ubuntu0.10"
    assert tag["tracker_url"] == "https://ubuntu.com/security/CVE-2025-26465"


def test_ubuntu_noble_host_uses_noble_statuses(enricher):
    tags = enricher.enrich_service("OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)", "",
                                   [line("CVE-2024-6387"), line("CVE-2025-26465"), line("CVE-2026-0001")])
    assert _statuses(tags) == {"CVE-2024-6387": dc.STATUS_FIXED, "CVE-2025-26465": dc.STATUS_OPEN,
                               "CVE-2026-0001": dc.STATUS_OPEN}
    assert tags[line("CVE-2024-6387")]["release"] == "noble"


def test_ubuntu_unknown_release_stays_unverified(enricher):
    tags = enricher.enrich_service("OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)", "",
                                   [line("CVE-2024-6387")])
    assert _statuses(tags) == {"CVE-2024-6387": dc.STATUS_UNVERIFIED}


# --------------------------------------------------------------------------- offline / failure

def test_offline_without_cache_degrades_to_unverified(tmp_path):
    NoNetwork.calls = 0
    enr = dc.DistroCveEnricher(str(tmp_path / "empty"), session=NoNetwork())
    for banner in (DEB12U10, "OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)"):
        tags = enr.enrich_service(banner, "", [line("CVE-2024-6387")])
        assert _statuses(tags) == {"CVE-2024-6387": dc.STATUS_UNVERIFIED}
    first = NoNetwork.calls
    assert first >= 1
    enr.enrich_service(DEB12U10, "", [line("CVE-2024-6387")])
    assert NoNetwork.calls == first, "a failed sync must back off, not retry on every host"


def test_stale_cache_is_used_when_offline(cache_dir):
    path = os.path.join(cache_dir, "debian_tracker.json")
    data = json.load(open(path))
    data["meta"]["fetched"] = time.time() - 30 * 86400
    json.dump(data, open(path, "w"))
    enr = dc.DistroCveEnricher(cache_dir, session=NoNetwork())
    tags = enr.enrich_service(DEB12U10, "", [line("CVE-2024-6387")])
    assert _statuses(tags) == {"CVE-2024-6387": dc.STATUS_FIXED}


def test_enricher_never_raises(enricher, monkeypatch):
    monkeypatch.setattr(enricher.debian, "resolve", lambda fp: 1 / 0)
    tags = enricher.enrich_service(DEB12U10, "", [line("CVE-2024-6387")])
    assert _statuses(tags) == {"CVE-2024-6387": dc.STATUS_UNVERIFIED}


# --------------------------------------------------------------------------- suppression + ranking

def _vuln(status=None, kev=False, severity="high"):
    details = {"distro": {"status": status, "kev": kev}} if status else {}
    return {"severity": severity, "details": details}


def test_suppression_rules():
    assert dc.is_suppressed(_vuln(dc.STATUS_FIXED))
    assert dc.is_suppressed(_vuln(dc.STATUS_NOT_AFFECTED))
    assert dc.is_suppressed(_vuln(dc.STATUS_EXPLOIT_REF))
    assert not dc.is_suppressed(_vuln(dc.STATUS_DEFERRED))
    assert not dc.is_suppressed(_vuln(dc.STATUS_OPEN))
    assert not dc.is_suppressed(_vuln(dc.STATUS_UNVERIFIED))
    assert not dc.is_suppressed(_vuln())                             # never enriched
    assert not dc.is_suppressed(_vuln(dc.STATUS_FIXED, kev=True))    # KEV is never hidden
    assert not dc.is_suppressed(_vuln(dc.STATUS_FIXED), enabled=False)  # feature switched off
    assert not dc.is_suppressed({"details": None}) and not dc.is_suppressed({})


def test_ranking_open_and_kev_outrank_suppressed():
    fixed_critical = _vuln(dc.STATUS_FIXED, severity="critical")
    open_medium = _vuln(dc.STATUS_DEFERRED, severity="medium")
    kev_low = _vuln(dc.STATUS_OPEN, kev=True, severity="low")
    plain_high = _vuln(severity="high")
    open_high = _vuln(dc.STATUS_OPEN, severity="high")
    ordered = sorted([fixed_critical, open_medium, plain_high, kev_low, open_high], key=dc.rank_key)
    assert ordered == [kev_low, open_high, plain_high, open_medium, fixed_critical]
    # with the feature off it is plain severity order again
    off = sorted([fixed_critical, open_medium, plain_high], key=lambda v: dc.rank_key(v, False))
    assert off == [fixed_critical, plain_high, open_medium]


# --------------------------------------------------------------------------- scanner + intelligence wiring

NMAP_OUTPUT = """Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for 192.168.1.50
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)
|_banner: SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10
| vulners:
|   cpe:/a:openbsd:openssh:9.2p1:
|     \tCVE-2023-38408\t9.8\thttps://vulners.com/cve/CVE-2023-38408
|     \tCVE-2026-60002\t9.4\thttps://vulners.com/cve/CVE-2026-60002
|_    \tC7BEBF2B-9C42-5FA8-80E1-3D371B3C964F\t8.1\thttps://vulners.com/githubexploit/C7BEBF2B\t*EXPLOIT*
80/tcp open  http    Apache httpd 2.4.57 ((Debian))
| banner: HTTP/1.1 400 Bad Request
| vulners:
|   cpe:/a:apache:http_server:2.4.57:
|_    \tCVE-2024-38476\t9.8\thttps://vulners.com/cve/CVE-2024-38476
"""


class _FakeIntel:
    def __init__(self):
        self.added = []

    def add_vulnerability(self, **kwargs):
        self.added.append(kwargs)


class _Shared:
    def __init__(self, datadir, enabled=True):
        self.datadir = datadir
        self.config = {"distro_cve_enrichment": enabled}
        self.network_intelligence = _FakeIntel()


def _scanner(shared):
    pytest.importorskip("rich")
    try:
        from actions.nmap_vuln_scanner import NmapVulnScanner
    except Exception as exc:  # heavy optional deps missing on a bare CI box
        pytest.skip("nmap_vuln_scanner not importable here: %s" % exc)
    scanner = NmapVulnScanner.__new__(NmapVulnScanner)
    scanner.shared_data = shared
    return scanner


def test_scanner_tags_findings_and_never_drops_them(cache_dir, monkeypatch):
    shared = _Shared(os.path.dirname(cache_dir))
    scanner = _scanner(shared)
    monkeypatch.setitem(dc._ENRICHERS, cache_dir, dc.DistroCveEnricher(cache_dir, session=NoNetwork()))

    banners = scanner.parse_service_banners(NMAP_OUTPUT)
    assert banners["22"] == {"version": "OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)",
                             "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10"}
    assert banners["80"]["version"] == "Apache httpd 2.4.57 ((Debian))"

    _, port_vulns, port_services = scanner.parse_vulnerabilities(NMAP_OUTPUT)
    tags = scanner.enrich_with_distro_tracker("192.168.1.50", NMAP_OUTPUT, port_vulns)
    scanner.feed_to_network_intelligence("192.168.1.50", port_vulns, port_services, tags)

    # nmap prefixes a script's last line with "|_"; the parser keeps the "_"
    added = {a["details"]["raw_output"].lstrip("_ \t").split("\t")[0]: a
             for a in shared.network_intelligence.added}
    assert len(added) == 4, "every finding is still stored"
    assert added["CVE-2023-38408"]["details"]["distro"]["status"] == dc.STATUS_FIXED
    assert added["CVE-2026-60002"]["details"]["distro"]["status"] == dc.STATUS_DEFERRED
    assert added["C7BEBF2B-9C42-5FA8-80E1-3D371B3C964F"]["details"]["distro"]["status"] == dc.STATUS_EXPLOIT_REF
    assert added["CVE-2024-38476"]["details"]["distro"]["status"] == dc.STATUS_UNVERIFIED  # no revision
    assert added["CVE-2023-38408"]["severity"] == "critical", "severity is not rewritten"
    json.dumps([a["details"] for a in shared.network_intelligence.added])  # must persist as JSON


def test_scanner_without_tags_is_unchanged(tmp_path):
    shared = _Shared(str(tmp_path), enabled=False)
    scanner = _scanner(shared)
    _, port_vulns, port_services = scanner.parse_vulnerabilities(NMAP_OUTPUT)
    scanner.feed_to_network_intelligence("192.168.1.50", port_vulns, port_services)
    assert len(shared.network_intelligence.added) == 4
    assert all("distro" not in a["details"] for a in shared.network_intelligence.added)
    assert dc.enrichment_enabled(shared) is False


def test_dashboard_counts_exclude_suppressed_only_when_enabled():
    try:
        from network_intelligence import NetworkIntelligence
    except Exception as exc:
        pytest.skip("network_intelligence not importable here: %s" % exc)
    vulns = {"a": _vuln(dc.STATUS_FIXED), "b": _vuln(dc.STATUS_DEFERRED),
             "c": _vuln(), "d": _vuln(dc.STATUS_FIXED, kev=True)}
    ni = NetworkIntelligence.__new__(NetworkIntelligence)
    ni.shared_data = _Shared("/nonexistent", enabled=True)
    assert ni.count_suppressed(vulns) == 1
    ni.shared_data = _Shared("/nonexistent", enabled=False)
    assert ni.count_suppressed(vulns) == 0


# --------------------------------------------------------------------------- web API

class _ApiIntel:
    """Stand-in for shared_data.network_intelligence with one patched Debian host."""

    def __init__(self, enabled):
        self.enabled = enabled

    def distro_suppression_enabled(self):
        return self.enabled

    def get_current_network_id(self):
        return "testnet"

    def get_vulnerabilities_for_network(self, status_filter="open"):
        def v(vid, text, severity, status=None, kev=False, note="n"):
            details = {"distro": {"status": status, "kev": kev, "note": note, "distro": "debian",
                                  "release": "bookworm", "package": "openssh",
                                  "host_version": "1:9.2p1-2+deb12u10"}} if status else {}
            return {"id": vid, "host": "203.0.113.50", "port": 22, "service": "ssh",
                    "vulnerability": text, "severity": severity, "details": details,
                    "discovered": "2026-11-07T10:00:00", "status": "active"}
        return {
            "f1": v("f1", "CVE-2023-38408 (Score: 9.8)", "critical", dc.STATUS_FIXED),
            "f2": v("f2", "CVE-2024-6387 (Score: 8.1)", "high", dc.STATUS_FIXED),
            "x1": v("x1", "PACKETSTORM:173661 9.8 *EXPLOIT*", "critical", dc.STATUS_EXPLOIT_REF),
            "n1": v("n1", "CVE-2026-123158 (Score: 8.1)", "high", dc.STATUS_NOT_AFFECTED, kev=True),
            "d1": v("d1", "CVE-2026-60002 (Score: 9.4)", "critical", dc.STATUS_DEFERRED,
                    note="Debian: <b>postponed</b>"),
            "u1": v("u1", "CVE-2020-0001 (Score: 5.0)", "medium"),
        }


def _grouped(monkeypatch, enabled):
    try:
        import webapp_modern as webapp
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip("webapp_modern unimportable here: %s" % exc)
    monkeypatch.setattr(webapp.auth_mgr, "is_configured", lambda: False)
    monkeypatch.setattr(webapp.shared_data, "network_intelligence", _ApiIntel(enabled))
    monkeypatch.setitem(webapp.shared_data.config, "network_intelligence_enabled", True)
    resp = webapp.app.test_client().get("/api/vulnerabilities/grouped?status=open")
    assert resp.status_code == 200
    data = resp.get_json()
    host = next(h for h in data["grouped_vulnerabilities"] if h["ip"] == "203.0.113.50")
    return data, host


def test_grouped_api_suppresses_tags_and_reranks(monkeypatch):
    data, host = _grouped(monkeypatch, enabled=True)
    assert data["distro_enrichment"] is True
    assert host["suppressed_count"] == 3 and host["total_vulnerabilities"] == 3
    assert host["severity_counts"] == {"critical": 1, "high": 1, "medium": 1, "low": 0}
    assert data["total_suppressed"] >= 3
    # nothing dropped: all six come back, visible first, KEV on top, suppressed last
    order = [v["id"] for v in host["vulnerabilities"]]
    assert order[:3] == ["n1", "d1", "u1"] and sorted(order[3:]) == ["f1", "f2", "x1"]
    by_id = {v["id"]: v for v in host["vulnerabilities"]}
    assert by_id["f1"]["suppressed"] and by_id["f1"]["distro_status"] == dc.STATUS_FIXED
    assert by_id["n1"]["kev"] and not by_id["n1"]["suppressed"]
    assert by_id["d1"]["distro"]["host_version"] == "1:9.2p1-2+deb12u10"
    assert by_id["u1"]["distro_status"] == dc.STATUS_UNVERIFIED and by_id["u1"]["distro"] is None
    assert all("_rank" not in v for v in host["vulnerabilities"])


def test_grouped_api_unchanged_when_feature_is_off(monkeypatch):
    data, host = _grouped(monkeypatch, enabled=False)
    assert data["distro_enrichment"] is False
    assert host["suppressed_count"] == 0 and host["total_vulnerabilities"] == 6
    assert host["severity_counts"]["critical"] == 3
    assert not any(v["suppressed"] for v in host["vulnerabilities"])
    assert [v["severity"] for v in host["vulnerabilities"]][:3] == ["critical"] * 3
