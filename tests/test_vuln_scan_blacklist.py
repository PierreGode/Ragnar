"""The nmap vuln scanner must honour the scan blacklist before probing.

Previously the blacklist was only checked when writing results to the DB, so
blacklisted hosts were still probed. On printers with raw print (9100) open,
nmap -sV/banner probes print as garbage pages.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def _scanner(monkeypatch, config):
    from actions import nmap_vuln_scanner

    class FakeSD:
        wardriving_session_active = False
        ragnarorch_status = ""

    sd = FakeSD()
    sd.config = config
    scanner = nmap_vuln_scanner.NmapVulnScanner.__new__(
        nmap_vuln_scanner.NmapVulnScanner)
    scanner.shared_data = sd
    calls = []
    monkeypatch.setattr(scanner, 'scan_vulnerabilities',
                        lambda *a, **k: calls.append(a) or None)
    return scanner, calls


ROW = {'Ports': '9100', 'Hostnames': 'printer', 'MAC Address': 'AA:BB:CC:DD:EE:FF'}


def test_skips_blacklisted_ip(monkeypatch):
    scanner, calls = _scanner(monkeypatch, {'ip_scan_blacklist': ['10.0.0.12']})
    assert scanner.execute('10.0.0.12', ROW, 'NmapVulnScanner') == 'skipped'
    assert calls == []


def test_skips_blacklisted_mac(monkeypatch):
    scanner, calls = _scanner(monkeypatch, {'mac_scan_blacklist': ['aa:bb:cc:dd:ee:ff']})
    assert scanner.execute('10.0.0.12', ROW, 'NmapVulnScanner') == 'skipped'
    assert calls == []


def test_scans_when_blacklistcheck_off_or_not_listed(monkeypatch):
    scanner, calls = _scanner(monkeypatch, {'blacklistcheck': False,
                                            'ip_scan_blacklist': ['10.0.0.12']})
    scanner.execute('10.0.0.12', ROW, 'NmapVulnScanner')
    scanner.shared_data.config = {'ip_scan_blacklist': ['10.0.0.99']}
    scanner.execute('10.0.0.12', ROW, 'NmapVulnScanner')
    assert len(calls) == 2
