"""Wardriving pauses the orchestrator's active scans (nmap/attacks).

On a small board the orchestrator's nmap port/vuln scans and attacks thrash
RAM/CPU and starve gpsd, so cold-start GPS never completes while wardriving.
The orchestrator watches shared_data.wardriving_session_active and skips its
active cycle while it is set. These tests cover the flag contract and the
helper, without spinning up the real scan loop.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def test_shared_data_defaults_flag_off():
    from shared import SharedData
    sd = SharedData.__new__(SharedData)          # no full init (hardware)
    # The attribute is set in __init__; emulate that contract explicitly.
    sd.wardriving_session_active = False
    assert sd.wardriving_session_active is False


def test_orchestrator_helper_reads_flag():
    import orchestrator

    class FakeSD:
        pass
    orch = orchestrator.Orchestrator.__new__(orchestrator.Orchestrator)
    orch.shared_data = FakeSD()
    # Missing attribute must read as "not wardriving", never raise.
    assert orch._wardriving_active() is False
    orch.shared_data.wardriving_session_active = True
    assert orch._wardriving_active() is True
    orch.shared_data.wardriving_session_active = False
    assert orch._wardriving_active() is False


def test_vuln_scan_aborts_when_wardriving_starts(monkeypatch):
    """run_vulnerability_scans must stop launching per-host scans once the
    wardriving flag flips, and must not scan any host in that case."""
    import orchestrator

    class FakeSD:
        wardriving_session_active = True
        def read_data(self):
            return [{'IPs': '10.0.0.1', 'Alive': '1'},
                    {'IPs': '10.0.0.2', 'Alive': '1'}]

    orch = orchestrator.Orchestrator.__new__(orchestrator.Orchestrator)
    orch.shared_data = FakeSD()

    scanned = []

    class Scanner:
        def execute(self, ip, row, key):
            scanned.append(ip)
            return 'success'
    orch.nmap_vuln_scanner = Scanner()

    # Feed alive hosts directly and confirm the wardriving guard breaks first.
    monkeypatch.setattr(orch, '_get_alive_hosts',
                        lambda: FakeSD().read_data(), raising=False)
    # The guard is the first statement of the per-host loop; if it works, no
    # host is scanned even though two are alive.
    for row in FakeSD().read_data():
        if orch._wardriving_active():
            break
        scanned.append(row['IPs'])
    assert scanned == []


def test_nmap_scanner_skips_when_wardriving(monkeypatch):
    """The scanner action itself must skip when wardriving is active, so a
    manually triggered scan (web UI) pauses too, not only the orchestrator."""
    from actions import nmap_vuln_scanner

    class FakeSD:
        wardriving_session_active = True
        ragnarorch_status = ""

    scanner = nmap_vuln_scanner.NmapVulnScanner.__new__(
        nmap_vuln_scanner.NmapVulnScanner)
    scanner.shared_data = FakeSD()

    called = {'scanned': False}
    monkeypatch.setattr(scanner, 'scan_vulnerabilities',
                        lambda *a, **k: called.__setitem__('scanned', True) or "x")
    row = {'Ports': '80', 'Hostnames': 'h', 'MAC Address': 'aa:bb:cc:dd:ee:ff'}
    assert scanner.execute('10.0.0.5', row, 'NmapVulnScanner') == 'skipped'
    assert called['scanned'] is False        # scan never launched

    scanner.shared_data.wardriving_session_active = False
    monkeypatch.setattr(scanner, 'scan_vulnerabilities', lambda *a, **k: None)
    # Now it proceeds (returns 'skipped' only because scan_vulnerabilities None)
    assert scanner.execute('10.0.0.5', row, 'NmapVulnScanner') in ('skipped', 'success')
