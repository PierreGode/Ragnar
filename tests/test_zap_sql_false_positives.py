"""Regression tests for ZAP/Ragnar-Fuzz SQL false positive filtering."""

from advanced_vuln_scanner import AdvancedVulnScanner, VulnSeverity


def _scanner_stub():
    scanner = AdvancedVulnScanner.__new__(AdvancedVulnScanner)
    scanner.scan_results = {}
    return scanner


def _base_alert(**overrides):
    alert = {
        'alertRef': '40018-1',
        'risk': '2',
        'confidence': '2',
        'name': 'SQL Injection',
        'description': 'Potential SQL injection detected',
        'url': 'https://example.test/api/items?id=1',
        'method': 'GET',
        'param': 'id',
        'attack': "' OR '1'='1",
        'evidence': 'SQL syntax near ...',
        'reference': '',
        'pluginId': '40018',
        'cweid': '89',
        'wascid': '19',
    }
    alert.update(overrides)
    return alert


def test_parse_zap_alert_filters_explicit_false_positive_confidence():
    scanner = _scanner_stub()
    alert = _base_alert(confidence='False Positive')

    finding = scanner._parse_zap_alert(alert, 'scan-1')

    assert finding is None


def test_parse_zap_alert_filters_low_confidence_low_risk_sql_noise():
    scanner = _scanner_stub()
    alert = _base_alert(
        risk='1',
        confidence='1',
        attack='',
        evidence='',
        description='Possible SQL injection based on response pattern',
    )

    finding = scanner._parse_zap_alert(alert, 'scan-1')

    assert finding is None


def test_parse_zap_alert_keeps_higher_confidence_sql_alerts():
    scanner = _scanner_stub()
    alert = _base_alert(risk='2', confidence='3')

    finding = scanner._parse_zap_alert(alert, 'scan-1')

    assert finding is not None
    assert finding.severity == VulnSeverity.MEDIUM
    assert finding.scanner == 'zap'


def test_parse_zap_alert_keeps_non_sql_low_confidence_alerts():
    scanner = _scanner_stub()
    alert = _base_alert(
        name='Missing Anti-clickjacking Header',
        description='X-Frame-Options header is not set',
        risk='1',
        confidence='1',
        cweid='1021',
    )

    finding = scanner._parse_zap_alert(alert, 'scan-1')

    assert finding is not None
    assert finding.title == 'Missing Anti-clickjacking Header'


def test_sqli_reflection_requires_sql_error_signals():
    scanner = _scanner_stub()

    assert scanner._response_has_sql_error_signal('Hello, your input was reflected') is False
    assert scanner._response_has_sql_error_signal('You have an error in your SQL syntax') is True
