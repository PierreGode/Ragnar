"""Tests for parsing nuclei -stats output into a progress percentage.

The Adv Scan progress bar sat at 0% for the whole nuclei run because the
monitor loop set the status label but never turned nuclei's -stats output into
progress_percent. With -jsonl, nuclei emits JSON stats lines to stderr; this
parser pulls the completion percentage out of them.
"""

import os
import tempfile

from advanced_vuln_scanner import AdvancedVulnScanner


def _scanner():
    # Bypass __init__ — the parser only touches the filesystem.
    return AdvancedVulnScanner.__new__(AdvancedVulnScanner)


def _write(text):
    path = tempfile.mktemp(suffix='.err')
    with open(path, 'w') as f:
        f.write(text)
    return path


def test_parses_json_percent_field():
    s = _scanner()
    text = (
        '[INF] Templates loaded for current scan: 10617\n'
        '{"duration":"0:00:05","percent":"1","requests":"282","total":"18629"}\n'
        '{"duration":"0:00:30","percent":"4","requests":"759","total":"18629"}\n'
    )
    path = _write(text)
    try:
        assert s._parse_nuclei_progress(path) == 4  # most recent line wins
    finally:
        os.unlink(path)


def test_falls_back_to_requests_over_total():
    s = _scanner()
    path = _write('{"requests":"500","total":"1000"}')
    try:
        assert s._parse_nuclei_progress(path) == 50
    finally:
        os.unlink(path)


def test_falls_back_to_paren_percent_token():
    s = _scanner()
    path = _write('Requests: 300/1000 (30%)')
    try:
        assert s._parse_nuclei_progress(path) == 30
    finally:
        os.unlink(path)


def test_none_before_any_stats():
    s = _scanner()
    path = _write('[INF] loading templates...\n')
    try:
        assert s._parse_nuclei_progress(path) is None
    finally:
        os.unlink(path)


def test_none_when_file_missing():
    assert _scanner()._parse_nuclei_progress('/no/such/file.err') is None


def test_percent_is_capped_at_99():
    s = _scanner()
    path = _write('{"percent":"100"}')
    try:
        # Only true completion (set elsewhere) should read 100.
        assert s._parse_nuclei_progress(path) == 99
    finally:
        os.unlink(path)
