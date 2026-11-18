#!/usr/bin/env python3
"""Pytest wrapper for the vendored RDAP lookup self-test.

The canonical self-test (python/selftest_rdap_lookup.py) spins up loopback RDAP +
WHOIS fixture servers and drives the production rdap_lookup CLI against them — no
external network, no root. This wrapper runs that whole hermetic suite and asserts
every check passed, so the RDAP tool is covered in CI. Run it standalone with
`python3 python/selftest_rdap_lookup.py` for the full per-check report.
"""
import io
import contextlib
import os
import sys

_PYDIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python')
if _PYDIR not in sys.path:
    sys.path.insert(0, _PYDIR)


def test_rdap_lookup_selftest_passes():
    import selftest_rdap_lookup as S
    S.PASS = S.FAIL = 0
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = S.main()
    report = buf.getvalue().strip()
    assert rc == 0, report
    assert S.FAIL == 0, report
    assert S.PASS > 100, report          # the suite is ~189 checks; guard against a no-op run


def test_do_rdap_adapter_classifies_offline():
    """The in-app adapter imports the engine and runs the classifier with no
    network: a garbage target comes back as a successful tool run that reports an
    invalid classification, never an exception."""
    sys.path.insert(0, os.path.dirname(_PYDIR))        # repo root for network_diagnostics
    import network_diagnostics as nd
    assert nd.do_rdap('') == {'success': False, 'error': 'no target'}
    rec = nd.do_rdap('@@not a target@@')
    assert rec['success'] is True          # the tool ran
    assert rec.get('ok') is False
    assert rec.get('status') == 'invalid'
    assert 'report' in rec


if __name__ == '__main__':
    test_rdap_lookup_selftest_passes()
    test_do_rdap_adapter_classifies_offline()
    print('ok')
