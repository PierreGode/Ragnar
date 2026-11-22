"""Target port-resolution for ZAP scans.

ZAP hard-validates reachability and would assume :80 for a bare host, failing
on an HTTPS-only or alt-port service where Nuclei (which never validated) just
runs. `_resolve_web_target` probes common web ports and rewrites the target to
a port that's actually listening.
"""
from __future__ import annotations

import sys
import os
import socket
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _make_scanner():
    from advanced_vuln_scanner import AdvancedVulnScanner
    return AdvancedVulnScanner.__new__(AdvancedVulnScanner)


def _listener(port_hint=0):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port_hint))
    srv.listen(4)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def loop():
        srv.settimeout(0.4)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                c.close()
            except socket.timeout:
                continue
            except OSError:
                break
    threading.Thread(target=loop, daemon=True).start()
    return srv, port, stop


def test_resolves_bare_host_to_live_alt_port():
    s = _make_scanner()
    srv, port, stop = _listener()
    s._WEB_PROBE_PORTS = (80, port)
    try:
        out = s._resolve_web_target("http://127.0.0.1")
    finally:
        stop.set()
        srv.close()
    assert out == f"http://127.0.0.1:{port}"


def test_respects_explicit_port():
    s = _make_scanner()
    # Even if nothing is listening, an operator-pinned port is left untouched.
    assert s._resolve_web_target("http://127.0.0.1:9999") == "http://127.0.0.1:9999"


def test_leaves_target_unchanged_when_nothing_listening():
    s = _make_scanner()
    # A port range that (almost certainly) has nothing bound on loopback.
    s._WEB_PROBE_PORTS = (7, 9)
    assert s._resolve_web_target("http://127.0.0.1") == "http://127.0.0.1"


def test_prefers_canonical_80_when_multiple_open():
    s = _make_scanner()
    srv80, p80, stop80 = _listener(80) if os.geteuid() == 0 else (None, None, None)
    srv_alt, p_alt, stop_alt = _listener()
    try:
        if srv80 is None:
            # Can't bind :80 without privileges — just assert alt-port resolution.
            s._WEB_PROBE_PORTS = (p_alt,)
            assert s._resolve_web_target("http://127.0.0.1") == f"http://127.0.0.1:{p_alt}"
        else:
            s._WEB_PROBE_PORTS = (80, p_alt)
            # 80 is canonical for http -> no :port suffix
            assert s._resolve_web_target("http://127.0.0.1") == "http://127.0.0.1"
    finally:
        if stop_alt:
            stop_alt.set()
        srv_alt and srv_alt.close()
        if stop80:
            stop80.set()
        srv80 and srv80.close()


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
