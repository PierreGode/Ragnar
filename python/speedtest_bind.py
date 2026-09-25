#!/usr/bin/env python3
"""Run the python speedtest-cli with every socket pinned to one interface.

Why this exists
---------------
speedtest-cli can only bind a source *address* (`--source`), and binding an
address does **not** force egress. On a multi-homed host the kernel still routes
by destination, so the packet leaves via the default-route interface while
carrying the *other* interface's source IP. That is indistinguishable from
spoofing: an AP/router will drop a frame whose source IP is not the lease it
handed that station, and the test dies as:

    Cannot retrieve speedtest configuration
    ERROR: <urlopen error timed out>

`SO_BINDTODEVICE` binds the *device*, which is what actually pins traffic to a
NIC. speedtest-cli exposes no such option, so patch `socket` before importing it.

Verified reality check (this is not theoretical): source-binding to docker0's
address reaches the internet fine — the packet simply leaves via wlan0 — so
`--source` succeeding proves nothing about the interface under test.

Needs CAP_NET_RAW (SO_BINDTODEVICE); Ragnar's service runs as root.

    python3 speedtest_bind.py <iface> [speedtest-cli args...]
"""

import socket
import sys


def bind_all_sockets_to(iface):
    """Force every socket created from here on out onto `iface`."""
    dev = iface.encode() + b'\0'
    real_socket = socket.socket

    class _BoundSocket(real_socket):
        def __init__(self, family=-1, type=-1, proto=-1, fileno=None):
            super().__init__(family, type, proto, fileno)
            try:
                self.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev)
            except OSError:
                # Not fatal here: a probe/connect that needed the bind will fail
                # loudly on its own, which is a clearer error than dying here.
                pass

    socket.socket = _BoundSocket


def main(argv):
    if not argv:
        sys.stderr.write('usage: speedtest_bind.py <iface> [speedtest-cli args]\n')
        return 2
    iface, rest = argv[0], argv[1:]
    bind_all_sockets_to(iface)
    try:
        import speedtest       # noqa: E402  (must follow the socket patch)
    except ImportError:
        sys.stderr.write('the python speedtest module is not importable\n')
        return 3
    # speedtest.main() reads sys.argv itself.
    sys.argv = ['speedtest-cli'] + rest
    speedtest.main()
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
