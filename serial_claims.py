#!/usr/bin/env python3
"""serial_claims.py — who holds which USB-serial port right now.

Several Ragnar components open serial ports on their own: the wardriving USB
monitor (GPS + ESP32 companions), the CYD serial bridge and the Meshtastic
link. Linux lets two processes/threads open the same tty, and when that
happens they split the byte stream and fight over the baud rate — the GPS
reports nothing, the CYD screen garbles, the Meshtastic handshake times out.

Each component registers a *provider*: a cheap callable returning the port(s)
it holds (or has reserved) at this moment. Anyone about to auto-detect or open
a port asks ``claimed(exclude_owner=<me>)`` and skips what others hold.
Providers are polled live, so there is no stale state to release on crash.
"""

import os
import threading

_lock = threading.Lock()
_providers = {}


def register(owner, provider):
    """Register (or replace) ``provider() -> str | iterable[str] | None`` for owner."""
    with _lock:
        _providers[owner] = provider


def unregister(owner):
    with _lock:
        _providers.pop(owner, None)


def _real(p):
    try:
        return os.path.realpath(p)
    except Exception:
        return p


def claims(exclude_owner=None):
    """{realpath: owner} for every port currently held, minus ``exclude_owner``.

    ``exclude_owner`` may be a string or a tuple; an owner ending in '*'
    matches by prefix (e.g. 'wardrive-*')."""
    if isinstance(exclude_owner, str):
        exclude_owner = (exclude_owner,)
    excl = tuple(exclude_owner or ())

    def _excluded(owner):
        return any(owner.startswith(e[:-1]) if e.endswith('*') else owner == e for e in excl)

    with _lock:
        items = list(_providers.items())
    out = {}
    for owner, fn in items:
        if _excluded(owner):
            continue
        try:
            val = fn()
        except Exception:
            continue
        if not val:
            continue
        for p in ([val] if isinstance(val, str) else val):
            if p and isinstance(p, str) and p.startswith('/dev/'):
                out.setdefault(_real(p), owner)
    return out


def claimed(exclude_owner=None):
    """Set of realpaths held by anyone except ``exclude_owner``."""
    return set(claims(exclude_owner))


def is_claimed(port, exclude_owner=None):
    return bool(port) and _real(port) in claimed(exclude_owner)


def _serial_console_reservation():
    """The read-only serial console's assigned port (data/serial_console.json).

    Registered here, at import, rather than only when serial_console starts, so
    the reservation holds in every process and regardless of startup order: a
    port wired to a switch's console must never be opened — let alone written
    to — by GPS / CYD / RoomScan auto-detection."""
    try:
        import json
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'data', 'serial_console.json')
        with open(path) as fh:
            port = (json.load(fh) or {}).get('port')
        return port if isinstance(port, str) else None
    except (OSError, ValueError, AttributeError):
        return None


register('serial-console', _serial_console_reservation)
