#!/usr/bin/env python3
"""mesh_manager.py — Tailscale-backed mesh layer for Ragnar.

Ragnar has always been a single-box tool: one Pi, one LAN, one web UI. That
works until the box you care about is in someone else's data centre and you are
not. This module makes a *mesh* of Ragnars addressable — every node reachable
by a stable private IP no matter what NAT, CGNAT or firewall sits in front of
it — and gives the local box a way to ask its peers how they are doing.

The transport is Tailscale (WireGuard). We deliberately do not reinvent it:
Tailscale already solves NAT traversal, key distribution, device authorization
and per-user ACLs, and it already ships an admin console that answers "is the
Jersey box up". What Tailscale does *not* know is anything about Ragnar — that
the box in Jersey saw a rogue AP, that its GPS lost fix, that its disk is 94%
full. That half is what this module adds.

Design notes
------------
* **Two ways to talk to tailscaled, in preference order.** The LocalAPI over the
  ``/var/run/tailscale/tailscaled.sock`` unix socket is a single round trip with
  no process spawn, which matters because ``whois`` sits on the web app's
  authentication hot path. The ``tailscale`` CLI is the fallback for when the
  socket has moved, permissions differ, or a future release changes the socket
  contract. Both are wrapped so callers never care which answered.

* **Identity comes from WireGuard, not from a shared secret.** Node-to-node API
  calls are authenticated by asking tailscaled who owns the source IP
  (``whois``) and checking the answer carries the mesh tag. There is no bearer
  token to mint, ship, rotate or leak: a caller either holds a WireGuard private
  key the coordination server vouches for, or it does not reach us at all. See
  ``caller_is_mesh_peer``.

* **Tag-owned, not user-owned.** Mesh nodes must be tagged (``tag:ragnar-mesh``
  by default). Tagging is what makes a node's key non-expiring — a user-owned
  node's key dies on the tailnet's expiry schedule (180 days by default) and the
  box silently drops off the tailnet with nobody on site to re-authenticate it.
  For a remote deployment that is the difference between a device and a brick.
  ``node_key_health`` surfaces this before it bites.

* **Everything degrades, nothing crashes.** Tailscale is optional. Every entry
  point returns a structured "not available" result rather than raising when the
  binary is missing, the daemon is down or the node is logged out, because
  Ragnar must keep working on a box that never joins a tailnet.

Self-test (no root, no tailnet, no network): ``python3 mesh_manager.py --self-test``.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

MODULE = 'mesh'

# Where tailscaled listens for LocalAPI calls on Linux. Tailscale's own client
# uses this path; the Host header value is a fixed sentinel, not a real name.
LOCALAPI_SOCKET = '/var/run/tailscale/tailscaled.sock'
LOCALAPI_HOST = 'local-tailscaled.sock'

# Default tag every Ragnar mesh node carries. Overridable via config so an
# operator running Ragnar inside a larger tailnet can scope it to their own tag.
DEFAULT_MESH_TAG = 'tag:ragnar-mesh'
DEFAULT_SHARE_TAG = 'tag:ragnar-share'

# One tailnet can hold several *completely separate* Ragnar meshes, told apart
# only by their tag. The default mesh is tag:ragnar-mesh; a second, isolated
# mesh is tag:ragnar-mesh-2, and so on. Separation is real because every trust
# check (caller_is_mesh_peer) and every peer scan filters on the exact tag, so a
# node tagged ragnar-mesh-2 is invisible to — and rejected by — a ragnar-mesh
# node even though they share a coordination server.
_MESH_TAG_PREFIX = 'tag:ragnar-mesh'
_SHARE_TAG_PREFIX = 'tag:ragnar-share'


def normalize_mesh_suffix(suffix):
    """Sanitise an operator-supplied mesh suffix to a DNS-label-safe fragment.

    The suffix becomes part of a Tailscale tag, which is a DNS label, so it is
    lowercased and reduced to [a-z0-9-]. An operator who pastes the whole thing
    ("ragnar-mesh-2", "tag:ragnar-mesh-2") gets the same result as typing "2".
    Returns '' for anything empty — i.e. the default mesh.
    """
    s = (str(suffix) if suffix is not None else '').strip().lower()
    for p in ('tag:ragnar-mesh-', 'ragnar-mesh-', 'tag:ragnar-mesh', 'ragnar-mesh'):
        if s.startswith(p):
            s = s[len(p):]
            break
    s = re.sub(r'[^a-z0-9-]+', '-', s).strip('-')
    return s[:32]


def mesh_tag_for_suffix(suffix):
    """The mesh tag for a suffix. Blank suffix ⇒ the default mesh tag."""
    s = normalize_mesh_suffix(suffix)
    return f'{_MESH_TAG_PREFIX}-{s}' if s else DEFAULT_MESH_TAG


def suffix_of_mesh_tag(mesh_tag):
    """Inverse of mesh_tag_for_suffix: the suffix a mesh tag carries ('' = default)."""
    tag = (mesh_tag or '').strip()
    prefix = _MESH_TAG_PREFIX + '-'
    return tag[len(prefix):] if tag.startswith(prefix) else ''


def share_tag_for_mesh_tag(mesh_tag):
    """The share-guest tag paired with a mesh tag, so guests stay mesh-scoped.

    ragnar-mesh ⇒ ragnar-share, ragnar-mesh-2 ⇒ ragnar-share-2. A fully custom
    mesh tag with no recognised prefix falls back to the default share tag.
    """
    s = suffix_of_mesh_tag(mesh_tag)
    return f'{_SHARE_TAG_PREFIX}-{s}' if s else DEFAULT_SHARE_TAG

# Port a peer Ragnar serves its web API on. Mesh polling assumes the mesh is
# homogeneous; a node on a different port can be overridden per-node in config.
DEFAULT_NODE_PORT = 8000

# ─────────────────────────────────────────────────────────────────────────────
# Viking names
# ─────────────────────────────────────────────────────────────────────────────
# Units are not clones. A mesh of boxes all called "raspberry" is one an
# operator cannot reason about out loud — every incident report needs a name
# nobody has to look up, the way a Flipper is a Flipper and not a serial number.
#
# The name is derived from the machine's own identity, so a unit is born with
# one: no configuration step, no central allocator, and the same box keeps the
# same name across reinstalls. Two lists rather than one because 48 names alone
# would collide inside a mesh of a dozen units often enough to be annoying —
# 48 x 24 gives 1,152 combinations, which pushes a first collision out past any
# mesh anyone is going to run.
# Given names for the auto-derived Viking identity. Overwhelmingly drawn from
# real Viking-age history and the Icelandic sagas — kings and jarls (Guthrum,
# Gorm, Horik, Ragnvald, Sigtrygg), explorers (Leif, Thorfinn, Ingvar), and
# saga figures (Egil, Skallagrim, Kjartan, Njal, Flosi) — with a few
# legendary/mythic names kept for flavour. Men first, women second; the split
# point is tracked by VIKING_FEMALE_NAMES below, so keep the two in step.
VIKING_MALE_NAMES = (
    'Ragnar', 'Bjorn', 'Ivar', 'Ubbe', 'Sigurd', 'Halfdan', 'Floki', 'Rollo',
    'Erik', 'Leif', 'Harald', 'Gunnar', 'Knut', 'Olaf', 'Sven', 'Torstein',
    'Ulf', 'Arne', 'Egil', 'Hakon', 'Vali', 'Orm', 'Trygve', 'Steinar',
    # Historical kings, jarls and Great Heathen Army leaders
    'Guthrum', 'Hastein', 'Eystein', 'Ottar', 'Horik', 'Gorm', 'Sigtrygg',
    'Magnus', 'Ragnvald', 'Godfred', 'Anlaf', 'Onund', 'Hemming', 'Styrbjorn',
    # Explorers and settlers
    'Thorfinn', 'Thorvald', 'Ingvar', 'Ketil', 'Ohthere', 'Naddod',
    # Jomsvikings and warriors
    'Palnatoki', 'Sigvaldi', 'Bui', 'Vagn', 'Toki', 'Thorkell', 'Thorgils',
    # Saga figures (Egils, Laxdaela, Njals, Eyrbyggja)
    'Skallagrim', 'Kveldulf', 'Thorolf', 'Snorri', 'Njal', 'Grim', 'Kjartan',
    'Bolli', 'Hrut', 'Skarphedin', 'Kari', 'Flosi', 'Hoskuld', 'Gizur',
    'Asgeir', 'Bard', 'Brand', 'Finn', 'Frodi', 'Geir', 'Hallvard', 'Hrafn',
    'Ingjald', 'Ospak', 'Ozur', 'Thorgeir', 'Thorir', 'Thormod', 'Vestein',
)

VIKING_FEMALE_NAMES_ORDERED = (
    'Lagertha', 'Astrid', 'Freydis', 'Sigrid', 'Thora', 'Yrsa', 'Ingrid',
    'Brynhild', 'Gudrun', 'Helga', 'Revna', 'Solveig', 'Torvi', 'Aslaug',
    'Randvi', 'Sigyn', 'Hilda', 'Runa', 'Eira', 'Frida', 'Idunn', 'Kara',
    'Nanna', 'Signy',
    # Historical queens and noblewomen
    'Gunnhild', 'Thyra', 'Estrid', 'Gyda', 'Ragnhild', 'Asa', 'Aud', 'Unn',
    # Saga women (Laxdaela, Njals, Egils, Eyrbyggja)
    'Thorgerd', 'Bergthora', 'Hallgerd', 'Melkorka', 'Thurid', 'Vigdis',
    'Thordis', 'Halldora', 'Katla', 'Groa', 'Steinunn', 'Thorunn', 'Jorunn',
    'Ingibjorg', 'Herdis', 'Alfhild', 'Bodil', 'Ragna', 'Svanhild', 'Gerd',
    'Hild', 'Grima', 'Ylva', 'Olof',
)

VIKING_NAMES = VIKING_MALE_NAMES + VIKING_FEMALE_NAMES_ORDERED

# The women's names within VIKING_NAMES — used to pick the matching header
# portrait (a unit renamed to a shieldmaiden shows the female Ragnar image).
VIKING_FEMALE_NAMES = frozenset(VIKING_FEMALE_NAMES_ORDERED)

# The ORIGINAL 48-name / 24-epithet pool, frozen exactly as it was. The
# auto-derived name (derive_viking_name) draws only from this so that no box
# already running Ragnar is renamed when the pool above grows: derivation is
# `hash % pool_size`, so changing the pool size would remap every seed. The
# larger VIKING_NAMES/VIKING_EPITHETS above are for the dice roll and manual
# choice — variety on demand, without disturbing anyone's inherited name. Do
# not reorder or resize these two; that is exactly what would rename units.
VIKING_NAMES_LEGACY = VIKING_MALE_NAMES[:24] + VIKING_FEMALE_NAMES_ORDERED[:24]
VIKING_EPITHETS_LEGACY = (
    'Ironside', 'the Boneless', 'Forkbeard', 'Bluetooth', 'the Red',
    'the Black', 'Longbeard', 'the Stout', 'the Fearless', 'Hardrada',
    'the Wanderer', 'Snake-eye', 'the Wise', 'Stormborn', 'the Silent',
    'Shieldbreaker', 'the Far-travelled', 'Frostbeard', 'the Keen',
    'Wolfsbane', 'the Unyielding', 'Seafarer', 'the Watchful', 'Ravenwing',
)


def is_female_viking(name):
    """True if the Viking name (full 'Yrsa Wolfsbane' or bare 'Yrsa') is one of
    the women's names."""
    if not name:
        return False
    return name.strip().split(' ', 1)[0] in VIKING_FEMALE_NAMES


# Bynames appended after the given name. Mostly genuine Viking-age epithets
# recorded in the chronicles and sagas — Ironside (Bjorn), the Boneless (Ivar),
# Forkbeard (Sven), Bluetooth (Harald), Fairhair, Bloodaxe (Erik), Flatnose
# (Ketil), the Deep-minded (Aud), Barefoot (Magnus), the Lucky (Leif),
# Skull-splitter (Thorfinn) — with a handful of flavour ones retained.
VIKING_EPITHETS = (
    'Ironside', 'the Boneless', 'Forkbeard', 'Bluetooth', 'the Red',
    'the Black', 'Longbeard', 'the Stout', 'the Fearless', 'Hardrada',
    'the Wanderer', 'Snake-eye', 'the Wise', 'the Silent', 'the Keen',
    'the Far-travelled', 'the Unyielding', 'Seafarer', 'the Watchful',
    'Shieldbreaker', 'Wolfsbane', 'Stormborn', 'Frostbeard', 'Ravenwing',
    # Attested historical bynames
    'Fairhair', 'Bloodaxe', 'the Good', 'the Great', 'the Old', 'Flatnose',
    'the Deep-minded', 'the Strong', 'Barefoot', 'the Tall', 'Longsword',
    'the Holy', 'the Mighty', 'Skull-splitter', 'the Lucky', 'the Peaceable',
    'the Proud', 'Half-troll', 'the Sharp', 'Longshanks', 'Crowbone',
    'the Generous', 'Bare-legs', 'the Quarrelsome',
)


def machine_seed():
    """A stable, unique-per-box seed for name derivation.

    /etc/machine-id is the right source: unique per installation, stable across
    reboots, and present on every systemd Linux. The fallbacks matter for the
    boards Ragnar actually runs on — a Pi's CPU serial survives an OS reimage,
    and the hostname is a last resort that at least differs between machines.
    """
    for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
        try:
            with open(path, 'r') as fh:
                value = fh.read().strip()
            if value:
                return value
        except OSError:
            continue
    try:
        with open('/proc/cpuinfo', 'r') as fh:
            for line in fh:
                if line.lower().startswith('serial'):
                    serial = line.split(':', 1)[1].strip()
                    if serial and serial.strip('0'):
                        return serial
    except OSError:
        pass
    return socket.gethostname()


def derive_viking_name(seed=None):
    """Deterministically turn a machine seed into 'Bjorn Ironside'.

    Same seed always yields the same name — a unit that is reinstalled comes
    back as itself rather than as a stranger.

    Draws from the FROZEN legacy pool (VIKING_*_LEGACY), not the larger roster,
    on purpose: the mapping is `hash % pool_size`, so growing the pool would
    remap every seed and rename boxes that never chose a name. Keeping the auto
    default on the original pool means no existing unit is ever renamed; the
    bigger historic roster is offered through the dice and manual selection.
    """
    import hashlib
    if seed is None:
        seed = machine_seed()
    digest = hashlib.sha256(str(seed).encode('utf-8')).digest()
    # Two independent slices so the given name and the epithet vary
    # independently; deriving both from one number would correlate them and
    # collapse the effective range back towards 48.
    name = VIKING_NAMES_LEGACY[int.from_bytes(digest[0:4], 'big') % len(VIKING_NAMES_LEGACY)]
    epithet = VIKING_EPITHETS_LEGACY[int.from_bytes(digest[4:8], 'big') % len(VIKING_EPITHETS_LEGACY)]
    return f'{name} {epithet}'


# ─────────────────────────────────────────────────────────────────────────────
# Raspberry Pi Connect
# ─────────────────────────────────────────────────────────────────────────────
# An access path that shares nothing with Tailscale: different vendor, different
# transport, different credentials. That independence is the whole value — if a
# tailnet is misconfigured, a key expires or tailscaled will not start, Pi
# Connect is still a way to reach a box that would otherwise need a site visit.
# Ragnar only ever *reports* its state; enabling it is the operator's call and
# `rpi-connect` requires an interactive browser sign-in that cannot be automated
# from here anyway.

def _parse_pi_connect(out):
    """Parse `rpi-connect status` text into running/signed_in flags.

    Real formats (rpi-connect 2.x):
      * off:                 "✗ Raspberry Pi Connect is not running, run rpi-connect on"
      * running, signed out: "Signed in: no\\nTo sign in, run rpi-connect signin"
      * running, signed in:  "Signed in: yes" plus screen-sharing / remote-shell lines

    Note the trap that bit the first cut: "Signed in: no" *contains* the
    substring "signed in", so a naive check reports a signed-out box as signed
    in. Key off the explicit yes/no instead.
    """
    low = out.lower()
    detail = out.splitlines()[0].strip() if out else 'No status reported.'
    if not out or 'not running' in low:
        return {'running': False, 'signed_in': False, 'detail': detail}
    signed_in = ('signed in: yes' in low or 'signed in as' in low
                 or 'signed-in: yes' in low)
    return {'running': True, 'signed_in': signed_in, 'detail': detail}


def _pi_connect_login_uids():
    """UIDs that have a live user-session runtime dir.

    rpi-connect is a *per-user* systemd service, so it can only be running in a
    session that has a `/run/user/<uid>`. A lingering or logged-in human user
    has one; root (Ragnar's own uid) does not have the *user's* session. Scanning
    here is what lets a root-run Ragnar see the login user's Connect state
    instead of its own empty one.
    """
    uids = []
    try:
        for name in os.listdir('/run/user'):
            if name.isdigit() and int(name) >= 1000:
                uids.append(int(name))
    except OSError:
        pass
    return sorted(uids)


def _read_pi_connect(exe, uid, timeout=8):
    """Run `rpi-connect status` in one login user's session (uid=None = ours).

    Root can step into any user's session; a non-root Ragnar can only read its
    own. Env is passed via `env` after `sudo` because sudo scrubs the
    environment, and the per-user D-Bus/runtime dir is what the tool needs.
    """
    if uid is not None and os.geteuid() == 0:
        runtime = f'/run/user/{uid}'
        cmd = ['sudo', '-n', f'-u#{uid}', 'env',
               f'XDG_RUNTIME_DIR={runtime}',
               f'DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus',
               exe, 'status']
    else:
        cmd = [exe, 'status']
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ((proc.stdout or '') + (proc.stderr or '')).strip()
    except (subprocess.TimeoutExpired, OSError):
        return ''


def pi_connect_status():
    """Report whether Raspberry Pi Connect is available as a backup way in.

    Returns {'installed', 'running', 'signed_in', 'user', 'detail'}. Never
    raises: this is a nice-to-have on non-Pi hardware where the tool is absent.

    The important subtlety: Connect is a per-user service, and Ragnar usually
    runs as root. Querying our own session would report "not signed in" on a box
    that is perfectly signed in as its login user — so we probe each login user's
    session and keep the best result.
    """
    result = {'installed': False, 'running': False, 'signed_in': False,
              'user': '', 'detail': 'Raspberry Pi Connect is not installed.'}
    exe = shutil.which('rpi-connect')
    if not exe:
        return result
    result['installed'] = True

    candidates = _pi_connect_login_uids()
    # Always also try our own session — covers a non-root Ragnar, or a box with
    # no /run/user entries where we are nonetheless the right context.
    candidates = candidates + [None]

    best = None
    for uid in candidates:
        out = _read_pi_connect(exe, uid)
        if not out:
            continue
        parsed = _parse_pi_connect(out)
        parsed['uid'] = uid
        if parsed['signed_in']:
            best = parsed          # signed in is the definitive win — stop here
            break
        if best is None or (parsed['running'] and not best['running']):
            best = parsed

    if best is None:
        result['detail'] = 'Installed, but status could not be read for any login user.'
        return result

    result['running'] = best['running']
    result['signed_in'] = best['signed_in']
    result['detail'] = best['detail']
    if best.get('uid'):
        try:
            import pwd
            result['user'] = pwd.getpwuid(best['uid']).pw_name
        except (KeyError, ImportError):
            result['user'] = f'uid {best["uid"]}'
    return result

# `tailscale status` is cheap but not free, and the UI polls. 5s is short enough
# that an operator clicking Refresh sees current truth, long enough that a busy
# dashboard does not fork a process per widget.
STATUS_TTL = 5.0

# whois sits on the auth path — one lookup per request would be a process spawn
# per request in the CLI fallback. Peer identity changes only when a node is
# re-tagged or re-keyed, so a minute of staleness is harmless.
WHOIS_TTL = 60.0

# A node key inside this many days of expiry is worth shouting about, because
# re-authenticating a remote node means sending a human to it.
KEY_EXPIRY_WARN_DAYS = 14

_status_cache = {'at': 0.0, 'data': None}
_whois_cache = {}
_cache_lock = threading.Lock()


class MeshUnavailable(Exception):
    """Tailscale is not installed, not running, or not logged in."""


# ─────────────────────────────────────────────────────────────────────────────
# Transport: talking to tailscaled
# ─────────────────────────────────────────────────────────────────────────────

def binary_path():
    """Absolute path to the `tailscale` CLI, or '' when it is not installed."""
    return shutil.which('tailscale') or ''


def installed():
    """True when the Tailscale client binary is present on this box."""
    return bool(binary_path())


def socket_present():
    """True when tailscaled's LocalAPI socket exists (daemon has run)."""
    try:
        return os.path.exists(LOCALAPI_SOCKET)
    except OSError:
        return False


def _run(args, timeout=15):
    """Run the tailscale CLI. Returns (rc, stdout, stderr); rc 127 if missing."""
    exe = binary_path()
    if not exe:
        return 127, '', 'tailscale is not installed'
    try:
        proc = subprocess.run([exe] + list(args), capture_output=True,
                              text=True, timeout=timeout,
                              # Nothing here runs on a terminal. Without this a
                              # subcommand that decides to prompt would block on
                              # a stdin that is never going to answer, and the
                              # only symptom would be a timeout that says
                              # nothing about the actual question being asked.
                              stdin=subprocess.DEVNULL)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, '', f'tailscale {" ".join(args)} timed out after {timeout}s'
    except OSError as exc:
        return 126, '', str(exc)


def local_api_get(path, timeout=5):
    """GET a LocalAPI path over the unix socket. Returns parsed JSON or None.

    Speaks just enough HTTP/1.1 to make one request and read one response —
    pulling in a full HTTP-over-UDS client for this would be a dependency for
    three lines of framing. Returns None on any failure so callers fall through
    to the CLI rather than dealing with transport errors.
    """
    if not socket_present():
        return None
    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(LOCALAPI_SOCKET)
        request = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: {LOCALAPI_HOST}\r\n'
            # tailscaled rejects browser-originated calls; this header marks the
            # request as a deliberate LocalAPI client rather than a stray fetch.
            'Sec-Tailscale: localapi\r\n'
            'Connection: close\r\n\r\n'
        )
        sock.sendall(request.encode('ascii'))
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b''.join(chunks)
    except (OSError, socket.timeout):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    head, _, body = raw.partition(b'\r\n\r\n')
    status_line = head.split(b'\r\n', 1)[0] if head else b''
    if b' 200' not in status_line:
        return None
    try:
        return json.loads(body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Status
# ─────────────────────────────────────────────────────────────────────────────

def raw_status(force=False):
    """Raw `tailscale status --json` as a dict, cached for STATUS_TTL seconds.

    Returns None when Tailscale is unavailable. LocalAPI first, CLI second.
    """
    now = time.time()
    with _cache_lock:
        if not force and _status_cache['data'] is not None:
            if now - _status_cache['at'] < STATUS_TTL:
                return _status_cache['data']

    data = local_api_get('/localapi/v0/status')
    if data is None:
        rc, out, _ = _run(['status', '--json'], timeout=10)
        if rc == 0 and out.strip():
            try:
                data = json.loads(out)
            except ValueError:
                data = None

    with _cache_lock:
        _status_cache['at'] = now
        _status_cache['data'] = data
    return data


def invalidate_cache():
    """Drop cached status/whois. Call after any state-changing operation."""
    with _cache_lock:
        _status_cache['at'] = 0.0
        _status_cache['data'] = None
        _whois_cache.clear()


def _primary_ip(ips):
    """Pick the IPv4 tailnet address from a node's address list."""
    for addr in ips or []:
        candidate = addr.split('/')[0]
        if ':' not in candidate:
            return candidate
    return (ips[0].split('/')[0] if ips else '')


def _days_until(timestamp):
    """Whole days from now until an RFC3339 timestamp; None if unparseable.

    Tailscale uses the zero time ("0001-01-01T00:00:00Z") to mean "never", which
    must not be reported as an expiry 700,000 days in the past.
    """
    if not timestamp or timestamp.startswith('0001-01-01'):
        return None
    # Python's fromisoformat did not accept a trailing 'Z' before 3.11, and
    # tailscaled emits sub-second precision of varying length.
    text = timestamp.replace('Z', '+00:00')
    text = re.sub(r'\.(\d{6})\d+', r'.\1', text)
    try:
        import datetime
        when = datetime.datetime.fromisoformat(text)
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.timezone.utc)
        delta = when - datetime.datetime.now(datetime.timezone.utc)
        return int(delta.total_seconds() // 86400)
    except (ValueError, ImportError):
        return None


def normalize_node(raw, is_self=False, magic_dns_suffix=''):
    """Flatten one `tailscale status` node record into Ragnar's node shape.

    The status JSON is verbose and version-sensitive; everything downstream
    (routes, UI, poller) speaks this smaller, stable dict instead.
    """
    ips = raw.get('TailscaleIPs') or []
    dns_name = (raw.get('DNSName') or '').rstrip('.')
    tags = list(raw.get('Tags') or [])
    key_expiry = raw.get('KeyExpiry') or ''
    expiry_days = _days_until(key_expiry)

    return {
        'id': raw.get('ID') or '',
        'hostname': raw.get('HostName') or '',
        'dns_name': dns_name,
        # Short name is what an operator actually recognises in a list.
        'short_name': dns_name.split('.')[0] if dns_name else raw.get('HostName', ''),
        'os': raw.get('OS') or '',
        'ips': [ip.split('/')[0] for ip in ips],
        'ip': _primary_ip(ips),
        'online': bool(raw.get('Online')),
        'active': bool(raw.get('Active')),
        'tags': tags,
        'exit_node': bool(raw.get('ExitNode')),
        'exit_node_option': bool(raw.get('ExitNodeOption')),
        'relay': raw.get('Relay') or '',
        # Direct connection vs DERP relay: CurAddr is set only when the peers
        # found a direct path. Useful when a remote node feels slow.
        'direct': bool(raw.get('CurAddr')),
        'rx_bytes': raw.get('RxBytes') or 0,
        'tx_bytes': raw.get('TxBytes') or 0,
        'last_seen': raw.get('LastSeen') or '',
        'created': raw.get('Created') or '',
        'key_expiry': key_expiry,
        'key_expiry_days': expiry_days,
        # A tagged node's key never expires — that is the whole point of tagging
        # a remote deployment, so surface the distinction explicitly.
        'key_expires': bool(key_expiry) and not key_expiry.startswith('0001-01-01'),
        'tagged': bool(tags),
        'is_self': is_self,
        'magic_dns_suffix': magic_dns_suffix,
    }


def status():
    """Mesh-level view of the tailnet.

    Always returns a dict — `available` is False with a human `reason` when
    Tailscale cannot answer, so callers never branch on exceptions.
    """
    if not installed():
        return {'available': False, 'installed': False, 'reason':
                'Tailscale is not installed on this node.',
                'backend_state': '', 'self': None, 'peers': []}

    data = raw_status()
    if data is None:
        return {'available': False, 'installed': True, 'reason':
                'tailscaled is not responding — the service may be stopped.',
                'backend_state': '', 'self': None, 'peers': []}

    backend = data.get('BackendState') or ''
    suffix = data.get('MagicDNSSuffix') or ''
    self_raw = data.get('Self') or {}
    self_node = normalize_node(self_raw, is_self=True, magic_dns_suffix=suffix) if self_raw else None

    peers = []
    for raw in (data.get('Peer') or {}).values():
        peers.append(normalize_node(raw, magic_dns_suffix=suffix))
    peers.sort(key=lambda n: (not n['online'], n['short_name'].lower()))

    # "Running" is the only state where traffic flows. NeedsLogin/NeedsMachineAuth
    # are the two an operator can actually act on, so pass the state through.
    return {
        'available': backend == 'Running',
        'installed': True,
        'reason': '' if backend == 'Running' else _backend_reason(backend, data),
        'backend_state': backend,
        'version': data.get('Version') or '',
        'magic_dns_suffix': suffix,
        'auth_url': data.get('AuthURL') or '',
        'self': self_node,
        'peers': peers,
    }


def _backend_reason(backend, data):
    """Human-readable explanation for a non-Running backend state."""
    if backend == 'NeedsLogin':
        url = data.get('AuthURL')
        return ('This node is not logged in to a tailnet.'
                + (f' Authenticate at {url}' if url else ''))
    if backend == 'NeedsMachineAuth':
        return 'Waiting for an admin to approve this device in the tailnet.'
    if backend == 'Stopped':
        return 'Tailscale is installed but stopped.'
    if backend == 'NoState':
        return 'tailscaled has not finished starting.'
    return f'Tailscale backend state is {backend or "unknown"}.'


def node_key_health(node):
    """Classify a node's key expiry: ('ok'|'warn'|'critical'|'expired', message).

    The failure this guards against is specific and expensive: a user-owned key
    expires, the node drops off the tailnet, and the only fix is physical access
    to a box in another country.
    """
    if not node:
        return 'ok', ''
    if not node.get('key_expires'):
        return 'ok', 'Key does not expire (tagged node).'
    days = node.get('key_expiry_days')
    if days is None:
        return 'ok', ''
    if days < 0:
        return 'expired', 'Node key has expired — this node needs re-authentication on site.'
    if days <= 3:
        return 'critical', f'Node key expires in {days} day(s). Tag this node so its key stops expiring.'
    if days <= KEY_EXPIRY_WARN_DAYS:
        return 'warn', f'Node key expires in {days} days. Tag this node to make it permanent.'
    return 'ok', f'Node key expires in {days} days.'


# ─────────────────────────────────────────────────────────────────────────────
# Identity: who is calling us
# ─────────────────────────────────────────────────────────────────────────────

def whois(ip, ttl=WHOIS_TTL):
    """Identify the tailnet node behind an IP. Returns a dict or None.

    Result shape: {'node', 'dns_name', 'tags', 'login', 'display_name'}.
    None means "not a tailnet address we can vouch for" — which callers on the
    auth path must treat as untrusted, never as an error to ignore.
    """
    if not ip:
        return None
    now = time.time()
    with _cache_lock:
        hit = _whois_cache.get(ip)
        if hit and now - hit['at'] < ttl:
            return hit['data']

    # The port is required by the API but irrelevant to node identity.
    data = local_api_get(f'/localapi/v0/whois?addr={ip}%3A0')
    if data is None:
        rc, out, _ = _run(['whois', '--json', ip], timeout=5)
        if rc == 0 and out.strip():
            try:
                data = json.loads(out)
            except ValueError:
                data = None

    result = None
    if data:
        node = data.get('Node') or {}
        profile = data.get('UserProfile') or {}
        name = (node.get('Name') or '').rstrip('.')
        result = {
            'node': node.get('ComputedName') or name.split('.')[0],
            'dns_name': name,
            'stable_id': node.get('StableID') or '',
            'tags': list(node.get('Tags') or []),
            'login': profile.get('LoginName') or '',
            'display_name': profile.get('DisplayName') or '',
        }

    with _cache_lock:
        _whois_cache[ip] = {'at': now, 'data': result}
    return result


def caller_is_mesh_peer(ip, mesh_tag=DEFAULT_MESH_TAG):
    """True when `ip` is a tailnet node carrying the mesh tag.

    This is the machine-authentication primitive: a peer Ragnar polling this
    node's API proves who it is by holding a WireGuard key the coordination
    server issued, and by being tagged into the mesh. Both halves matter —
    tailnet membership alone would let *any* device on the tailnet (a laptop, a
    phone, a contractor's box) drive Ragnar's full offensive toolset.

    Fails closed: no tailscaled, no answer, or no tag means False.
    """
    if not ip or not installed():
        return False
    # Cheap reject before spending a lookup: tailnet addresses are 100.64/10
    # (CGNAT space) or fd7a:115c:a1e0::/48. Anything else cannot be a peer.
    if not is_tailnet_addr(ip):
        return False
    identity = whois(ip)
    if not identity:
        return False
    return mesh_tag in identity.get('tags', [])


def is_tailnet_addr(ip):
    """True when `ip` falls inside Tailscale's IPv4 or IPv6 range."""
    if not ip:
        return False
    if ':' in ip:
        return ip.lower().startswith('fd7a:115c:a1e0')
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    # 100.64.0.0/10 — Tailscale allocates node addresses from this CGNAT block.
    return first == 100 and 64 <= second <= 127


# ─────────────────────────────────────────────────────────────────────────────
# Provisioning
# ─────────────────────────────────────────────────────────────────────────────

def _valid_auth_key(key):
    """Tailscale auth keys are `tskey-auth-...` / `tskey-client-...`."""
    return bool(key) and key.startswith('tskey-') and len(key) > 20


def join(auth_key, hostname='', tags=None, advertise_routes=None,
         enable_ssh=True, accept_routes=False, accept_dns=True, timeout=90,
         logout_first=False):
    """Join this node to a tailnet with a pre-authorized key.

    This is the unattended-deploy path: everything a remote node needs is
    supplied up front so a technician who plugs the box in never sees a login
    prompt. Returns (ok, message).

    `logout_first` switches tailnets: a node already logged into tailnet A
    cannot re-`up` straight onto tailnet B, so log out first. Harmless when the
    node is on no tailnet (logout is then a no-op).
    """
    if not installed():
        return False, 'Tailscale is not installed on this node.'
    if not _valid_auth_key(auth_key):
        return False, 'That does not look like a Tailscale auth key (expected tskey-...).'

    if logout_first:
        _run(['logout'], timeout=30)  # best-effort; a no-op if already logged out
        invalidate_cache()

    args = ['up', '--authkey', auth_key, '--reset']
    if hostname:
        args += ['--hostname', hostname]
    if tags:
        args += ['--advertise-tags', ','.join(tags)]
    if advertise_routes:
        args += ['--advertise-routes', ','.join(advertise_routes)]
        # A subnet router is useless without IP forwarding — enable it up front.
        ensure_ip_forwarding()
    if enable_ssh:
        # Tailscale SSH is the out-of-band way back in when Ragnar's own web UI
        # is wedged — the reason to deploy a Pi as a remote hands device at all.
        args += ['--ssh']
    args += ['--accept-routes' if accept_routes else '--accept-routes=false']
    args += ['--accept-dns' if accept_dns else '--accept-dns=false']

    rc, out, err = _run(args, timeout=timeout)
    invalidate_cache()
    if rc == 0:
        return True, 'Joined the tailnet.'
    detail = (err or out or '').strip()
    return False, _explain_up_failure(rc, detail)


def _explain_up_failure(rc, detail):
    """Turn `tailscale up` failure text into something actionable."""
    lowered = detail.lower()
    if rc == 124:
        return ('Timed out contacting the Tailscale coordination server. '
                'Check this node has outbound internet (UDP 41641 / TCP 443).')
    if 'invalid key' in lowered or 'unauthorized' in lowered:
        return 'The auth key was rejected — it may be expired, already used, or from another tailnet.'
    if 'requires' in lowered and 'tag' in lowered:
        return ('The auth key is not permitted to apply those tags. In the admin '
                'console, the key\'s owner must be listed in tagOwners for the tag.')
    if 'not logged in' in lowered:
        return 'Tailscale is not logged in and no valid auth key was supplied.'
    return detail or f'tailscale up failed (exit {rc}).'


def leave(timeout=30):
    """Log this node out of its tailnet. Returns (ok, message)."""
    if not installed():
        return False, 'Tailscale is not installed on this node.'
    rc, out, err = _run(['logout'], timeout=timeout)
    invalidate_cache()
    if rc == 0:
        return True, 'Logged out of the tailnet.'
    return False, (err or out or f'tailscale logout failed (exit {rc}).').strip()


def set_running(running, timeout=30):
    """Bring the tunnel up or down without logging out. Returns (ok, message)."""
    if not installed():
        return False, 'Tailscale is not installed on this node.'
    rc, out, err = _run(['up' if running else 'down'], timeout=timeout)
    invalidate_cache()
    if rc == 0:
        return True, 'Tunnel up.' if running else 'Tunnel down.'
    return False, (err or out or f'tailscale {"up" if running else "down"} failed (exit {rc}).').strip()


def https_available():
    """True when this tailnet can issue TLS certificates for MagicDNS names.

    `CertDomains` is populated by the control plane only when the tailnet has
    HTTPS Certificates switched on. Checking it is not an optimisation — with
    the feature disabled, `tailscale serve --https` does not fail, it *hangs*
    indefinitely waiting for a certificate that can never be issued (verified
    against a live tailnet; it blocks even with stdin closed, so it is not an
    unanswered prompt). Every caller must therefore check before invoking, or
    the only symptom a user ever sees is an unexplained timeout.
    """
    data = raw_status()
    if not data:
        return False
    return bool(data.get('CertDomains'))


HTTPS_SETUP_URL = 'https://login.tailscale.com/admin/dns'


def serve_web(port=DEFAULT_NODE_PORT, enable=True, use_https=False, timeout=120):
    """Expose (or stop exposing) Ragnar's web UI to the tailnet.

    Plain HTTP on port 80 is the default and the path most units use: it needs
    no certificate, is still tailnet-only, and works on every tailnet. Opting
    into `use_https` terminates TLS with a real certificate for the node's
    MagicDNS name — but only works once the tailnet has HTTPS Certificates
    enabled (see https_available), so it is the deliberate choice, not the
    default that hangs when the feature is off.

    Either way this is deliberately *not* `tailscale funnel`: funnel publishes to
    the open internet, which for a box full of offensive tooling would be an
    unambiguous mistake.

    The timeout is generous because a genuine first-time certificate issuance
    goes out to Let's Encrypt and is legitimately slow. That is only ever
    reached on the HTTPS path once the precondition below has passed.
    """
    if not installed():
        return False, 'Tailscale is not installed on this node.'

    # Stopping clears BOTH schemes, so "Stop" always fully unpublishes no matter
    # which one is live — the caller should not have to know what was published.
    if not enable:
        _run(['serve', '--https', '443', 'off'], timeout=30)
        _run(['serve', '--http', '80', 'off'], timeout=30)
        invalidate_cache()
        return True, 'Stopped publishing the web UI.'

    # Refuse rather than hang. See https_available().
    if use_https and not https_available():
        return False, (
            'HTTPS certificates are not enabled for this tailnet, so no '
            'certificate can be issued for this unit and the request would '
            f'hang rather than fail. Enable them at {HTTPS_SETUP_URL} '
            '(DNS → HTTPS Certificates), or publish over plain HTTP instead — '
            'still tailnet-only, just without TLS.')

    args = (['serve', '--bg', '--https', '443', f'http://127.0.0.1:{port}']
            if use_https else
            ['serve', '--bg', '--http', '80', f'http://127.0.0.1:{port}'])

    rc, out, err = _run(args, timeout=timeout)
    if rc == 0:
        scheme = 'HTTPS' if use_https else 'HTTP'
        host = magic_dns_name()
        where = f' at {"https" if use_https else "http"}://{host}' if host else ''
        return True, f'Web UI published to the tailnet over {scheme}{where}.'
    return False, _explain_serve_failure(rc, (err or out or '').strip(), use_https)


def magic_dns_name():
    """This node's MagicDNS name, e.g. 'ragnar-jersey.tailnet.ts.net'."""
    data = raw_status()
    if not data:
        return ''
    return ((data.get('Self') or {}).get('DNSName') or '').rstrip('.')


def serve_state():
    """Whether THIS unit is currently publishing its web UI, and at what URL.

    Publish state is *local* to each node — Tailscale does not report a peer's
    `serve` config in status — so a unit reports its own here and peers display
    it (that is the only way one Ragnar can know another is published). Read from
    `tailscale serve status --json`, whose shape is, e.g.::

        {"Web": {"host.tailnet.ts.net:80": {"Handlers": {"/": {"Proxy": "..."}}}}}

    Returns {'published', 'url', 'scheme', 'host'}. Any failure — not installed,
    not serving, unparseable — degrades to not-published rather than raising,
    because this is folded into a health report polled on a timer.
    """
    blank = {'published': False, 'url': '', 'scheme': '', 'host': ''}
    if not installed():
        return blank
    rc, out, _ = _run(['serve', 'status', '--json'], timeout=8)
    if rc != 0 or not (out or '').strip():
        return blank
    try:
        cfg = json.loads(out)
    except (ValueError, TypeError):
        return blank

    # Only an entry that actually proxies something counts as "the web UI is
    # published" — a bare TCP forward is not it. Prefer HTTPS (443) over HTTP
    # (80) if both somehow exist, so the link offered is the better one.
    best = None
    for key, entry in (cfg.get('Web') or {}).items():
        handlers = (entry or {}).get('Handlers') or {}
        if not any((h or {}).get('Proxy') for h in handlers.values()):
            continue
        host, _, port = key.rpartition(':')
        scheme = 'https' if port == '443' else 'http'
        if best is None or (scheme == 'https' and best['scheme'] != 'https'):
            best = {'host': host, 'scheme': scheme, 'port': port}
    if not best:
        return blank

    # Drop the port when it is the scheme default, so the link reads as the
    # clean friendly hostname the operator expects.
    is_default = ((best['scheme'] == 'https' and best['port'] == '443')
                  or (best['scheme'] == 'http' and best['port'] == '80'))
    url = f"{best['scheme']}://{best['host']}" + ('' if is_default else f":{best['port']}")
    return {'published': True, 'url': url, 'scheme': best['scheme'], 'host': best['host']}


def _explain_serve_failure(rc, detail, use_https):
    """Turn a `tailscale serve` failure into something the operator can act on."""
    lowered = detail.lower()
    if 'access denied' in lowered or 'permission denied' in lowered:
        return ('Tailscale refused the serve config because Ragnar is not '
                'running as root. Either run Ragnar as root (the packaged '
                'service does) or grant this user control with: '
                'sudo tailscale set --operator=$USER')
    if rc == 124 and use_https:
        return ('Timed out waiting for a TLS certificate. Confirm HTTPS '
                f'Certificates are enabled for the tailnet at {HTTPS_SETUP_URL}, '
                'then try again — or publish over plain HTTP instead.')
    if rc == 124:
        return 'Timed out talking to tailscaled. Check: systemctl status tailscaled'
    if 'funnel' in lowered:
        return detail
    return detail or f'tailscale serve failed (exit {rc}).'


FORWARDING_SYSCTL_FILE = '/etc/sysctl.d/99-ragnar-tailscale-forwarding.conf'


def ensure_ip_forwarding():
    """Enable (and persist) IPv4/IPv6 forwarding so this node can actually route
    for the subnets it advertises.

    A Tailscale subnet router with forwarding OFF is the classic silent failure:
    `tailscale up --advertise-routes` warns, the route shows in the admin
    console, peers route to it — and every forwarded packet is dropped. So we
    turn it on whenever routes are advertised. Best-effort (needs root); returns
    True on success. AP mode does not use forwarding, so enabling it is safe.
    """
    content = ("# Managed by Ragnar — required for Tailscale subnet routing\n"
               "net.ipv4.ip_forward = 1\n"
               "net.ipv6.conf.all.forwarding = 1\n")
    ok = True
    try:
        try:
            existing = open(FORWARDING_SYSCTL_FILE).read()
        except FileNotFoundError:
            existing = None
        if existing != content:
            with open(FORWARDING_SYSCTL_FILE, 'w') as fh:
                fh.write(content)
    except Exception:
        ok = False
    # Apply immediately without waiting for a reboot.
    for key in ('net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1'):
        try:
            subprocess.run(['sysctl', '-w', key], capture_output=True, timeout=10)
        except Exception:
            ok = False
    return ok


def advertise_routes(routes, timeout=30):
    """Advertise LAN subnets so the tailnet can reach the node's local network.

    This is what turns a remote Ragnar into a way into the whole site: with the
    route approved in the admin console, every device on the far-side LAN
    becomes addressable by its real IP from anywhere on the tailnet.

    Advertising a route is useless without IP forwarding, so we enable it here
    (persistently) whenever a non-empty route set is advertised.
    """
    if not installed():
        return False, 'Tailscale is not installed on this node.'
    value = ','.join(routes) if routes else ''
    fwd_ok = ensure_ip_forwarding() if routes else True
    rc, out, err = _run(['set', f'--advertise-routes={value}'], timeout=timeout)
    invalidate_cache()
    if rc == 0:
        if not value:
            return True, 'Stopped advertising subnet routes.'
        msg = 'Advertising ' + value
        if not fwd_ok:
            msg += ' (warning: could not enable IP forwarding — packets may not route)'
        msg += '. Approve the route in the Tailscale admin console for peers to use it.'
        return True, msg
    return False, (err or out or f'tailscale set failed (exit {rc}).').strip()


# ─────────────────────────────────────────────────────────────────────────────
# Peer polling: what Tailscale cannot tell us
# ─────────────────────────────────────────────────────────────────────────────

def peer_url(node, port=DEFAULT_NODE_PORT, path='/api/mesh/unit'):
    """Build the URL for a peer Ragnar's mesh endpoint."""
    host = node.get('ip') or node.get('dns_name')
    if not host:
        return ''
    if ':' in host and not host.startswith('['):
        host = f'[{host}]'
    return f'http://{host}:{port}{path}'


def poll_peer(node, port=DEFAULT_NODE_PORT, timeout=6, path='/api/mesh/unit'):
    """Ask one peer for its Ragnar health summary (or any mesh endpoint).

    Returns a dict with `reachable` plus whatever the peer reported. A peer that
    is online in Tailscale but unreachable here is the interesting case: the box
    has power and network but Ragnar itself is down.
    """
    url = peer_url(node, port, path)
    if not url:
        return {'reachable': False, 'error': 'no address'}
    try:
        import urllib.error
        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'Ragnar-Mesh'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return {'reachable': False, 'error': f'HTTP {resp.status}'}
            payload = json.loads(resp.read().decode('utf-8'))
        payload['reachable'] = True
        return payload
    except urllib.error.HTTPError as exc:
        # 401 is worth distinguishing: the node is alive and Ragnar answered,
        # we just are not tagged into its mesh (or it cannot see our tag).
        if exc.code == 401:
            return {'reachable': False, 'error': 'not authorized by peer — check the mesh tag'}
        return {'reachable': False, 'error': f'HTTP {exc.code}'}
    except Exception as exc:  # socket errors, timeouts, bad JSON
        return {'reachable': False, 'error': type(exc).__name__}


def diagnose_peer(ip, port=DEFAULT_NODE_PORT, timeout=6, path='/api/mesh/unit',
                  mesh_tag=DEFAULT_MESH_TAG):
    """Probe a peer and classify *why* it does or doesn't answer.

    `poll_peer` answers "did it work"; a red card that only says "Ragnar's API
    did not answer" is nearly useless because that one symptom covers at least
    four causes with four different fixes:

      * refused — nothing is listening on the port (app down / wrong port);
      * timeout — the port is filtered (ACL or host firewall), not closed;
      * auth    — the peer answered but rejected this unit's identity;
      * badbody — something else is on the port, not Ragnar.

    This runs the same request the poller does and returns a machine `category`
    plus a human `hint`, so the operator gets the actual fix instead of a guess.
    """
    result = {'ip': ip, 'port': port, 'url': '', 'reachable': False,
              'status': None, 'error': '', 'category': '', 'hint': ''}
    if not ip:
        result.update(category='address', error='no address',
                      hint='This peer has no tailnet address to probe.')
        return result

    host = f'[{ip}]' if (':' in ip and not ip.startswith('[')) else ip
    url = f'http://{host}:{port}{path}'
    result['url'] = url

    import urllib.error
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Ragnar-Mesh-Diagnose'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result['status'] = getattr(resp, 'status', None) or resp.getcode()
            body = resp.read(65536)
        if result['status'] == 200:
            try:
                json.loads(body.decode('utf-8'))
                result.update(reachable=True, category='ok',
                              hint='The peer answered normally — it is reachable and sharing data.')
            except (ValueError, UnicodeDecodeError):
                result.update(category='badbody',
                              hint=(f'Something is listening on port {port} at {ip}, but the reply '
                                    'was not Ragnar JSON — it is probably a different service. '
                                    'Check that this is the peer\'s Ragnar port.'))
        else:
            result.update(category='http', error=f'HTTP {result["status"]}',
                          hint=f'The peer returned HTTP {result["status"]}.')
        return result
    except urllib.error.HTTPError as exc:
        result['status'] = exc.code
        if exc.code == 401:
            result.update(category='auth', error='HTTP 401',
                          hint=('The peer answered but rejected this unit. It has login enabled and '
                                'did not recognize this unit as a tagged mesh peer. Confirm THIS '
                                f'unit carries {mesh_tag} (the peer authorizes the *caller* by tag), '
                                'and that tailscaled is running on the peer so it can identify it.'))
        else:
            result.update(category='http', error=f'HTTP {exc.code}',
                          hint=f'The peer returned HTTP {exc.code}.')
        return result
    except urllib.error.URLError as exc:
        reason = getattr(exc, 'reason', None)
        text = str(reason) if reason is not None else str(exc)
        result['error'] = text or 'URLError'
        low = text.lower()
        if isinstance(reason, ConnectionRefusedError) or 'refused' in low:
            result.update(category='refused',
                          hint=(f'Nothing is listening on port {port} at {ip}. The peer\'s Ragnar is '
                                'not running, crashed, or serves on a different port. On that box: '
                                '`sudo systemctl status ragnar`, and check its web port.'))
        elif isinstance(reason, TimeoutError) or 'timed out' in low or 'timeout' in low:
            result.update(category='timeout',
                          hint=(f'The connection to port {port} timed out — the port is filtered, not '
                                f'closed. Almost always your Tailscale ACL does not permit '
                                f'{mesh_tag}:{port} between units, or a host firewall (ufw/iptables) '
                                'blocks it. Tailnet membership alone does not open the port.'))
        else:
            result.update(category='network',
                          hint=f'Could not reach port {port} at {ip}: {result["error"]}.')
        return result
    except (TimeoutError, socket.timeout):
        result.update(category='timeout', error='timed out',
                      hint=(f'The connection to port {port} timed out — likely a Tailscale ACL or a '
                            f'host firewall blocking {mesh_tag}:{port} between units.'))
        return result
    except Exception as exc:
        result.update(category='error', error=type(exc).__name__,
                      hint=f'Unexpected error probing the peer: {type(exc).__name__}.')
        return result


def poll_mesh(nodes, port=DEFAULT_NODE_PORT, timeout=6, max_workers=8,
              include_offline=False):
    """Poll peers in parallel. Returns {node_id: health_dict}.

    Serial polling would make a 10-node mesh with one dead box take a full
    timeout per box; the UI would look hung, so every peer is polled at once.

    `include_offline` controls whether peers Tailscale currently marks offline
    are still polled. Tailscale's `Online` flag is *lazy*: a peer with no recent
    traffic flips to offline even though it is perfectly reachable, and it only
    flips back once something sends it traffic. If the mesh poller skips those
    peers, an idle unit is never polled, so it never exchanges traffic, so it
    stays "offline" forever — a chicken-and-egg that silently stops data sharing
    minutes after units go quiet. For the mesh we therefore poll tagged peers
    regardless of the Online flag: the poll itself is the keepalive that both
    tests the link and warms it. A genuinely dead box just costs one parallel
    timeout. (The default stays False so other callers keep the cheap behaviour.)
    """
    if include_offline:
        targets = [n for n in nodes if not n.get('is_self')]
    else:
        targets = [n for n in nodes if n.get('online') and not n.get('is_self')]
    results = {}
    if not targets:
        return results

    # Deliberately NOT concurrent.futures. Its ThreadPoolExecutor keys off a
    # process-global "shutdown" flag that flask-socketio/eventlet can trip while
    # the process is still very much alive; once set, every submit() raises
    # "cannot schedule new futures after interpreter shutdown" and the poller is
    # dead until a restart (silently — peers just read "Not polled"). Plain
    # threads have no such global, so they keep working for the life of the
    # process. Fan out in batches of `max_workers` so a large fleet never spawns
    # thousands of threads at once; each poll_peer has its own socket timeout.
    import threading
    lock = threading.Lock()

    def _worker(node):
        try:
            r = poll_peer(node, port, timeout)
        except Exception as exc:
            r = {'reachable': False, 'error': type(exc).__name__}
        with lock:
            results[node['id']] = r

    batch = max(1, int(max_workers))
    for i in range(0, len(targets), batch):
        threads = [threading.Thread(target=_worker, args=(n,), daemon=True)
                   for n in targets[i:i + batch]]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=timeout + 3)
    return results


def post_peer(node, path, payload, port=DEFAULT_NODE_PORT, timeout=20):
    """POST a JSON body to an arbitrary mesh endpoint on a peer.

    The generic write helper (command_peer is the monitor-toggle special case).
    Used by scan delegation to start/cancel a scan on a capable peer. Same
    WireGuard-identity auth as every other mesh call — the peer authorises the
    caller by mesh tag. Returns the peer's JSON reply plus `reachable`.
    """
    url = peer_url(node, port, path)
    if not url:
        return {'reachable': False, 'success': False, 'error': 'no address'}
    body = json.dumps(payload or {}).encode('utf-8')
    try:
        import urllib.error
        import urllib.request
        req = urllib.request.Request(
            url, data=body, method='POST',
            headers={'User-Agent': 'Ragnar-Mesh', 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            reply = json.loads(resp.read().decode('utf-8'))
        reply['reachable'] = True
        return reply
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return {'reachable': False, 'success': False,
                    'error': 'not authorized by peer — check the mesh tag'}
        try:
            reply = json.loads(exc.read().decode('utf-8'))
            reply.setdefault('success', False)
            reply['reachable'] = True
            return reply
        except Exception:
            return {'reachable': False, 'success': False, 'error': f'HTTP {exc.code}'}
    except Exception as exc:
        return {'reachable': False, 'success': False, 'error': type(exc).__name__}


def command_peer(node, feature, action, port=DEFAULT_NODE_PORT, timeout=15):
    """Ask one peer to start/stop a subsystem — the write side of the mesh.

    Polling reads; this actuates. It POSTs to the peer's `/api/mesh/control`,
    which authorises the *caller* by mesh tag (same WireGuard identity check the
    read path uses) and only accepts an allowlisted feature+action. The timeout
    is generous because starting a capture can take a couple of seconds.

    Returns the peer's JSON reply plus `reachable`, mirroring `poll_peer` so the
    caller handles a dead box and a refusal the same way.
    """
    url = peer_url(node, port, '/api/mesh/control')
    if not url:
        return {'reachable': False, 'success': False, 'error': 'no address'}
    body = json.dumps({'feature': feature, 'action': action}).encode('utf-8')
    try:
        import urllib.error
        import urllib.request
        req = urllib.request.Request(
            url, data=body, method='POST',
            headers={'User-Agent': 'Ragnar-Mesh', 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode('utf-8'))
        payload['reachable'] = True
        return payload
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return {'reachable': False, 'success': False,
                    'error': 'not authorized by peer — check the mesh tag'}
        try:
            payload = json.loads(exc.read().decode('utf-8'))
            payload.setdefault('success', False)
            payload['reachable'] = True
            return payload
        except Exception:
            return {'reachable': False, 'success': False, 'error': f'HTTP {exc.code}'}
    except Exception as exc:
        return {'reachable': False, 'success': False, 'error': type(exc).__name__}


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

_SAMPLE_STATUS = {
    'Version': '1.98.4',
    'BackendState': 'Running',
    'MagicDNSSuffix': 'tailnet.ts.net',
    'TailscaleIPs': ['100.78.0.7'],
    'Self': {
        'ID': 'nSELF', 'HostName': 'ragnar-home', 'DNSName': 'ragnar-home.tailnet.ts.net.',
        'OS': 'linux', 'TailscaleIPs': ['100.78.0.7', 'fd7a:115c:a1e0::c01:91'],
        'Online': True, 'KeyExpiry': '0001-01-01T00:00:00Z', 'Tags': ['tag:ragnar-mesh'],
    },
    'Peer': {
        'k1': {'ID': 'nJERSEY', 'HostName': 'ragnar-jersey',
               'DNSName': 'ragnar-jersey.tailnet.ts.net.', 'OS': 'linux',
               'TailscaleIPs': ['100.78.0.9'], 'Online': True, 'CurAddr': '1.2.3.4:41641',
               'Tags': ['tag:ragnar-mesh'], 'Relay': 'lhr', 'RxBytes': 10, 'TxBytes': 20},
        'k2': {'ID': 'nLAPTOP', 'HostName': 'laptop',
               'DNSName': 'laptop.tailnet.ts.net.', 'OS': 'macOS',
               'TailscaleIPs': ['100.78.0.3'], 'Online': False, 'KeyExpiry': ''},
    },
}


def _self_test():
    """Exercise the pure logic with no daemon, no network and no root."""
    failures = []

    def check(name, condition):
        print(f'  {"PASS" if condition else "FAIL"}  {name}')
        if not condition:
            failures.append(name)

    print('normalize_node')
    suffix = _SAMPLE_STATUS['MagicDNSSuffix']
    jersey = normalize_node(_SAMPLE_STATUS['Peer']['k1'], magic_dns_suffix=suffix)
    check('short_name strips the tailnet suffix', jersey['short_name'] == 'ragnar-jersey')
    check('primary IP prefers IPv4', jersey['ip'] == '100.78.0.9')
    check('direct connection detected from CurAddr', jersey['direct'] is True)
    check('mesh tag preserved', jersey['tags'] == ['tag:ragnar-mesh'])

    laptop = normalize_node(_SAMPLE_STATUS['Peer']['k2'], magic_dns_suffix=suffix)
    check('offline peer reported offline', laptop['online'] is False)
    check('untagged peer flagged untagged', laptop['tagged'] is False)

    self_node = normalize_node(_SAMPLE_STATUS['Self'], is_self=True, magic_dns_suffix=suffix)
    check('IPv6 kept alongside IPv4', len(self_node['ips']) == 2)
    check('zero KeyExpiry means never expires', self_node['key_expires'] is False)

    print('_days_until')
    check('zero time is not an expiry', _days_until('0001-01-01T00:00:00Z') is None)
    check('empty string is not an expiry', _days_until('') is None)
    check('nanosecond precision parses', _days_until('2099-01-01T00:00:00.123456789Z') is not None)
    check('past date is negative', (_days_until('2000-01-01T00:00:00Z') or 0) < 0)

    print('node_key_health')
    state, _ = node_key_health(self_node)
    check('tagged node is ok', state == 'ok')
    expired = dict(self_node, key_expires=True, key_expiry_days=-2)
    check('expired key is critical', node_key_health(expired)[0] == 'expired')
    soon = dict(self_node, key_expires=True, key_expiry_days=2)
    check('key expiring in 2 days is critical', node_key_health(soon)[0] == 'critical')
    warn = dict(self_node, key_expires=True, key_expiry_days=10)
    check('key expiring in 10 days warns', node_key_health(warn)[0] == 'warn')
    far = dict(self_node, key_expires=True, key_expiry_days=100)
    check('key expiring in 100 days is ok', node_key_health(far)[0] == 'ok')

    print('is_tailnet_addr')
    check('100.78.0.9 is a tailnet address', is_tailnet_addr('100.78.0.9') is True)
    check('100.64.0.1 is in range', is_tailnet_addr('100.64.0.1') is True)
    check('100.127.255.254 is in range', is_tailnet_addr('100.127.255.254') is True)
    check('100.128.0.1 is out of range', is_tailnet_addr('100.128.0.1') is False)
    check('100.63.0.1 is out of range', is_tailnet_addr('100.63.0.1') is False)
    check('192.168.1.5 is not a tailnet address', is_tailnet_addr('192.168.1.5') is False)
    check('tailnet IPv6 recognised', is_tailnet_addr('fd7a:115c:a1e0::c01:91') is True)
    check('other IPv6 rejected', is_tailnet_addr('fe80::1') is False)
    check('garbage rejected', is_tailnet_addr('not-an-ip') is False)
    check('empty rejected', is_tailnet_addr('') is False)

    print('auth key validation')
    check('real-looking key accepted', _valid_auth_key('tskey-auth-' + 'k' * 30) is True)
    check('short key rejected', _valid_auth_key('tskey-auth-x') is False)
    check('non-tskey rejected', _valid_auth_key('hunter2hunter2hunter2hunter2') is False)
    check('empty rejected', _valid_auth_key('') is False)

    print('peer_url')
    check('IPv4 peer URL', peer_url(jersey, 8000) == 'http://100.78.0.9:8000/api/mesh/unit')
    v6_only = dict(jersey, ip='fd7a:115c:a1e0::1')
    check('IPv6 peer URL is bracketed',
          peer_url(v6_only, 8000) == 'http://[fd7a:115c:a1e0::1]:8000/api/mesh/unit')
    check('addressless node yields no URL', peer_url({'ip': '', 'dns_name': ''}) == '')

    print('viking names')
    check('same seed always gives the same name',
          derive_viking_name('seed-a') == derive_viking_name('seed-a'))
    check('different seeds give different names',
          derive_viking_name('seed-a') != derive_viking_name('seed-b'))
    check('name has a given name and an epithet',
          len(derive_viking_name('seed-a').split(' ', 1)) == 2)
    check('given name comes from the pool',
          derive_viking_name('seed-a').split(' ', 1)[0] in VIKING_NAMES)
    check('epithet comes from the pool',
          derive_viking_name('seed-a').split(' ', 1)[1] in VIKING_EPITHETS)
    check('numeric seeds work', bool(derive_viking_name(12345)))
    check('empty seed still yields a name', bool(derive_viking_name('')))
    # A mesh is only legible if units are actually distinguishable, so measure
    # the spread rather than trusting the hash: 200 machine-ids should produce
    # a lot of distinct names, not a handful of favourites.
    sample = {derive_viking_name(f'machine-id-{i}') for i in range(200)}
    check(f'200 seeds yield >150 distinct names (got {len(sample)})', len(sample) > 150)
    check('name pools are collision-free',
          len(set(VIKING_NAMES)) == len(VIKING_NAMES)
          and len(set(VIKING_EPITHETS)) == len(VIKING_EPITHETS))
    check('female names are all in the given-name pool',
          VIKING_FEMALE_NAMES <= set(VIKING_NAMES))
    check('no name is both a man\'s and a woman\'s',
          not (set(VIKING_MALE_NAMES) & VIKING_FEMALE_NAMES))
    check(f'pool is large (got {len(VIKING_NAMES)} names x {len(VIKING_EPITHETS)} epithets)',
          len(VIKING_NAMES) >= 100 and len(VIKING_EPITHETS) >= 40)
    # The auto default must stay frozen so growing the pool never renames a box.
    check('legacy pool is unchanged in size (48 x 24)',
          len(VIKING_NAMES_LEGACY) == 48 and len(VIKING_EPITHETS_LEGACY) == 24)
    check('legacy pool is a subset of the full roster',
          set(VIKING_NAMES_LEGACY) <= set(VIKING_NAMES)
          and set(VIKING_EPITHETS_LEGACY) <= set(VIKING_EPITHETS))
    # Golden values: derive_viking_name must return exactly what it did before
    # the roster was expanded. If these change, existing units get renamed.
    _GOLDEN = {
        'seed-a': 'Knut Stormborn',
        'seed-b': 'Erik Ravenwing',
        'machine-id-1': 'Astrid Forkbeard',
        'abc123': 'Revna Bluetooth',
    }
    check('auto-derived names are unchanged (no box renamed)',
          all(derive_viking_name(s) == want for s, want in _GOLDEN.items()))

    print('pi connect')
    pc = pi_connect_status()
    check('status is always structured', set(pc) ==
          {'installed', 'running', 'signed_in', 'user', 'detail'})
    check('never raises on any host', isinstance(pc['installed'], bool))

    print('caller_is_mesh_peer fails closed')
    check('non-tailnet address rejected without a lookup',
          caller_is_mesh_peer('192.168.1.5') is False)
    check('empty address rejected', caller_is_mesh_peer('') is False)

    print()
    if failures:
        print(f'{len(failures)} check(s) FAILED:')
        for name in failures:
            print(f'  - {name}')
        return 1
    print('all checks passed')
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if '--self-test' in argv:
        return _self_test()
    if '--json' in argv:
        print(json.dumps(status(), indent=2))
        return 0

    state = status()
    if not state['installed']:
        print('Tailscale is not installed.')
        return 1
    if not state['available']:
        print(f'Tailscale unavailable: {state["reason"]}')
        return 1

    me = state['self'] or {}
    print(f'This node : {me.get("dns_name", "?")}  {me.get("ip", "")}')
    key_state, key_msg = node_key_health(me)
    if key_msg:
        print(f'Node key  : [{key_state}] {key_msg}')
    print(f'Peers     : {len(state["peers"])}')
    for peer in state['peers']:
        flag = 'online ' if peer['online'] else 'offline'
        tags = ','.join(peer['tags']) or '-'
        print(f'  {flag}  {peer["short_name"]:<24} {peer["ip"]:<16} {peer["os"]:<8} {tags}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
