"""Network diagnostics endpoints for Ragnar.

Registers a set of /api/net/* routes that wrap standard Linux networking
tools (ping, traceroute, mtr, whois, speedtest, arp-scan, lldpctl, ethtool,
ip, nmcli) and surface the results as JSON for the Network > Diagnostics /
Switch & L2 / Interfaces sub-tabs in the web UI.

The whole module is self-contained (no import from webapp_modern) to avoid a
circular import: webapp_modern imports register_network_diagnostics() and calls
it once with the Flask app. Auth is enforced globally by webapp_modern's
before_request handler, so these routes inherit it automatically.

The Ragnar service runs as root, so the wrapped tools are invoked directly
(no sudo); they still work if the app is ever run as a normal user with the
appropriate sudoers entries.
"""

import bisect
import json
import re
import secrets
import shutil
import subprocess
import ipaddress
import os
import sys
import threading
import time
import socket
import ssl
import tempfile
import urllib.parse
from datetime import datetime, timezone, timedelta

import bgp_speaker
import ldap_watch
import path_asymmetry
import tls_watch
import wifi_analyzer
import wifi_defense
import report_common
import bt_scanner
import sdr_spectrum
import zigbee_scan
from ldap_watch import do_ldap_watch
from tls_watch import do_tls_watch

try:
    from flask import request, jsonify
except Exception:  # pragma: no cover - flask always present in the app
    request = None
    jsonify = None

# --------------------------------------------------------------------------
# Input validation — these endpoints run system commands, so user-supplied
# targets/interfaces are strictly validated. Commands are always invoked with
# an argument list (never shell=True), and a leading '-' is rejected so a
# target can't be smuggled in as a tool flag.
# --------------------------------------------------------------------------

_TARGET_RE = re.compile(r'^[A-Za-z0-9._:\-/]{1,255}$')
_IFACE_RE = re.compile(r'^[A-Za-z0-9._@\-]{1,32}$')


def _valid_target(t):
    return bool(t and isinstance(t, str) and t[0] != '-' and _TARGET_RE.match(t))


def _valid_iface(i):
    return bool(i and isinstance(i, str) and i[0] != '-' and _IFACE_RE.match(i))


def _clamp_int(val, default, lo, hi):
    try:
        n = int(val)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _run(cmd, timeout=30, env=None):
    """Run a command (list of args) and return {rc, out, err}.

    Never raises: missing binary -> rc 127, timeout -> rc 124.
    """
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=env)
        return {'rc': r.returncode, 'out': r.stdout, 'err': r.stderr}
    except FileNotFoundError:
        return {'rc': 127, 'out': '',
                'err': f"{cmd[0]}: not installed (run the Ragnar installer/update to add it)"}
    except subprocess.TimeoutExpired:
        return {'rc': 124, 'out': '', 'err': f"{cmd[0]}: timed out after {timeout}s"}
    except Exception as e:  # pragma: no cover - defensive
        return {'rc': 1, 'out': '', 'err': str(e)}


def _have(binname):
    return shutil.which(binname) is not None


def _have_scapy():
    """True if the Scapy Python module is importable (not just the CLI). Scapy is
    optional — only the scanners' end-to-end self-test leg uses it — so this is a
    lightweight spec check that doesn't pay Scapy's slow import."""
    try:
        import importlib.util
        return importlib.util.find_spec('scapy') is not None
    except Exception:
        return False


# --------------------------------------------------------------------------
# Diagnostics: ping / traceroute / mtr / whois / speedtest
# --------------------------------------------------------------------------

def do_ping(target, count=4, interface=None):
    """Ping `target`. `interface`, if given, pins the probes to that NIC
    (ping -I <device>), so a multi-homed box tests the link the caller chose
    rather than whatever holds the default route."""
    count = _clamp_int(count, 4, 1, 15)
    deadline = count + 3
    cmd = ['ping', '-n', '-c', str(count), '-w', str(deadline)]
    if interface:
        if not _valid_iface(interface) or interface not in _list_iface_names(include_virtual=True):
            return {'success': False, 'output': '', 'summary': {},
                    'error': f'Unknown interface: {interface}'}
        cmd += ['-I', interface]
    res = _run(cmd + [target], timeout=deadline + 5)
    out = res['out'] or res['err']
    summary = {}
    m = re.search(r'(\d+) packets transmitted, (\d+) received.*?([\d.]+)% packet loss', out, re.S)
    if m:
        summary['transmitted'] = int(m.group(1))
        summary['received'] = int(m.group(2))
        summary['loss_pct'] = float(m.group(3))
    m = re.search(r'=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms', out)
    if m:
        summary['rtt_min'] = float(m.group(1))
        summary['rtt_avg'] = float(m.group(2))
        summary['rtt_max'] = float(m.group(3))
    # ping returns non-zero on 100% loss; treat "ran" as success and let the
    # summary/output convey the result.
    if res['rc'] == 127:
        return {'success': False, 'output': '', 'summary': {},
                'error': 'ping is not installed. Click Install to add it.',
                'missing_tool': 'ping'}
    return {'success': True, 'output': out.strip(), 'summary': summary, 'error': None}


def do_traceroute(target, max_hops=20):
    max_hops = _clamp_int(max_hops, 20, 1, 30)
    res = _run(['traceroute', '-n', '-q', '1', '-w', '2', '-m', str(max_hops), target],
               timeout=max_hops * 3 + 10)
    if res['rc'] == 127:
        return {'success': False, 'output': '',
                'error': 'traceroute is not installed. Click Install to add it.',
                'missing_tool': 'traceroute'}
    return {'success': True, 'output': (res['out'] or res['err']).strip(), 'error': None}


def _local_ipv4_addrs():
    """Set of this host's IPv4 addresses (no CIDR), across all interfaces.
    Used to validate an mtr source ('start point') binding."""
    addrs = set()
    for name in _list_iface_names(include_virtual=True):
        v4, _ = _iface_addrs(name)
        for a in v4:
            addrs.add(a.split('/')[0])
    return addrs


def do_mtr(target, count=5, source=None):
    """Snapshot per-hop loss/latency from this host to `target` over `count`
    probe cycles. `source`, if given, binds the trace to one of this host's
    local IPv4 addresses (mtr -a) so a multi-homed box can choose which
    interface/path the probes leave from."""
    count = _clamp_int(count, 5, 1, 20)
    cmd = ['mtr', '-n', '-r', '-c', str(count)]
    if source:
        try:
            ipaddress.ip_address(source)
        except ValueError:
            return {'success': False, 'error': f'Invalid source IP: {source}'}
        local = _local_ipv4_addrs()
        if source not in local:
            valid = ', '.join(sorted(local)) or 'none'
            return {'success': False,
                    'error': f'Source {source} is not a local address on this host '
                             f'(mtr can only originate from a local IP). Valid: {valid}'}
        cmd += ['-a', source]
    cmd += ['-j', target]
    res = _run(cmd, timeout=count * 3 + 15)
    if res['rc'] == 127:
        return {'success': False,
                'error': 'mtr is not installed. Click Install to add it.',
                'missing_tool': 'mtr'}
    hops = []
    try:
        data = json.loads(res['out'])
        for h in data.get('report', {}).get('hubs', []):
            hops.append({
                'hop': h.get('count'),
                'host': h.get('host'),
                'loss_pct': h.get('Loss%'),
                'sent': h.get('Snt'),
                'last': h.get('Last'),
                'avg': h.get('Avg'),
                'best': h.get('Best'),
                'worst': h.get('Wrst'),
                'stdev': h.get('StDev'),
            })
        return {'success': True, 'hops': hops}
    except (ValueError, KeyError) as e:
        return {'success': False, 'error': f'could not parse mtr output: {e}',
                'output': res['out'] or res['err']}


def do_whois(target):
    res = _run(['whois', target], timeout=25)
    if res['rc'] == 127:
        return {'success': False, 'output': '',
                'error': 'whois is not installed. Click Install to add it.',
                'missing_tool': 'whois'}
    return {'success': True, 'output': (res['out'] or res['err']).strip(), 'error': None}


def do_ip_intel(target, offline=False):
    """Attribute an IP address — country, ASN, network owner, abuse contact.

    Thin wrapper over ip_intel.lookup(); see that module for why no street
    address is ever reported. Accepts a hostname too, resolving it first, so the
    UI can take either."""
    import ip_intel
    ip = str(target).strip()
    resolved_from = None
    if ip_intel.ip_scope(ip)[0] == 'invalid':
        try:                                  # maybe it's a hostname
            resolved = socket.gethostbyname(ip)
            resolved_from, ip = ip, resolved
        except (OSError, socket.gaierror):
            return {'success': False, 'error': f'Not a valid IP or resolvable host: {target}'}
    try:
        rec = ip_intel.lookup(ip, allow_network=not offline)
    except Exception as exc:
        return {'success': False, 'error': f'lookup failed: {exc}'}
    rec['success'] = True
    rec['report'] = ip_intel.report(rec)
    if resolved_from:
        rec['resolved_from'] = resolved_from
    return rec


def _probe_egress(iface, timeout=4.0):
    """Can `iface` actually reach the internet? True / False / None (unknown).

    Binds the probe socket to the *device* (SO_BINDTODEVICE) and TCP-connects to
    a public endpoint, so the answer reflects that NIC and nothing else. This is
    the only trustworthy signal we have:
      - a default route only says a gateway is configured, not that it works;
      - source-address binding proves nothing at all — a probe bound to docker0's
        address reaches the internet fine, because the packet just leaves via the
        default-route interface wearing that address.
    Returns None when the bind is not permitted (needs CAP_NET_RAW), so callers
    can proceed rather than block on a check they could not run."""
    unknown = False
    for dst in (('1.1.1.1', 443), ('8.8.8.8', 443)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(timeout)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b'\0')
            s.connect(dst)
            return True
        except PermissionError:
            unknown = True
        except OSError:
            pass
        finally:
            s.close()
    return None if unknown else False


def _speedtest_client():
    """Locate a speedtest client and learn how it can pin an interface.

    Returns (kind, exe): kind 'ookla' (supports --interface, a real device bind)
    or 'cli' (the python speedtest-cli, which only offers --source).

    Do NOT infer the client from the binary name: on Debian/Raspberry Pi OS
    /usr/bin/speedtest is usually just an entry-point alias for the python
    speedtest-cli and rejects --interface outright. Ask --help instead."""
    for name in ('speedtest', 'speedtest-cli'):
        if not _have(name):
            continue
        h = _run([name, '--help'], timeout=10)
        if '--interface' in ((h['out'] or '') + (h['err'] or '')):
            return 'ookla', name
    for name in ('speedtest-cli', 'speedtest'):
        if _have(name):
            return 'cli', name
    return None, None


def _speedtest_error(res, meta):
    """Turn a speedtest client failure into something actionable. 'Cannot
    retrieve speedtest configuration / urlopen error timed out' means it could
    not reach speedtest.net at all — when we bound the socket to an interface
    that is the prime suspect, otherwise it is plain no-internet/blocked."""
    raw = (res['err'] or res['out'] or 'speedtest failed').strip()
    low = raw.lower()
    if 'retrieve speedtest configuration' in low or 'urlopen error' in low:
        if meta.get('bound'):
            return (f"Could not reach speedtest.net with the test pinned to "
                    f"{meta.get('interface')}, even though that interface can reach the "
                    f"internet. speedtest.net may be blocked on that path, or the link "
                    f"dropped mid-test — try Auto to compare. [{raw}]")
        return (f"Could not reach speedtest.net — no internet on this host, or "
                f"speedtest.net is blocked/unreachable from here. [{raw}]")
    return raw


def _iface_has_default_route(iface):
    """True if this interface has a default route (a gateway) of its own.

    The only trustworthy 'can it reach the internet' signal we can get without
    sending traffic. NOT `ip route get <ip> oif <iface>`: forcing oif makes the
    kernel synthesize an answer for an interface that has no route at all (it
    will happily report a route out of an address-less eth0, borrowing another
    interface's src), so that check silently passes for exactly the interfaces
    we need to exclude."""
    res = _run(['ip', 'route', 'show', 'default', 'dev', iface], timeout=5)
    return res['rc'] == 0 and bool(res['out'].strip())


def _iface_default_gateway(iface):
    """The gateway of this interface's own default route, or None. Lets a test
    pinned to a NIC ping *that* link's gateway instead of the global one (which
    may sit on a different segment entirely)."""
    res = _run(['ip', 'route', 'show', 'default', 'dev', iface], timeout=5)
    m = re.search(r'\bvia\s+(\S+)', res['out'] or '')
    return m.group(1) if m else None


def _egress_iface(preferred=None):
    """Best interface to originate an *egress* test (speedtest) from: the
    caller's pin, else a wired port that can actually reach the internet, else
    the default-route interface.

    Deliberately NOT _capture_iface(): that one prefers any wired port with
    carrier, which for the sensor deployment is exactly the SPAN/monitor leg —
    fine to sniff, useless to originate from. An address alone isn't enough
    either: a Ragnar plugged into a switch gets a DHCP lease on that segment but
    reaches the internet over WiFi, so a wired port only qualifies as egress if
    it has a default route. Binding to one that doesn't is what produces
    speedtest-cli's 'Cannot retrieve speedtest configuration / urlopen error
    timed out'."""
    if _valid_iface(preferred or ''):
        return preferred
    dflt = _default_route_iface()
    wired = []
    for name in _list_iface_names(include_virtual=False):
        if _is_wireless(name) or name.startswith(('tun', 'tap', 'wg', 'zt', 'tailscale')):
            continue
        try:
            with open(f'/sys/class/net/{name}/carrier') as f:
                if f.read().strip() != '1':
                    continue
        except OSError:      # admin-down or vanished — not a candidate
            continue
        v4, _ = _iface_addrs(name)
        if v4 and _iface_has_default_route(name):
            wired.append(name)
    if wired:
        return dflt if dflt in wired else sorted(wired)[0]
    return dflt


def do_speedtest(interface=None):
    """Run a bandwidth test. Supports both the Ookla `speedtest` CLI and the
    python `speedtest-cli`; returns download/upload in Mbps.

    `interface` pins which local interface the test originates from; '' / None
    auto-selects (a wired port that can reach the internet first — see
    _egress_iface), so a multi-homed box tests the cable rather than whatever
    holds the default route.

    Pinning binds the *device* (Ookla `--interface`, or SO_BINDTODEVICE via
    speedtest_bind.py for the python client) — never speedtest-cli's `--source`,
    which only sets a source address and does not force egress: on a box whose
    WiFi and LAN face the same router, the packet still left via WiFi carrying
    the LAN address and the router dropped it as spoofed."""
    if interface:
        # _valid_iface is only a name/injection guard — it does not check that
        # the interface exists, so verify membership too or a typo surfaces as a
        # confusing "no IPv4 address" further down.
        if not _valid_iface(interface) or interface not in _list_iface_names(include_virtual=True):
            return {'success': False, 'error': f'Unknown interface: {interface}'}
    iface = _egress_iface(interface)
    source_ip = None
    if iface:
        v4, _ = _iface_addrs(iface)
        if v4:
            source_ip = v4[0].split('/')[0]
        elif interface:
            # Explicitly asked for an interface that can't originate traffic.
            return {'success': False,
                    'error': f'{iface} has no IPv4 address — it cannot originate a '
                             f'speed test (a monitor/SPAN port has link but no address).'}
    # Only bind when deliberately leaving the kernel's normal path. If we landed
    # on the default-route interface anyway, binding adds nothing but risk — run
    # exactly as we did before the interface selector existed.
    bind = bool(iface and iface != _default_route_iface())
    meta = {'interface': iface, 'source_ip': source_ip if bind else None,
            'bound': bind}
    # Ask the interface itself whether it can reach the internet, rather than
    # inferring it from a default route. A wired port can hold a perfectly good
    # default route to the same router as WiFi and still be the wrong thing to
    # bind — and, conversely, we must never tell a user their interface "has no
    # route to the internet" when it demonstrably does.
    if bind:
        reach = _probe_egress(iface)
        if reach is False:
            return {'success': False, **meta,
                    'error': f'{iface} cannot reach the internet — verified by a direct '
                             f'connection test bound to that interface. Use Auto, or pick '
                             f'the interface that carries your internet connection.'}
    # Self-heal: if neither client is present, install speedtest-cli on demand.
    # A device updated from the UI may not have finished (or may have missed)
    # background tool provisioning, and the old behaviour was to just error out
    # telling the user to run the installer. Install it here so the button works.
    if not _have('speedtest-cli') and not _have('speedtest'):
        do_install_tool('speedtest-cli')

    kind, exe = _speedtest_client()
    if not kind:
        return {'success': False, **meta,
                'error': 'speedtest is not installed. Click Install to add it.',
                'missing_tool': 'speedtest-cli'}

    if kind == 'ookla':
        cmd = [exe, '--format=json', '--accept-license', '--accept-gdpr']
        if bind:
            cmd += ['--interface', iface]      # a real device bind
        res = _run(cmd, timeout=120)
        if res['rc'] == 0:
            try:
                d = json.loads(res['out'])
                dl = d.get('download', {}).get('bandwidth', 0) * 8 / 1e6
                ul = d.get('upload', {}).get('bandwidth', 0) * 8 / 1e6
                return {'success': True, **meta,
                        'download_mbps': round(dl, 2),
                        'upload_mbps': round(ul, 2),
                        'ping_ms': round(d.get('ping', {}).get('latency', 0), 2),
                        'server': (d.get('server') or {}).get('name'),
                        'server_location': (d.get('server') or {}).get('location'),
                        'isp': d.get('isp')}
            except ValueError:
                pass
        return {'success': False, **meta,
                'error': _speedtest_error(res, meta)}

    # python speedtest-cli. To pin an interface we must bind the *device*: its
    # own --source only sets a source address, which does not force egress (the
    # packet still leaves via the default-route NIC wearing the other NIC's IP,
    # and gets dropped as spoofed). speedtest_bind.py patches the socket layer
    # with SO_BINDTODEVICE and then runs the very same client.
    if bind:
        wrapper = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'python', 'speedtest_bind.py')
        cmd = [sys.executable or 'python3', wrapper, iface, '--json']
    else:
        cmd = [exe, '--json']
    res = _run(cmd, timeout=120)
    if res['rc'] == 0:
        try:
            d = json.loads(res['out'])
            return {'success': True, **meta,
                    'download_mbps': round(d.get('download', 0) / 1e6, 2),
                    'upload_mbps': round(d.get('upload', 0) / 1e6, 2),
                    'ping_ms': round(d.get('ping', 0), 2),
                    'server': (d.get('server') or {}).get('sponsor'),
                    'server_location': (d.get('server') or {}).get('name'),
                    'isp': (d.get('client') or {}).get('isp')}
        except ValueError:
            pass
    return {'success': False, **meta, 'error': _speedtest_error(res, meta)}


# --------------------------------------------------------------------------
# Switch & L2: LLDP/CDP/EDP neighbor discovery + ARP scan
# --------------------------------------------------------------------------

def do_lldp(interface=None):
    """Return discovered switch neighbors via lldpctl. lldpd (configured with
    -c -e -f -s) also decodes CDPv1/v2 (Cisco), EDP (Extreme), FDP (Foundry)
    and SONMP (Nortel) in addition to LLDP. VLAN id/name are included when the
    neighbor advertises them.

    `interface` limits discovery to one local port; '' / None reports every
    interface (the default). On a multi-homed box — a Ragnar with a LAN cable,
    a USB NIC and WiFi — that is the difference between "which switch am I
    plugged into on *this* port" and a merged list you have to eyeball."""
    if not _have('lldpctl'):
        return {'success': False,
                'error': 'lldpd/lldpctl is not installed. Click Install to add it '
                         '(configured for LLDP + CDPv1/v2, EDP, FDP and SONMP so '
                         'Cisco, Extreme, Foundry and Nortel switches are seen too).',
                'missing_tool': 'lldpd',
                'neighbors': []}
    if interface:
        # Name/injection guard plus an existence check, so a typo surfaces as a
        # clear error rather than an empty neighbour list that looks like "no
        # switch found".
        if not _valid_iface(interface) or interface not in _list_iface_names(include_virtual=True):
            return {'success': False, 'error': f'Unknown interface: {interface}',
                    'neighbors': []}
    # lldpctl takes trailing interface names to filter natively.
    cmd = ['lldpctl', '-f', 'json'] + ([interface] if interface else [])
    res = _run(cmd, timeout=15)
    if res['rc'] != 0 and not res['out']:
        return {'success': False, 'error': res['err'] or 'lldpctl failed',
                'interface': interface, 'neighbors': []}
    neighbors = []
    try:
        data = json.loads(res['out'])
        ifaces = data.get('lldp', {}).get('interface', [])
        if isinstance(ifaces, dict):
            ifaces = [ifaces]
        for entry in ifaces:
            for local_if, info in entry.items():
                neighbors.append(_parse_lldp_iface(local_if, info))
    except ValueError as e:
        return {'success': False, 'error': f'could not parse lldpctl output: {e}',
                'interface': interface, 'neighbors': [], 'output': res['out']}
    if not neighbors:
        note = ('No neighbors yet? Switches announce every ~30s; give it up '
                'to a minute after connecting, and ensure the port isn\'t on a hub.')
        if interface:
            note = (f'No neighbours on {interface}. ' + note +
                    ' If the cable is on a different port, switch to Auto (all '
                    'interfaces) to see every neighbour this box can hear.')
    else:
        note = None
    return {'success': True, 'interface': interface, 'neighbors': neighbors,
            'note': note}


def _first_key(d):
    """lldpctl json nests some objects under a single dynamic key (e.g. the
    chassis name). Return (key, value) of the first item, or (None, {})."""
    if isinstance(d, dict) and d:
        k = next(iter(d))
        return k, d[k]
    return None, {}


def _scalar(v):
    """lldpctl represents values either as a scalar or as {'value': X}."""
    if isinstance(v, dict):
        return v.get('value')
    return v


def _poe_watts(mw):
    """lldpd reports 802.3at/LLDP-MED power values in milliwatts. Convert to
    watts, tolerating strings and junk. Returns a float or None."""
    try:
        w = round(int(str(mw).strip()) / 1000.0, 1)
        return w if 0 < w <= 200 else None  # sanity bound (802.3bt tops out ~90W)
    except (TypeError, ValueError):
        return None


def _poe_class_num(class_str):
    """Pull the numeric class out of an lldpctl class string ('class 4' -> 4)."""
    if not class_str:
        return None
    m = re.search(r'(\d+)', str(class_str))
    return int(m.group(1)) if m else None


def _poe_standard(power_type, class_num):
    """Resolve the PoE standard to a short code (af/at/bt) and a long label.

    802.3bt (Type 3/4) introduced classes 5-8, so any class >=5 is bt. Otherwise
    the dot3 'power-type' field distinguishes Type 2 (802.3at) from Type 1
    (802.3af); when it's absent we fall back to the class (class 4 requires at)."""
    if class_num is not None and class_num >= 5:
        return 'bt', '802.3bt (Type 3/4)'
    pt = str(power_type).strip() if power_type is not None else ''
    if pt.startswith('2'):
        return 'at', '802.3at (Type 2)'
    if pt.startswith('1'):
        return 'af', '802.3af (Type 1)'
    if class_num is not None:
        return ('at', '802.3at (Type 2)') if class_num >= 4 else ('af', '802.3af (Type 1)')
    return None, None


def _parse_poe(port):
    """Extract Power-over-Ethernet state from an lldpctl port's Power-via-MDI
    TLV (dot3 / LLDP-MED). A PoE-capable switch advertises this, so it tells us
    whether the port supplies power and at what class/wattage. Returns None when
    the neighbour advertised no power TLV."""
    if not isinstance(port, dict):
        return None
    power = port.get('power')
    if isinstance(power, list) and power:
        power = power[0]
    if not isinstance(power, dict) or not power:
        return None

    def val(k):
        v = _scalar(power.get(k))
        return str(v).strip() if v is not None else None

    def truthy(v):
        return str(v).strip().lower() in ('yes', 'true', '1', 'on', 'enabled')

    device_type = val('device-type') or val('device_type')
    enabled = val('enabled')
    supported = val('supported')
    ptype = val('power-type') or val('power_type')
    class_str = val('class')
    class_num = _poe_class_num(class_str)
    poe_type, standard = _poe_standard(ptype, class_num)
    allocated_w = _poe_watts(power.get('allocated') if isinstance(power.get('allocated'), (str, int)) else _scalar(power.get('allocated')))
    requested_w = _poe_watts(power.get('requested') if isinstance(power.get('requested'), (str, int)) else _scalar(power.get('requested')))
    # The switch port is a PSE (Power Sourcing Equipment) and power is enabled
    # => it is delivering, or ready to deliver, PoE to us.
    powered = bool(device_type and device_type.upper() == 'PSE' and truthy(enabled))

    # Active vs passive: an LLDP Power-via-MDI TLV means the PSE does 802.3
    # detection/classification handshaking, i.e. ACTIVE (standards) PoE. Passive
    # PoE injectors put voltage straight on the wire with no negotiation and no
    # TLV, so they are undetectable from the PD side over LLDP -- we can only
    # affirm 'active', never confirm 'passive' here.
    mode = 'active'

    # EndSpan vs MidSpan: not an explicit LLDP field, but the powered pairs are
    # a strong hint. Alternative A (data pairs / 'signal') is how switch-
    # integrated PSEs (endspan) deliver power; Alternative B (spare pairs /
    # 'spare') is the classic mid-span injector. Best-effort; 802.3at/bt drive
    # all four pairs so treat this as indicative, not definitive.
    pairs = val('pairs')
    power_via = None
    if pairs:
        p = pairs.lower()
        if 'spare' in p:
            power_via = 'midspan'
        elif 'signal' in p or 'both' in p:
            power_via = 'endspan'

    return {
        'device_type': device_type,          # PSE (switch) or PD (powered device)
        'supported': truthy(supported) if supported is not None else None,
        'enabled': truthy(enabled) if enabled is not None else None,
        'powered': powered,
        'type': poe_type,                     # af / at / bt
        'mode': mode,                         # active (passive not LLDP-detectable)
        'power_via': power_via,               # endspan (switch) / midspan (injector)
        'class': class_str,
        'class_num': class_num,
        'standard': standard,
        'pairs': pairs,
        'allocated_w': allocated_w,
        'requested_w': requested_w,
    }


def _parse_lldp_iface(local_if, info):
    via = info.get('via') or info.get('protocol')
    chassis = info.get('chassis', {})
    ch_name, ch = _first_key(chassis) if isinstance(chassis, dict) and 'id' not in chassis else (None, chassis)
    if ch_name is None and isinstance(chassis, dict):
        ch = chassis
    port = info.get('port', {})
    vlan = info.get('vlan', {})
    vlan_id = None
    vlan_name = None
    if isinstance(vlan, list) and vlan:
        vlan = vlan[0]
    if isinstance(vlan, dict):
        vlan_id = vlan.get('vlan-id') or vlan.get('vlan_id') or _scalar(vlan)
        vlan_name = vlan.get('value') if isinstance(vlan.get('value'), str) else None
    mgmt = ch.get('mgmt-ip') if isinstance(ch, dict) else None
    if isinstance(mgmt, list):
        mgmt = ', '.join(str(x) for x in mgmt)
    return {
        'local_interface': local_if,
        'protocol': via,
        'switch_name': ch_name or (_scalar(ch.get('name')) if isinstance(ch, dict) else None),
        'switch_descr': _scalar(ch.get('descr')) if isinstance(ch, dict) else None,
        'mgmt_ip': mgmt,
        'port_id': _scalar(port.get('id')) if isinstance(port, dict) else None,
        'port_descr': _scalar(port.get('descr')) if isinstance(port, dict) else None,
        'vlan_id': vlan_id,
        'vlan_name': vlan_name,
        'poe': _parse_poe(port),
    }


def do_arp_scan(interface=None):
    if not _have('arp-scan'):
        return {'success': False,
                'error': 'arp-scan is not installed. Click Install to add it.',
                'missing_tool': 'arp-scan', 'hosts': []}
    interface = _capture_iface(interface)
    if not interface:
        return {'success': False, 'hosts': [],
                'error': 'No suitable interface found — pick one explicitly.'}
    res = _run(['arp-scan', f'--interface={interface}', '--localnet'], timeout=40)
    if res['rc'] == 127:
        return {'success': False, 'error': res['err'] or 'arp-scan not found',
                'missing_tool': 'arp-scan', 'hosts': []}
    hosts = []
    for line in res['out'].splitlines():
        m = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)$', line)
        if m:
            hosts.append({'ip': m.group(1), 'mac': m.group(2),
                          'vendor': m.group(3).strip() or None})
    return {'success': True, 'hosts': hosts, 'count': len(hosts), 'interface': interface}


# --------------------------------------------------------------------------
# ARP spoofing / poisoning detection: watch the gateway's IP->MAC binding
# against a learned baseline (a MITM inserting itself changes it), and flag a
# single MAC answering for many IPs (one host impersonating the whole subnet).
# The kernel neighbour table is authoritative and needs no capture, so this is
# cheap enough to run on a schedule from the integrity monitor.
# --------------------------------------------------------------------------

_ARP_BASELINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'data', 'arp_baseline.json')
_arp_baseline_lock = threading.Lock()
# A MAC bound to at least this many IPs in the neighbour table is treated as a
# possible impersonator. Proxy-ARP routers can legitimately answer for a few, so
# keep the floor above normal noise.
_ARP_IMPERSONATOR_MIN_IPS = 4


def _neigh_entries(iface=None):
    """Parse `ip -4 neigh` into [(ip, mac, state)] for entries with a lladdr.
    Scoped to one interface's segment when `iface` is given."""
    cmd = ['ip', '-4', 'neigh', 'show']
    if iface:
        cmd += ['dev', iface]
    res = _run(cmd, timeout=5)
    out = []
    for line in res['out'].splitlines():
        m = re.match(r'^(\d+\.\d+\.\d+\.\d+)\b.*?\blladdr\s+([0-9a-fA-F:]{17})\s+(\w+)', line)
        if m:
            out.append((m.group(1), m.group(2).lower(), m.group(3)))
    return out


def _neigh_mac(ip):
    """Current MAC bound to `ip` in the kernel neighbour table, or None. Sends a
    single ping first if the entry is missing, to populate it."""
    if not ip:
        return None
    for i, mac, _ in _neigh_entries():
        if i == ip:
            return mac
    _run(['ping', '-n', '-c', '1', '-W', '1', ip], timeout=3)
    for i, mac, _ in _neigh_entries():
        if i == ip:
            return mac
    return None


def _arp_baseline_load():
    try:
        with open(_ARP_BASELINE_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _arp_baseline_save(d):
    try:
        os.makedirs(os.path.dirname(_ARP_BASELINE_PATH), exist_ok=True)
        tmp = _ARP_BASELINE_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _ARP_BASELINE_PATH)
    except OSError:
        pass


def do_arp_baseline(action='get'):
    """Manage the trusted gateway IP->MAC baseline the spoof check compares
    against. action='reset' clears it so the current binding is re-learned on
    the next check (use after a legitimate router/gateway change)."""
    with _arp_baseline_lock:
        if action == 'reset':
            _arp_baseline_save({})
            return {'success': True, 'reset': True, 'gateways': {}}
        return {'success': True, 'gateways': (_arp_baseline_load().get('gateways') or {})}


def do_arp_check(interface=None, learn=True):
    """Detect ARP spoofing / poisoning from the kernel neighbour table.

    Signals: (1) the default gateway's MAC no longer matches the trusted
    baseline — the classic MITM signature (an attacker ARP-replies as the
    gateway to intercept traffic); (2) one MAC answering for many IPs — a host
    impersonating much of the subnet. First run learns the gateway baseline.

    verdict: 'spoofed'    -- gateway MAC changed from the trusted baseline
             'suspicious' -- a MAC is impersonating several IPs
             'clean'      -- gateway matches baseline, no impersonators
             'unknown'    -- no gateway, or its MAC couldn't be resolved

    With `interface` set, the check is scoped to that segment: its own default
    gateway (a higher-metric uplink still counts) and only the neighbours on that
    interface — the right lens on a multi-homed box."""
    iface = interface if _valid_iface(interface or '') else None
    gw = _iface_gateway(iface) if iface else _default_gateway()
    if not gw:
        return {'success': True, 'verdict': 'unknown', 'gateway': None,
                'interface': iface,
                'reasons': [('no default gateway via %s — nothing to check' % iface)
                            if iface else 'no default gateway on this host — nothing to check'],
                'impersonators': [], 'neighbor_count': 0}

    gw_mac = _neigh_mac(gw)
    reasons = []
    verdict = 'clean'
    learned = False
    with _arp_baseline_lock:
        baseline = _arp_baseline_load()
        gws = baseline.setdefault('gateways', {})
        base_mac = gws.get(gw)
        if gw_mac and not base_mac and learn:
            gws[gw] = gw_mac
            _arp_baseline_save(baseline)
            base_mac = gw_mac
            learned = True

    if not gw_mac:
        verdict = 'unknown'
        reasons.append(f'could not resolve the gateway {gw} MAC (no ARP reply)')
    elif base_mac and gw_mac != base_mac:
        verdict = 'spoofed'
        reasons.append(f'gateway {gw} MAC changed from trusted {base_mac} to {gw_mac} '
                       '— classic ARP-spoofing / MITM signature')

    # One MAC claiming many IPs (attacker impersonating multiple hosts). The
    # gateway MAC is excluded — a router legitimately fronts its own address.
    entries = _neigh_entries(iface)
    mac_ips = {}
    for ip, mac, _ in entries:
        mac_ips.setdefault(mac, set()).add(ip)
    impersonators = [{'mac': mac, 'ips': sorted(ips)}
                     for mac, ips in mac_ips.items()
                     if len(ips) >= _ARP_IMPERSONATOR_MIN_IPS and mac != gw_mac]
    if impersonators:
        if verdict == 'clean':
            verdict = 'suspicious'
        for imp in impersonators:
            ips = imp['ips']
            reasons.append(f"MAC {imp['mac']} answers for {len(ips)} IPs "
                           f"({', '.join(ips[:4])}{'…' if len(ips) > 4 else ''}) "
                           '— possible ARP spoofing')

    return {'success': True, 'verdict': verdict, 'interface': iface,
            'gateway': {'ip': gw, 'mac': gw_mac, 'baseline': base_mac,
                        'learned': learned},
            'impersonators': impersonators,
            'neighbor_count': len(entries),
            'reasons': reasons}


# --------------------------------------------------------------------------
# MAC Watch — detection-only MAC-spoofing + randomization detector & tracker.
#
# Three jobs, all passive (reads the kernel neighbour table, optionally an
# arp-scan sweep — no capture, and it never spoofs anything itself):
#   1. Spoofing / cloning: a vendor OUI wearing the locally-administered bit
#      (disguised vendor), the same MAC bound to several IPs (a clone), and an
#      IP whose MAC changed identity over time (the past-spoofing signature).
#   2. Randomization: privacy (locally-administered, vendor-less) MACs on the
#      segment, reported as an aggregate inventory rather than per-MAC noise so
#      a busy Wi-Fi segment full of iPhones doesn't drown a real spoof.
#   3. Tracking: an IP that cycles through several randomized MACs over time is
#      one device rotating to hide — grouped into a track so it can be followed
#      across the addresses it hides behind.
#
# A small JSON store keeps first/last-seen, per-IP MAC history and change
# events, so "current AND past" spoofing/rotation survives across checks and
# restarts. True cross-MAC device tracking on a switched/Wi-Fi segment needs
# probe-request fingerprinting (monitor-mode only); this IP-anchored version is
# the honest, capture-free approximation and is labelled as such in the UI.
# --------------------------------------------------------------------------

_MAC_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'data', 'mac_watch.json')
_mac_watch_lock = threading.Lock()

# A randomized MAC seen within this window counts as "current" segment activity.
_MAC_WATCH_WINDOW_S = 24 * 3600
# A randomized MAC whose whole lifetime was shorter than this is "ephemeral" —
# the fingerprint of active privacy rotation (device changing address rapidly).
_MAC_EPHEMERAL_S = 15 * 60
# Keep at most this many change events in the store (newest wins).
_MAC_EVENTS_CAP = 200
# One MAC bound to at least this many distinct IPs at once is a clone candidate.
_MAC_CLONE_MIN_IPS = 2

# Locally-administered VM / container prefixes — tracked apart from privacy
# randomization so virtual NICs don't inflate the randomized count or look like
# a spoof. Keyed by the leading octets (lowercase, colon-separated).
_MAC_VIRTUAL_PREFIXES = {
    '02:42': 'Docker',
    '52:54:00': 'QEMU/KVM',
    '0a:00:27': 'VirtualBox host-only',
    '02:00:4c': 'Microsoft NDIS loopback',
    '02:50:41': 'Parallels',
}

# Always-present universal (LAA-clear) vendor OUI seed, used even when the
# arp-scan / nmap OUI database isn't installed. Only universal prefixes belong
# here — a prefix with the locally-administered bit set can never be a
# legitimately-registered OUI, and seeding one would make it read as a spoof.
_MAC_VENDOR_SEED = {
    'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi',
    'e4:5f:01': 'Raspberry Pi', 'd8:3a:dd': 'Raspberry Pi',
    '2c:cf:67': 'Raspberry Pi', '28:cd:c1': 'Raspberry Pi',
    '3c:22:fb': 'Apple', 'a4:83:e7': 'Apple', 'f0:18:98': 'Apple',
    '00:1b:63': 'Apple', 'ac:bc:32': 'Apple', '90:9c:4a': 'Apple',
    '00:50:56': 'VMware', '00:0c:29': 'VMware', '00:05:69': 'VMware',
    '08:00:27': 'VirtualBox', '00:15:5d': 'Microsoft Hyper-V',
    '00:16:6c': 'Samsung', 'e8:50:8b': 'Samsung', '5c:0a:5b': 'Samsung',
    '3c:97:0e': 'Intel', '00:1b:21': 'Intel', '34:13:e8': 'Intel',
    '00:1a:a1': 'Cisco', '00:1b:0d': 'Cisco',
    '50:c7:bf': 'TP-Link', 'a4:2b:b0': 'TP-Link', 'c0:06:c3': 'TP-Link',
    '00:14:6c': 'Netgear', '20:e5:2a': 'Netgear',
    '24:0a:c4': 'Espressif', '30:ae:a4': 'Espressif',
    '7c:9e:bd': 'Espressif', 'a0:20:a6': 'Espressif',
    '00:e0:fc': 'Huawei', 'ec:b5:fa': 'Philips',
}

_OUI_DB_PATHS = ('/usr/share/arp-scan/ieee-oui.txt',
                 '/usr/share/nmap/nmap-mac-prefixes')
# Cap the loaded OUI table so a pathological file can't blow memory.
_OUI_DB_CAP = 60000
_oui_db_cache = None
_oui_db_lock = threading.Lock()


def _mac_norm(mac):
    """Normalise a MAC to lowercase colon form, or None if it isn't a MAC."""
    if not mac or not isinstance(mac, str):
        return None
    hexs = re.sub(r'[^0-9a-fA-F]', '', mac)
    if len(hexs) != 12:
        return None
    hexs = hexs.lower()
    return ':'.join(hexs[i:i + 2] for i in range(0, 12, 2))


def _mac_first_octet(mac):
    try:
        return int(mac[0:2], 16)
    except (ValueError, TypeError):
        return None


def _is_laa(mac):
    """True if the locally-administered (privacy/spoof) bit is set."""
    b0 = _mac_first_octet(mac)
    return b0 is not None and bool(b0 & 0x02)


def _is_universal_prefix(oui):
    """True if a 6-hex OUI could be a legitimately-registered (LAA-clear) OUI.
    Filters junk out of the vendor table so an LAA/randomization range in a full
    manuf file can't be mistaken for a real vendor by the spoof check."""
    try:
        b0 = int(oui[0:2], 16)
    except (ValueError, TypeError, IndexError):
        return False
    return not (b0 & 0x02) and not (b0 & 0x01)


def _load_oui_db():
    """Load {6-hex-prefix: vendor} from the arp-scan / nmap OUI DB if present,
    merged over the built-in seed. Universal prefixes only; cached."""
    global _oui_db_cache
    if _oui_db_cache is not None:
        return _oui_db_cache
    with _oui_db_lock:
        if _oui_db_cache is not None:
            return _oui_db_cache
        db = {}
        for oui, vendor in _MAC_VENDOR_SEED.items():
            db[oui.replace(':', '')] = vendor
        for path in _OUI_DB_PATHS:
            try:
                with open(path, encoding='utf-8', errors='replace') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        parts = re.split(r'\s+', line, maxsplit=1)
                        if len(parts) != 2:
                            continue
                        pfx = re.sub(r'[^0-9a-fA-F]', '', parts[0]).lower()
                        if len(pfx) < 6:
                            continue
                        pfx = pfx[:6]
                        if not _is_universal_prefix(pfx):
                            continue
                        db.setdefault(pfx, parts[1].strip())
                        if len(db) >= _OUI_DB_CAP:
                            break
            except OSError:
                continue
            if len(db) >= _OUI_DB_CAP:
                break
        _oui_db_cache = db
        return db


def _vendor_for_prefix(prefix6):
    return _load_oui_db().get(prefix6)


def _classify_mac(mac):
    """Classify one MAC. Returns {klass, vendor, note}.

    klass ∈ {'universal', 'spoofed_vendor_oui', 'virtual_laa', 'randomized',
             'invalid'}. A universal address is a normal burned-in NIC; the
    three LAA buckets are kept distinct so privacy randomization (benign, an
    aggregate) never gets conflated with a vendor OUI wearing the LAA bit
    (impersonation) or with a VM/container NIC."""
    m = _mac_norm(mac)
    if not m:
        return {'klass': 'invalid', 'vendor': None, 'note': 'not a MAC'}
    b0 = _mac_first_octet(m)
    prefix6 = m.replace(':', '')[:6]
    if b0 & 0x01:  # multicast/broadcast — never a valid source address
        return {'klass': 'invalid', 'vendor': None, 'note': 'multicast/broadcast'}
    if not (b0 & 0x02):  # universal — legitimately-registered OUI
        vendor = _vendor_for_prefix(prefix6)
        return {'klass': 'universal', 'vendor': vendor, 'note': None}
    # Locally-administered: virtual, disguised-vendor, or privacy randomization.
    for pfx, name in _MAC_VIRTUAL_PREFIXES.items():
        if m.startswith(pfx):
            return {'klass': 'virtual_laa', 'vendor': name, 'note': 'VM/container NIC'}
    # Clear the LAA bit and see whether the underlying OUI is a real vendor — a
    # registered vendor OUI can't legitimately carry the LAA bit, so this is the
    # impersonation signature (a spoofer picked a plausible vendor prefix).
    deladdr = '%02x%s' % (b0 & ~0x02, prefix6[2:])
    vendor = _vendor_for_prefix(deladdr)
    if vendor:
        return {'klass': 'spoofed_vendor_oui', 'vendor': vendor,
                'note': f'vendor OUI ({vendor}) with the locally-administered bit set'}
    return {'klass': 'randomized', 'vendor': None, 'note': 'privacy-randomized MAC'}


def _local_macs():
    """Own NIC MACs, so this host's interfaces are never counted or flagged."""
    macs = set()
    res = _run(['ip', '-o', 'link', 'show'], timeout=5)
    for m in re.finditer(r'link/\w+\s+([0-9a-fA-F:]{17})', res['out']):
        norm = _mac_norm(m.group(1))
        if norm:
            macs.add(norm)
    return macs


def _mac_watch_load():
    try:
        with open(_MAC_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _mac_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_MAC_WATCH_PATH), exist_ok=True)
        tmp = _MAC_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _MAC_WATCH_PATH)
    except OSError:
        pass


def _fmt_ago(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f'{seconds}s ago'
    if seconds < 3600:
        return f'{seconds // 60}m ago'
    if seconds < 86400:
        return f'{seconds // 3600}h ago'
    return f'{seconds // 86400}d ago'


def do_mac_watch_reset():
    """Clear the MAC-watch history (first/last-seen, per-IP history, events)."""
    with _mac_watch_lock:
        _mac_watch_save({})
    return {'success': True, 'reset': True}


def do_mac_watch(scan=True, interface=None):
    """Detect current + past MAC spoofing/cloning and randomization, and track
    devices that rotate randomized MACs. Detection-only; nothing is spoofed.

    scan=True adds an arp-scan sweep (active but harmless) to widen coverage
    beyond whatever is already in the neighbour table; scan=False reads the
    neighbour table only (works unprivileged, no traffic generated)."""
    now = time.time()
    gw = _default_gateway()
    gw_mac = _neigh_mac(gw) if gw else None
    local = _local_macs()

    # Current (ip, mac) observations from the neighbour table, optionally
    # widened by an arp-scan sweep. Deduped; own-NIC MACs dropped.
    seen = {}  # mac -> set(ips)
    for ip, mac, _state in _neigh_entries():
        m = _mac_norm(mac)
        if m and m not in local:
            seen.setdefault(m, set()).add(ip)
    scan_iface = None       # interface the arp-scan sweep actually ran on
    scanned = False         # whether an arp-scan sweep was performed
    if scan and _have('arp-scan'):
        scan_iface = interface if _valid_iface(interface or '') else _default_route_iface()
        if scan_iface:
            scanned = True
            sweep = do_arp_scan(scan_iface)
            for h in (sweep.get('hosts') or []):
                m = _mac_norm(h.get('mac'))
                if m and m not in local:
                    seen.setdefault(m, set()).add(h.get('ip'))

    # Classify every currently-seen MAC.
    current = []
    for mac, ips in seen.items():
        info = _classify_mac(mac)
        if info['klass'] == 'invalid':
            continue
        current.append({'mac': mac, 'ips': sorted(i for i in ips if i),
                        'klass': info['klass'], 'vendor': info['vendor'],
                        'note': info['note']})

    # --- update the persistent store (this is what makes "past" possible) ----
    with _mac_watch_lock:
        store = _mac_watch_load()
        macs = store.setdefault('macs', {})
        ip_hist = store.setdefault('ip_history', {})
        events = store.setdefault('events', [])

        for c in current:
            rec = macs.setdefault(c['mac'], {'first': now, 'count': 0,
                                             'ips': [], 'klass': c['klass'],
                                             'vendor': c['vendor']})
            rec['last'] = now
            rec['count'] = rec.get('count', 0) + 1
            rec['klass'] = c['klass']
            rec['vendor'] = c['vendor']
            rec['ips'] = sorted(set(rec.get('ips', [])) | set(c['ips']))
            # Per-IP identity history — a change here is the past-spoof signal.
            for ip in c['ips']:
                hist = ip_hist.setdefault(ip, [])
                if not hist or hist[-1]['mac'] != c['mac']:
                    if hist and hist[-1]['mac'] != c['mac']:
                        old = hist[-1]
                        oc = _classify_mac(old['mac'])
                        # A randomized<->randomized flip on one IP is ordinary
                        # privacy rotation (DHCP re-lease); only flag identity
                        # changes that involve a real/burned-in vendor address.
                        privacy_only = (oc['klass'] in ('randomized', 'virtual_laa')
                                        and c['klass'] in ('randomized', 'virtual_laa'))
                        events.append({
                            'ts': now, 'ip': ip,
                            'old_mac': old['mac'], 'new_mac': c['mac'],
                            'old_klass': oc['klass'], 'new_klass': c['klass'],
                            'severity': 'low' if privacy_only else 'high',
                        })
                    hist.append({'mac': c['mac'], 'first': now, 'last': now})
                else:
                    hist[-1]['last'] = now
                # Bound per-IP history growth.
                if len(hist) > 40:
                    del hist[:len(hist) - 40]

        if len(events) > _MAC_EVENTS_CAP:
            del events[:len(events) - _MAC_EVENTS_CAP]
        _mac_watch_save(store)

    # --- assemble findings ---------------------------------------------------
    reasons = []
    verdict = 'clean'

    # (1) Disguised-vendor spoofs seen right now.
    spoofed = [c for c in current if c['klass'] == 'spoofed_vendor_oui']
    for c in spoofed:
        reasons.append(f"{c['mac']} is a {c['vendor']} vendor OUI with the "
                       f"locally-administered bit set — MAC-spoofing signature "
                       f"(IP {', '.join(c['ips']) or 'unknown'})")

    # (2) Clones — one MAC currently bound to several IPs (gateway excluded).
    clones = [c for c in current
              if len(c['ips']) >= _MAC_CLONE_MIN_IPS and c['mac'] != gw_mac]
    for c in clones:
        reasons.append(f"{c['mac']} answers for {len(c['ips'])} IPs "
                       f"({', '.join(c['ips'][:4])}"
                       f"{'…' if len(c['ips']) > 4 else ''}) — cloned/duplicated MAC")

    # (3) Past spoofing — identity changes on an IP within the window.
    with _mac_watch_lock:
        events = (_mac_watch_load().get('events') or [])
    recent_events = [e for e in events if now - e.get('ts', 0) <= _MAC_WATCH_WINDOW_S]
    hi_events = [e for e in recent_events if e.get('severity') == 'high']
    for e in hi_events[-8:]:
        reasons.append(f"IP {e['ip']} changed MAC {e['old_mac']} → {e['new_mac']} "
                       f"({_fmt_ago(now - e['ts'])}) — possible spoof/clone in the past")

    # (4) Randomization inventory (aggregate, not per-MAC).
    randomized = [c for c in current if c['klass'] == 'randomized']
    virtual = [c for c in current if c['klass'] == 'virtual_laa']
    with _mac_watch_lock:
        macs_store = (_mac_watch_load().get('macs') or {})
    ephemeral = 0
    for mac, rec in macs_store.items():
        if rec.get('klass') != 'randomized':
            continue
        life = rec.get('last', 0) - rec.get('first', 0)
        if 0 <= life < _MAC_EPHEMERAL_S and rec.get('count', 0) >= 1:
            ephemeral += 1
    randomization = {
        'count': len(randomized),
        'ephemeral': ephemeral,
        'virtual': len(virtual),
        'macs': [c['mac'] for c in randomized],
        'virtual_macs': [{'mac': c['mac'], 'vendor': c['vendor']} for c in virtual],
    }
    if randomized:
        note = (f"{len(randomized)} randomized (privacy) MAC(s) on the segment"
                + (f", {ephemeral} short-lived (active rotation)" if ephemeral else ""))
        reasons.append(note)

    # (5) Tracking — an IP that cycled through >=2 randomized MACs is one device
    # rotating to hide. Group its randomized addresses into a followable track.
    tracks = []
    with _mac_watch_lock:
        ip_hist = (_mac_watch_load().get('ip_history') or {})
    for ip, hist in ip_hist.items():
        rand_macs, first, last = [], None, None
        for h in hist:
            if _classify_mac(h['mac'])['klass'] == 'randomized':
                rand_macs.append(h['mac'])
                first = h['first'] if first is None else min(first, h['first'])
                last = h['last'] if last is None else max(last, h['last'])
        uniq = sorted(set(rand_macs))
        if len(uniq) >= 2 and last and now - last <= _MAC_WATCH_WINDOW_S:
            tracks.append({'ip': ip, 'macs': uniq, 'changes': len(uniq) - 1,
                           'first': first, 'last': last,
                           'span': _fmt_ago(now - first) if first else None})
    tracks.sort(key=lambda t: len(t['macs']), reverse=True)
    for t in tracks[:6]:
        reasons.append(f"device at {t['ip']} rotated through {len(t['macs'])} "
                       f"randomized MACs — tracked across its address changes")

    if spoofed or clones or hi_events:
        verdict = 'spoofed'
    elif tracks or randomized:
        verdict = 'suspicious' if tracks else 'randomization'

    return {
        'success': True, 'verdict': verdict,
        'summary': {
            'observed': len(current),
            'spoofed': len(spoofed),
            'clones': len(clones),
            'past_events': len(hi_events),
            'randomized': len(randomized),
            'virtual': len(virtual),
            'tracks': len(tracks),
        },
        'spoofed': spoofed,
        'clones': clones,
        # Every MAC seen this pass, worst class first, so the UI can list them.
        'observed_macs': sorted(
            current,
            key=lambda c: ({'spoofed_vendor_oui': 0, 'universal': 1,
                            'randomized': 2, 'virtual_laa': 3}.get(c['klass'], 4),
                           c['ips'][0] if c['ips'] else '', c['mac'])),
        'events': [dict(e, ago=_fmt_ago(now - e['ts'])) for e in recent_events[-20:]][::-1],
        'randomization': randomization,
        'tracks': tracks,
        'gateway': {'ip': gw, 'mac': gw_mac},
        'interface': scan_iface,
        'scanned': scanned,
        'source': (f'arp-scan sweep on {scan_iface}' if scanned
                   else 'neighbour table (all interfaces)'),
        'oui_db': bool(len(_load_oui_db()) > len(_MAC_VENDOR_SEED)),
        'reasons': reasons,
    }


# --------------------------------------------------------------------------
# DHCP Guardian — DHCP-snooping-style monitor (detection-only).
#
# The DHCP layer is the one L2 service Ragnar hadn't covered, and it's arguably
# the second-highest-value one after DNS: whoever answers DHCP hands you your
# gateway and DNS, so a rogue DHCP server is a turnkey man-in-the-middle. Two
# jobs, both passive/harmless (it never runs a DHCP server or hands out leases):
#
#   1. Rogue / fake DHCP server — an active `broadcast-dhcp-discover` provokes
#      *every* DHCP server on the segment to OFFER. More than one distinct
#      server, or a server offering a gateway/DNS that differs from the trusted
#      one, is the rogue-server / MITM signature. The offered gateway's MAC is
#      cross-checked against the ARP baseline (do_arp_check) so a DHCP steer
#      backed by ARP spoofing reads as one combined finding.
#   2. DHCP starvation — a short passive tcpdump capture counts client DISCOVER/
#      REQUEST messages and the distinct client hardware addresses behind them;
#      a burst of many distinct chaddrs in a few seconds is the pool-exhaustion
#      signature (the classic precursor that clears the field for the rogue).
#
# A trusted-server baseline (data/dhcp_baseline.json) is learned on first run —
# like the ARP baseline — so a *new* server or a *changed* offered gateway is
# flagged even against an otherwise-quiet segment. verdict: clean / suspicious /
# rogue / starvation.
# --------------------------------------------------------------------------

_DHCP_BASELINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   'data', 'dhcp_baseline.json')
_dhcp_baseline_lock = threading.Lock()

# Distinct client hardware addresses seen in the capture window at or above
# which we call it starvation (a normal segment shows a handful at most).
_DHCP_STARV_MIN_CLIENTS = 12
# nmap's per-server OFFER wait; long enough for a slow server to answer, short
# enough to keep the whole scan bounded.
_DHCP_DISCOVER_TIMEOUT_S = 8


def _dhcp_baseline_load():
    try:
        with open(_DHCP_BASELINE_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _dhcp_baseline_save(d):
    try:
        os.makedirs(os.path.dirname(_DHCP_BASELINE_PATH), exist_ok=True)
        tmp = _DHCP_BASELINE_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _DHCP_BASELINE_PATH)
    except OSError:
        pass


def do_dhcp_baseline(action='get'):
    """Manage the trusted DHCP-server baseline the rogue check compares against.
    action='reset' clears it so the current server(s) are re-learned on the next
    scan (use after a legitimate DHCP-server/gateway change)."""
    with _dhcp_baseline_lock:
        if action == 'reset':
            _dhcp_baseline_save({})
            return {'success': True, 'reset': True, 'servers': {}}
        return {'success': True, 'servers': (_dhcp_baseline_load().get('servers') or {})}


def _parse_dhcp_discover(output):
    """Parse `nmap --script broadcast-dhcp-discover` output into a list of
    OFFERs: {server_id, router, dns[], offered_ip, lease, domain, iface}. Each
    'Response N of M' block is one responding DHCP server."""
    offers = []
    cur = None

    def _flush():
        if cur and (cur.get('server_id') or cur.get('offered_ip')):
            offers.append(cur)

    for raw in output.splitlines():
        line = raw.strip().lstrip('|_').strip()
        m = re.match(r'Response\s+\d+\s+of\s+\d+', line)
        if m:
            _flush()
            cur = {'server_id': None, 'router': None, 'dns': [],
                   'offered_ip': None, 'lease': None, 'domain': None, 'iface': None}
            continue
        if cur is None:
            continue
        m = re.match(r'Server Identifier:\s*(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            cur['server_id'] = m.group(1); continue
        m = re.match(r'Router:\s*(.+)', line)
        if m:
            cur['router'] = m.group(1).strip(); continue
        m = re.match(r'Domain Name Server:\s*(.+)', line)
        if m:
            cur['dns'] = [x.strip() for x in re.split(r'[,\s]+', m.group(1).strip()) if x.strip()]
            continue
        m = re.match(r'IP Offered:\s*(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            cur['offered_ip'] = m.group(1); continue
        m = re.match(r'IP Address Lease Time:\s*(.+)', line)
        if m:
            cur['lease'] = m.group(1).strip(); continue
        m = re.match(r'Domain Name:\s*(.+)', line)
        if m:
            cur['domain'] = m.group(1).strip(); continue
        m = re.match(r'Interface:\s*(\S+)', line)
        if m:
            cur['iface'] = m.group(1); continue
    _flush()
    return offers


def _dhcp_discover(interface, timeout_s=_DHCP_DISCOVER_TIMEOUT_S):
    """Provoke every DHCP server on the segment to OFFER, via nmap's
    broadcast-dhcp-discover. Returns (offers, error)."""
    if not _have('nmap'):
        return [], 'nmap is not installed (needed for rogue-DHCP discovery)'
    cmd = ['nmap', '--script', 'broadcast-dhcp-discover',
           '--script-args', f'broadcast-dhcp-discover.timeout={int(timeout_s)}']
    if interface and _valid_iface(interface):
        cmd += ['-e', interface]
    res = _run(cmd, timeout=int(timeout_s) + 25)
    if res['rc'] == 127:
        return [], 'nmap not found'
    return _parse_dhcp_discover(res['out']), None


def _parse_dhcp_capture(output):
    """Parse verbose `tcpdump` DHCP output into client-request stats:
    (requests, distinct_client_macs). Counts DISCOVER/REQUEST (client→server)
    and the distinct BOOTP client hardware addresses (chaddr) behind them —
    chaddr is what a starvation tool spoofs, so distinct chaddrs is the signal."""
    requests = 0
    clients = set()
    kind = None
    for raw in output.splitlines():
        line = raw.strip()
        m = re.search(r'DHCP-Message.*?:\s*(\w+)', line)
        if m:
            kind = m.group(1).lower()
            if kind in ('discover', 'request'):
                requests += 1
            continue
        m = re.search(r'Client-Ethernet-Address\s+([0-9a-fA-F:]{17})', line)
        if m and kind in ('discover', 'request'):
            clients.add(m.group(1).lower())
    return requests, clients


def _dhcp_capture(interface, seconds):
    """Passively capture DHCP client requests for `seconds` and return
    (requests, distinct_clients, error). No traffic generated."""
    if not _have('tcpdump'):
        return 0, 0, 'tcpdump is not installed (needed for starvation capture)'
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return 0, 0, 'no interface to capture on'
    cmd = ['tcpdump', '-i', iface, '-n', '-e', '-v', '-l',
           'udp and (port 67 or port 68)']
    # tcpdump has no built-in duration cap; run it under a timeout and read what
    # it buffered. SIGTERM (rc 124) is the normal, expected end of the window.
    res = _run(cmd, timeout=max(2, int(seconds)))
    if res['rc'] == 127:
        return 0, 0, 'tcpdump not found'
    requests, clients = _parse_dhcp_capture(res['out'])
    return requests, len(clients), None


def do_dhcp_guardian(interface=None, capture_seconds=6, learn=True, quick=False):
    """DHCP-snooping-style rogue-server + starvation detector (detection-only).

    quick=True skips the passive starvation capture (rogue-server discovery
    only) — used by the background integrity monitor and the e-Paper page so
    they stay fast. verdict: clean / suspicious / rogue / starvation."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    gw = _default_gateway()
    _, resolv_dns, _ = _read_resolv_conf()
    reasons = []
    verdict = 'clean'

    # --- (1) rogue / fake DHCP server -------------------------------------
    # quick mode (background monitor / e-Paper / "Check now") uses a shorter
    # OFFER wait — a legitimate local server answers in well under a second, so
    # 4s is plenty and keeps the interactive path snappy.
    offers, offer_err = _dhcp_discover(iface, 4 if quick else _DHCP_DISCOVER_TIMEOUT_S)
    server_ids = sorted({o['server_id'] for o in offers if o.get('server_id')})
    learned = False
    rogue_servers = []

    with _dhcp_baseline_lock:
        baseline = _dhcp_baseline_load()
        trusted = baseline.setdefault('servers', {})
        # First scan with exactly one server learns it as the trusted baseline
        # (mirrors the ARP gateway-baseline learn-on-first-run behaviour).
        if learn and not trusted and len(server_ids) == 1:
            sid = server_ids[0]
            o = next(o for o in offers if o.get('server_id') == sid)
            trusted[sid] = {'router': o.get('router'), 'dns': o.get('dns') or []}
            _dhcp_baseline_save(baseline)
            learned = True
        trusted_ids = set(trusted.keys())

    # A server that isn't the trusted one — or a trusted one whose offered
    # gateway changed — is rogue. If nothing is trusted yet, ≥2 servers is the
    # rogue signal on its own.
    for o in offers:
        sid = o.get('server_id')
        if not sid:
            continue
        base = trusted.get(sid)
        if trusted_ids and sid not in trusted_ids:
            rogue_servers.append(o)
            reasons.append(f"rogue DHCP server {sid} on the segment "
                           f"(offers gateway {o.get('router') or '?'}, "
                           f"DNS {', '.join(o.get('dns') or []) or '?'})")
        elif base and o.get('router') and base.get('router') and o['router'] != base['router']:
            rogue_servers.append(o)
            reasons.append(f"DHCP server {sid} changed the offered gateway from "
                           f"trusted {base['router']} to {o['router']} — DHCP steering")
        elif gw and o.get('router') and o['router'] != gw:
            # Offered gateway differs from the one actually in use — steering.
            rogue_servers.append(o)
            reasons.append(f"DHCP server {sid} offers gateway {o['router']}, "
                           f"but your active gateway is {gw} — possible DHCP steering")

    if not trusted_ids and len(server_ids) >= 2:
        reasons.append(f"{len(server_ids)} DHCP servers answered "
                       f"({', '.join(server_ids)}) — only one is legitimate")

    # Cross-check the active gateway's ARP binding: a rogue DHCP steer is far
    # more dangerous when the gateway MAC is also spoofed (full MITM).
    arp = {}
    try:
        arp = do_arp_check(learn=False)
    except Exception:
        arp = {}
    if rogue_servers and arp.get('verdict') == 'spoofed':
        reasons.append("gateway MAC is ALSO ARP-spoofed — combined DHCP+ARP "
                       "man-in-the-middle")

    # --- (2) starvation ----------------------------------------------------
    starv = {'requests': 0, 'clients': 0, 'captured': False, 'error': None}
    if not quick:
        req, clients, cap_err = _dhcp_capture(iface, capture_seconds)
        starv = {'requests': req, 'clients': clients,
                 'captured': cap_err is None, 'error': cap_err}
        if clients >= _DHCP_STARV_MIN_CLIENTS:
            reasons.append(f"{clients} distinct DHCP clients requested leases in "
                           f"{capture_seconds}s ({req} requests) — DHCP starvation "
                           "(pool-exhaustion) signature")

    # --- verdict -----------------------------------------------------------
    if starv['clients'] >= _DHCP_STARV_MIN_CLIENTS:
        verdict = 'starvation'
    elif rogue_servers or (not trusted_ids and len(server_ids) >= 2):
        verdict = 'rogue'
    elif offer_err and not offers:
        # No server answered at all — could be a static segment, or a pool that
        # a starvation attack already drained. Informational, not an alarm.
        verdict = 'clean'
        reasons.append(offer_err)
    elif not offers:
        reasons.append("no DHCP server answered — static addressing, or the "
                       "pool may be exhausted")

    return {
        'success': True, 'verdict': verdict, 'interface': iface,
        'gateway': gw, 'resolver_dns': resolv_dns,
        'servers': [{
            'server_id': o.get('server_id'), 'router': o.get('router'),
            'dns': o.get('dns') or [], 'offered_ip': o.get('offered_ip'),
            'lease': o.get('lease'), 'domain': o.get('domain'),
            'trusted': o.get('server_id') in trusted_ids,
            'rogue': o in rogue_servers,
        } for o in offers],
        'server_count': len(server_ids),
        'trusted_count': len(trusted_ids),
        'learned': learned,
        'rogue_count': len(rogue_servers),
        'arp_verdict': arp.get('verdict'),
        'starvation': starv,
        'reasons': reasons,
    }


# --------------------------------------------------------------------------
# DHCP Snooping (inline bridge) — enterprise-grade rogue-DHCP detection.
#
# When the Pi sits INLINE with two NICs bridged (rgsnoop0 = eth_a + eth_b), it
# sees every DHCP packet transiting the link, per ingress port. That unlocks the
# managed-switch "DHCP snooping" model, which is strictly stronger than the
# active-probe DHCP Guardian above:
#
#   * Trusted vs. untrusted ports. You designate the uplink NIC (toward the real
#     DHCP server) trusted and the client NIC untrusted. A DHCP *server* message
#     (OFFER/ACK/NAK) that ingresses the UNTRUSTED port is, by definition, a
#     rogue server — no baseline, no guessing, zero false positives.
#   * Binding table. From the OFFER/ACK it records client-MAC ↔ assigned-IP ↔
#     server ↔ lease ↔ ingress-port — the same table a switch keeps, and the
#     basis for spotting IP spoofing / feeding dynamic ARP inspection later.
#   * Starvation. Distinct client hardware addresses (chaddr) flooding DISCOVERs
#     on the untrusted side are counted directly off the wire.
#
# Detection-only for now (it never drops or rewrites a frame); inline *blocking*
# with an nftables/ebtables bridge rule is a deliberate future opt-in. Ingress
# port comes from `tcpdump -i any -Q in` (LINUX_SLL2 tags each packet with its
# interface). The bridge itself is optional — bring your own br0/SPAN, or use
# the guarded setup helper to enslave two wired NICs into rgsnoop0.
# --------------------------------------------------------------------------

_DHCP_SNOOP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'data', 'dhcp_snoop.json')
_dhcp_snoop_lock = threading.Lock()
_DHCP_SNOOP_BRIDGE = 'rgsnoop0'          # bridge the setup helper creates
_DHCP_SNOOP_WIRED_RE = re.compile(r'^(eth|en|usb)')   # eligible wired NICs


def _dhcp_snoop_load():
    try:
        with open(_DHCP_SNOOP_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _dhcp_snoop_save(d):
    try:
        os.makedirs(os.path.dirname(_DHCP_SNOOP_PATH), exist_ok=True)
        tmp = _DHCP_SNOOP_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _DHCP_SNOOP_PATH)
    except OSError:
        pass


def _iface_master(iface):
    """The bridge (or bond) an interface is enslaved to, or None."""
    res = _run(['ip', '-o', 'link', 'show', 'dev', iface], timeout=5)
    m = re.search(r'\bmaster\s+(\S+)', res['out'])
    return m.group(1) if m else None


def _bridge_members(bridge):
    """Interfaces enslaved to `bridge`."""
    res = _run(['ip', '-o', 'link', 'show', 'master', bridge], timeout=5)
    out = []
    for line in res['out'].splitlines():
        m = re.match(r'^\d+:\s+([^:@]+)', line)
        if m:
            out.append(m.group(1).strip())
    return out


def _list_bridges():
    res = _run(['ip', '-o', 'link', 'show', 'type', 'bridge'], timeout=5)
    out = []
    for line in res['out'].splitlines():
        m = re.match(r'^\d+:\s+([^:@]+)', line)
        if m:
            name = m.group(1).strip()
            out.append({'name': name, 'members': _bridge_members(name)})
    return out


def _wired_nics():
    """Physical wired NICs eligible to be bridged (eth*/en*/usb*), excluding the
    default-route interface and anything already in a non-snoop bridge."""
    names = []
    for n in _list_iface_names(include_virtual=False):
        if _DHCP_SNOOP_WIRED_RE.match(n) and not _is_wireless(n):
            names.append(n)
    return names


def do_dhcp_snoop_config(trusted=None, untrusted=None):
    """Get or set the trusted/untrusted port designation (persisted). Pass both
    to set; pass neither to just read."""
    with _dhcp_snoop_lock:
        cfg = _dhcp_snoop_load()
        if trusted is not None and untrusted is not None:
            if not _valid_iface(trusted) or not _valid_iface(untrusted):
                return {'success': False, 'error': 'invalid interface name'}
            if trusted == untrusted:
                return {'success': False, 'error': 'trusted and untrusted must differ'}
            cfg['trusted'] = trusted
            cfg['untrusted'] = untrusted
            _dhcp_snoop_save(cfg)
        return {'success': True, 'trusted': cfg.get('trusted'),
                'untrusted': cfg.get('untrusted')}


def do_dhcp_snoop_status():
    """Report the inline-snooping setup: bridges present, eligible wired NICs,
    the default-route interface (never bridged), and the trusted/untrusted
    config — everything the UI needs to guide wiring."""
    bridges = _list_bridges()
    snoop_bridge = next((b for b in bridges if b['name'] == _DHCP_SNOOP_BRIDGE), None)
    with _dhcp_snoop_lock:
        cfg = _dhcp_snoop_load()
    return {
        'success': True,
        'bridges': bridges,
        'snoop_bridge': snoop_bridge,
        'wired_nics': _wired_nics(),
        'default_iface': _default_route_iface(),
        'trusted': cfg.get('trusted'),
        'untrusted': cfg.get('untrusted'),
        'inline_ready': bool(snoop_bridge and len(snoop_bridge['members']) >= 2),
    }


def do_dhcp_snoop_setup(iface_a, iface_b, action='create'):
    """Guarded bridge setup: enslave two wired NICs into rgsnoop0 so the box is
    inline. Refuses the default-route / wireless / management interface so it
    can't cut its own link. Detection-only bridge (no IP on it)."""
    if action == 'destroy':
        with _dhcp_snoop_lock:
            for m in _bridge_members(_DHCP_SNOOP_BRIDGE):
                _run(['ip', 'link', 'set', m, 'nomaster'], timeout=5)
                _run(['ip', 'link', 'set', m, 'down'], timeout=5)
            _run(['ip', 'link', 'set', _DHCP_SNOOP_BRIDGE, 'down'], timeout=5)
            r = _run(['ip', 'link', 'del', _DHCP_SNOOP_BRIDGE], timeout=5)
        if r['rc'] not in (0, 1):
            return {'success': False, 'error': r['err'] or 'failed to remove bridge'}
        return {'success': True, 'destroyed': True}

    # ---- create: validate hard before touching any link --------------------
    default_if = _default_route_iface()
    for i in (iface_a, iface_b):
        if not _valid_iface(i):
            return {'success': False, 'error': f'invalid interface {i!r}'}
        if not _DHCP_SNOOP_WIRED_RE.match(i) or _is_wireless(i):
            return {'success': False, 'error': f'{i} is not an eligible wired NIC'}
        if i == default_if:
            return {'success': False,
                    'error': f'{i} carries the default route — refusing to bridge the '
                             'management interface (you would cut your own link)'}
        if i not in _list_iface_names(include_virtual=True):
            return {'success': False, 'error': f'{i} not found'}
        m = _iface_master(i)
        if m and m != _DHCP_SNOOP_BRIDGE:
            return {'success': False, 'error': f'{i} is already enslaved to {m}'}
    if iface_a == iface_b:
        return {'success': False, 'error': 'need two different interfaces'}

    with _dhcp_snoop_lock:
        # Create the bridge if absent; enslave both members; bring everything up.
        if _DHCP_SNOOP_BRIDGE not in [b['name'] for b in _list_bridges()]:
            r = _run(['ip', 'link', 'add', 'name', _DHCP_SNOOP_BRIDGE, 'type', 'bridge'], timeout=5)
            if r['rc'] != 0:
                return {'success': False, 'error': r['err'] or 'failed to create bridge'}
        for i in (iface_a, iface_b):
            _run(['ip', 'link', 'set', i, 'master', _DHCP_SNOOP_BRIDGE], timeout=5)
            _run(['ip', 'link', 'set', i, 'up'], timeout=5)
        _run(['ip', 'link', 'set', _DHCP_SNOOP_BRIDGE, 'up'], timeout=5)
        members = _bridge_members(_DHCP_SNOOP_BRIDGE)

    return {'success': True, 'bridge': _DHCP_SNOOP_BRIDGE, 'members': members}


# DHCP message types by the direction they flow, so we can tell a *server*
# message (only a DHCP server sends these) from a *client* request.
_DHCP_SERVER_MSGS = {'offer', 'ack', 'nak'}
_DHCP_CLIENT_MSGS = {'discover', 'request', 'decline', 'release', 'inform'}


def _parse_dhcp_snoop(output, members=None):
    """Parse `tcpdump -i any -Q in -e -n -v` DHCP output into per-packet records:
    {iface, src_ip, src_port, dst_port, is_server, msg_type, chaddr, yiaddr,
     server_id, router, lease}. `members` (if given) filters to those ingress
     interfaces. Each packet is a header line (timestamp + ingress iface + IP
     src>dst) followed by indented option lines until the next header."""
    packets = []
    cur = None

    def _flush():
        if cur and cur.get('msg_type'):
            packets.append(cur)

    for raw in output.splitlines():
        # Header line: "<ts> <iface> In  ifindex N <mac> ethertype ...: IP a.b.c.d.p > e.f.g.h.q: ..."
        h = re.match(r'^\d\d:\d\d:\d\d\.\d+\s+(\S+)\s+In\b', raw)
        if h:
            _flush()
            iface = h.group(1)
            cur = None
            mip = re.search(r'\bIP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)', raw)
            if not mip:
                continue
            src_port, dst_port = int(mip.group(2)), int(mip.group(4))
            if {src_port, dst_port} & {67, 68} == set():
                continue
            if members is not None and iface not in members:
                continue
            cur = {'iface': iface, 'src_ip': mip.group(1), 'src_port': src_port,
                   'dst_ip': mip.group(3), 'dst_port': dst_port,
                   'is_server': src_port == 67, 'msg_type': None,
                   'chaddr': None, 'yiaddr': None, 'server_id': None,
                   'router': None, 'lease': None}
            continue
        if cur is None:
            continue
        line = raw.strip()
        m = re.search(r'DHCP-Message.*?:\s*(\w+)', line)
        if m:
            cur['msg_type'] = m.group(1).lower(); continue
        m = re.search(r'Client-Ethernet-Address\s+([0-9a-fA-F:]{17})', line)
        if m:
            cur['chaddr'] = m.group(1).lower(); continue
        m = re.match(r'Your-IP\s+(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            cur['yiaddr'] = m.group(1); continue
        m = re.search(r'Server-ID.*?:\s*(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            cur['server_id'] = m.group(1); continue
        m = re.search(r'(?:Default-Gateway|Router).*?:\s*(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            cur['router'] = m.group(1); continue
        m = re.search(r'Lease-Time.*?:\s*(\d+)', line)
        if m:
            cur['lease'] = int(m.group(1)); continue
    _flush()
    return packets


def _dhcp_snoop_capture(members, seconds):
    """Passively capture inbound DHCP on all interfaces for `seconds`, tagged by
    ingress port. Returns (packets, error). No traffic generated."""
    if not _have('tcpdump'):
        return [], 'tcpdump is not installed'
    cmd = ['tcpdump', '-i', 'any', '-Q', 'in', '-n', '-e', '-v', '-l',
           'udp and (port 67 or port 68)']
    res = _run(cmd, timeout=max(2, int(seconds)))
    if res['rc'] == 127:
        return [], 'tcpdump not found'
    return _parse_dhcp_snoop(res['out'], members=members), None


def do_dhcp_snoop(trusted=None, untrusted=None, seconds=20):
    """Inline DHCP-snooping pass. Captures real DHCP off the wire per ingress
    port and applies the trusted/untrusted model:

      * any DHCP *server* message on the UNTRUSTED port  -> rogue (definitive)
      * OFFER/ACK anywhere                               -> binding-table entry
      * many distinct chaddrs in DISCOVERs               -> starvation

    verdict: clean / rogue / starvation. Detection-only."""
    with _dhcp_snoop_lock:
        cfg = _dhcp_snoop_load()
    trusted = trusted or cfg.get('trusted')
    untrusted = untrusted or cfg.get('untrusted')
    if not trusted or not untrusted:
        return {'success': False,
                'error': 'trusted and untrusted ports are not set — designate them first',
                'need_config': True}

    members = [trusted, untrusted]
    packets, err = _dhcp_snoop_capture(members, seconds)
    if err:
        return {'success': False, 'error': err}

    reasons = []
    rogue_msgs = []          # server messages seen on the untrusted port
    bindings = {}            # chaddr -> latest binding
    servers = {}             # server_id/ip -> {port, trusted}
    client_macs = set()

    for p in packets:
        on_trusted = p['iface'] == trusted
        if p['is_server'] and p['msg_type'] in _DHCP_SERVER_MSGS:
            sid = p.get('server_id') or p.get('src_ip')
            servers.setdefault(sid, {'port': p['iface'],
                                     'trusted': on_trusted,
                                     'router': p.get('router')})
            if not on_trusted:
                rogue_msgs.append(p)
            if p['msg_type'] in ('offer', 'ack') and p.get('chaddr'):
                bindings[p['chaddr']] = {
                    'mac': p['chaddr'], 'ip': p.get('yiaddr'),
                    'server': sid, 'router': p.get('router'),
                    'lease': p.get('lease'), 'port': p['iface'],
                    'via': p['msg_type']}
        elif p['msg_type'] in _DHCP_CLIENT_MSGS and p.get('chaddr'):
            client_macs.add(p['chaddr'])

    rogue_servers = sorted({(m.get('server_id') or m['src_ip']) for m in rogue_msgs})
    for sid in rogue_servers:
        info = servers.get(sid, {})
        reasons.append(f"rogue DHCP server {sid} answering on the UNTRUSTED port "
                       f"{untrusted}" + (f" (offers gateway {info.get('router')})"
                                         if info.get('router') else "")
                       + " — a DHCP server must never appear on the client side")

    starvation = len(client_macs)
    if starvation >= _DHCP_STARV_MIN_CLIENTS:
        reasons.append(f"{starvation} distinct DHCP clients requested leases in "
                       f"{seconds}s — starvation (pool-exhaustion) signature")

    verdict = 'clean'
    if rogue_servers:
        verdict = 'rogue'
    elif starvation >= _DHCP_STARV_MIN_CLIENTS:
        verdict = 'starvation'
    if not packets:
        reasons.append("no DHCP seen on the wire during the window — quiet segment, "
                       "or the box may not actually be inline (bridge the two NICs)")

    return {
        'success': True, 'verdict': verdict,
        'trusted': trusted, 'untrusted': untrusted,
        'packets': len(packets),
        'servers': [{'server': sid, 'port': i['port'], 'trusted': i['trusted'],
                     'router': i.get('router'),
                     'rogue': not i['trusted']} for sid, i in servers.items()],
        'bindings': list(bindings.values()),
        'binding_count': len(bindings),
        'rogue_count': len(rogue_servers),
        'client_count': starvation,
        'reasons': reasons,
    }


# --------------------------------------------------------------------------
# Interfaces: link speed / duplex / auto-neg, static-vs-DHCP, IP/CIDR, VLAN
# --------------------------------------------------------------------------

# Container/virtual interfaces that are just noise on the Interfaces tab.
_VIRTUAL_IFACE_RE = re.compile(r'^(veth|docker|br-|virbr|vmnet|vboxnet|vnet|macvtap)')


def _list_iface_names(include_virtual=False):
    res = _run(['ip', '-o', 'link', 'show'], timeout=5)
    names = []
    for line in res['out'].splitlines():
        m = re.match(r'^\d+:\s+([^:@]+)', line)
        if m:
            name = m.group(1).strip()
            if name == 'lo':
                continue
            if not include_virtual and _VIRTUAL_IFACE_RE.match(name):
                continue
            names.append(name)
    return names


def _iface_link_details(iface):
    """MAC, operstate, and VLAN info from `ip -d link show`."""
    res = _run(['ip', '-d', 'link', 'show', 'dev', iface], timeout=5)
    out = res['out']
    d = {'mac': None, 'operstate': None, 'vlan_id': None, 'vlan_proto': None}
    m = re.search(r'state (\S+)', out)
    if m:
        d['operstate'] = m.group(1)
    m = re.search(r'link/\w+\s+([0-9a-fA-F:]{17})', out)
    if m:
        d['mac'] = m.group(1)
    m = re.search(r'vlan protocol (\S+) id (\d+)', out)
    if m:
        d['vlan_proto'] = m.group(1)
        d['vlan_id'] = int(m.group(2))
    return d


def _iface_addrs(iface):
    v4 = []
    res = _run(['ip', '-o', '-4', 'addr', 'show', 'dev', iface], timeout=5)
    for line in res['out'].splitlines():
        m = re.search(r'inet (\S+)', line)
        if m:
            v4.append(m.group(1))
    v6 = []
    res6 = _run(['ip', '-o', '-6', 'addr', 'show', 'dev', iface], timeout=5)
    for line in res6['out'].splitlines():
        m = re.search(r'inet6 (\S+)', line)
        if m:
            v6.append(m.group(1))
    return v4, v6


def _iface_ethtool(iface):
    """Speed / duplex / auto-negotiation / link. Wireless & virtual ifaces
    typically don't support this -> fields stay None."""
    d = {'speed': None, 'duplex': None, 'autoneg': None, 'link_detected': None}
    res = _run(['ethtool', iface], timeout=6)
    if res['rc'] != 0:
        return d
    out = res['out']
    m = re.search(r'Speed:\s*(.+)', out)
    if m and 'Unknown' not in m.group(1):
        d['speed'] = m.group(1).strip()
    m = re.search(r'Duplex:\s*(.+)', out)
    if m and 'Unknown' not in m.group(1):
        d['duplex'] = m.group(1).strip()
    m = re.search(r'Auto-negotiation:\s*(\w+)', out)
    if m:
        d['autoneg'] = (m.group(1).strip().lower() == 'on')
    m = re.search(r'Link detected:\s*(\w+)', out)
    if m:
        d['link_detected'] = (m.group(1).strip().lower() == 'yes')
    return d


def _iface_ip_method(iface, v4):
    """Determine DHCP vs static via nmcli; fall back to APIPA / heuristic.

    Returns 'dhcp', 'static', 'dhcp-failed' (APIPA 169.254), 'link-down', or
    'unknown'."""
    # APIPA: got a 169.254 address only -> DHCP attempted and failed.
    if v4 and all(a.startswith('169.254.') for a in v4):
        return 'dhcp-failed'
    # No address at all: report link-down without asking nmcli. Skipping the
    # two nmcli calls (up to ~12 s each worst-case) keeps the Interfaces tab
    # fast on boxes with several disconnected NICs (eth0 unplugged, usb0, ...).
    if not v4:
        return 'link-down'
    if _have('nmcli'):
        conn = None
        res = _run(['nmcli', '-t', '-g', 'GENERAL.CONNECTION', 'device', 'show', iface],
                   timeout=6)
        if res['rc'] == 0:
            conn = res['out'].strip()
        if conn and conn != '--':
            r2 = _run(['nmcli', '-t', '-g', 'ipv4.method', 'connection', 'show', conn],
                      timeout=6)
            method = r2['out'].strip()
            if method == 'auto':
                return 'dhcp'
            if method == 'manual':
                return 'static'
    if not v4:
        return 'link-down'
    return 'unknown'


def _is_wireless(iface):
    import os
    return os.path.isdir(f'/sys/class/net/{iface}/wireless')


# Interface name prefixes that denote a VPN / tunnel link (not a physical NIC).
_VPN_IFACE_PREFIXES = ('tun', 'tap', 'wg', 'tailscale', 'ppp', 'ipsec',
                       'zt', 'nordlynx', 'proton', 'gpd', 'utun', 'vpn', 'nebula')

# VPN *product* recognised anywhere in the interface name (most specific).
_VPN_PRODUCTS = (
    ('tailscale', 'Tailscale'), ('nordlynx', 'NordVPN'), ('mullvad', 'Mullvad'),
    ('proton', 'ProtonVPN'), ('zerotier', 'ZeroTier'), ('nebula', 'Nebula'),
    ('globalprotect', 'GlobalProtect'), ('expressvpn', 'ExpressVPN'),
)
# Generic VPN kind by interface-name prefix (fallback when the product is
# unknown and the link kind is only a bare tun/tap).
_VPN_PREFIX_KINDS = (
    ('wg', 'WireGuard'), ('tun', 'OpenVPN'), ('tap', 'OpenVPN'),
    ('ppp', 'PPP/L2TP'), ('ipsec', 'IPsec'), ('zt', 'ZeroTier'),
    ('gpd', 'GlobalProtect'), ('utun', 'VPN tunnel'), ('vpn', 'VPN tunnel'),
)
# Tunnel link kinds from `ip -d link show` (authoritative, needs no extra tools).
# ('strong' kinds are unambiguously a VPN/tunnel; bare tun/tap are weaker.)
_VPN_LINK_KINDS = (
    ('wireguard', 'WireGuard'), ('vti6', 'IPsec/VTI'), ('vti', 'IPsec/VTI'),
    ('gretap', 'GRE'), ('gre', 'GRE'), ('ip6tnl', 'IPv6 tunnel'),
    ('ipip', 'IPIP'), ('sit', 'SIT tunnel'), ('ppp', 'PPP'),
    ('tun', 'tunnel'), ('tap', 'tunnel'),
)
_VPN_STRONG_KINDS = ('WireGuard', 'IPsec/VTI', 'GRE', 'IPv6 tunnel',
                     'IPIP', 'SIT tunnel', 'PPP')


def _iface_arphrd_none(iface):
    """True if the interface's link type is ARPHRD_NONE (65534) -- typical of
    point-to-point tunnels (tun/wireguard/tailscale)."""
    try:
        with open(f'/sys/class/net/{iface}/type') as f:
            return f.read().strip() == '65534'
    except OSError:
        return False


def _iface_link_kind(name):
    """Authoritative tunnel kind from `ip -d link show` (iproute2 is always
    present), or None. Returns a friendly name like 'WireGuard' / 'GRE'."""
    res = _run(['ip', '-d', 'link', 'show', 'dev', name], timeout=5)
    if res['rc'] != 0:
        return None
    for tok, friendly in _VPN_LINK_KINDS:
        if re.search(r'(?:^|\s)' + tok + r'(?:\s|$)', res['out'], re.M):
            return friendly
    return None


def _wg_interfaces():
    """Names of active WireGuard interfaces (definitive, catches custom-named
    tunnels the running iproute2 may not tag as 'wireguard'). Needs `wg`."""
    if not _have('wg'):
        return frozenset()
    res = _run(['wg', 'show', 'interfaces'], timeout=5)
    return frozenset(res['out'].split()) if res['rc'] == 0 else frozenset()


def _wg_endpoint(name):
    """WireGuard peer endpoint (the VPN server's IP:port), if `wg` is available."""
    if not _have('wg'):
        return None
    res = _run(['wg', 'show', name, 'endpoints'], timeout=5)
    if res['rc'] != 0:
        return None
    for line in res['out'].splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1] not in ('(none)', 'none', ''):
            return parts[-1]
    return None


def _iface_vpn_info(name):
    """Rich VPN/tunnel classification of an interface.

    Returns {is_vpn, kind, endpoint}: `kind` names the VPN technology/product
    (WireGuard, Tailscale, OpenVPN, GRE, ...) and `endpoint` is the peer/server
    address when it can be determined (WireGuard via `wg`)."""
    n = name.lower()
    product = next((f for sub, f in _VPN_PRODUCTS if sub in n), None)
    link_kind = _iface_link_kind(name)
    prefix_kind = next((f for pre, f in _VPN_PREFIX_KINDS if n.startswith(pre)), None)
    arphrd_none = _iface_arphrd_none(name)
    strong = link_kind in _VPN_STRONG_KINDS
    # Definitive: a tun/tap character device exposes tun_flags in sysfs. This
    # catches OpenVPN in BOTH tun and tap (bridged) mode — a tap is ARPHRD_ETHER,
    # so the arphrd_none heuristic alone missed it. (VM taps like vnet*/macvtap
    # are filtered out of the interface list before typing.)
    is_tuntap = os.path.exists(f'/sys/class/net/{name}/tun_flags')
    # Definitive WireGuard, even for custom-named tunnels on an iproute2 that
    # doesn't print the 'wireguard' link kind.
    is_wg = (link_kind == 'WireGuard') or (arphrd_none and name in _wg_interfaces())

    is_vpn = bool(product or prefix_kind or strong or is_wg or is_tuntap
                  or n.startswith(_VPN_IFACE_PREFIXES)
                  or (link_kind and arphrd_none))
    if not is_vpn:
        return {'is_vpn': False, 'kind': None, 'endpoint': None}

    kind = (product
            or ('WireGuard' if is_wg else None)
            or (link_kind if strong else None)
            or prefix_kind
            or (link_kind if link_kind and link_kind != 'tunnel' else None)
            or 'VPN tunnel')
    endpoint = _wg_endpoint(name) if kind == 'WireGuard' else None
    return {'is_vpn': True, 'kind': kind, 'endpoint': endpoint}


def _is_vpn(iface):
    """Backwards-compatible boolean wrapper around _iface_vpn_info."""
    return _iface_vpn_info(iface)['is_vpn']


def do_interfaces(include_virtual=False):
    interfaces = []
    for name in _list_iface_names(include_virtual=include_virtual):
        link = _iface_link_details(name)
        v4, v6 = _iface_addrs(name)
        vpn = _iface_vpn_info(name)
        if _is_wireless(name):
            itype = 'wifi'
        elif vpn['is_vpn']:
            itype = 'vpn'
        else:
            itype = 'ethernet'
        eth = _iface_ethtool(name) if itype == 'ethernet' else {
            'speed': None, 'duplex': None, 'autoneg': None, 'link_detected': None}
        method = _iface_ip_method(name, v4)
        interfaces.append({
            'name': name,
            'type': itype,
            'vpn_kind': vpn['kind'],
            'vpn_endpoint': vpn['endpoint'],
            'mac': link['mac'],
            'operstate': link['operstate'],
            'ipv4': v4,
            'ipv6': [a for a in v6 if not a.lower().startswith('fe80')],
            'ip_method': method,
            'speed': eth['speed'],
            'duplex': eth['duplex'],
            'autoneg': eth['autoneg'],
            'link_detected': eth['link_detected'],
            'vlan_id': link['vlan_id'],
            'vlan_proto': link['vlan_proto'],
        })
    return {'success': True, 'interfaces': interfaces, 'count': len(interfaces)}


# --------------------------------------------------------------------------
# Network identity: DNS search domain(s), nameservers, hostname/FQDN, gateway
# --------------------------------------------------------------------------

def _read_resolv_conf():
    """Parse /etc/resolv.conf for search domains and nameservers.

    Returns (domains, nameservers, stub) where `stub` is True when the only
    nameserver is the systemd-resolved stub (127.0.0.53) -- in that case the
    real upstream servers must come from nmcli/resolvectl instead."""
    domains, nameservers = [], []
    try:
        with open('/etc/resolv.conf', 'r') as f:
            text = f.read()
    except OSError:
        return domains, nameservers, False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('#') or not line:
            continue
        parts = line.split()
        if parts[0] in ('search', 'domain'):
            for d in parts[1:]:
                if d not in domains:
                    domains.append(d)
        elif parts[0] == 'nameserver' and len(parts) > 1:
            if parts[1] not in nameservers:
                nameservers.append(parts[1])
    stub = nameservers == ['127.0.0.53'] or nameservers == ['127.0.0.1']
    return domains, nameservers, stub


def _nmcli_global_values(field):
    """Collect values for an nmcli field (e.g. IP4.DOMAINS, IP4.DNS) across all
    devices. nmcli prints repeated keys as `FIELD[1]:value`."""
    vals = []
    if not _have('nmcli'):
        return vals
    res = _run(['nmcli', '-t', '-f', field, 'device', 'show'], timeout=6)
    if res['rc'] != 0:
        return vals
    for line in res['out'].splitlines():
        if ':' not in line:
            continue
        _, _, v = line.partition(':')
        v = v.strip()
        if v and v != '--' and v not in vals:
            vals.append(v)
    return vals


def _default_gateway():
    """Return the IPv4 default gateway IP, or None."""
    res = _run(['ip', '-4', 'route', 'show', 'default'], timeout=5)
    m = re.search(r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)', res['out'])
    return m.group(1) if m else None


def _iface_gateway(iface):
    """The IPv4 default gateway reachable via ONE interface (that segment's
    own DHCP gateway on a multi-homed box), or None when the segment offers no
    default route. A higher-metric default (the non-active uplink) still
    counts — that's exactly the 'the one I'm testing' case."""
    res = _run(['ip', '-4', 'route', 'show', 'default', 'dev', iface], timeout=5)
    m = re.search(r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)', res['out'])
    if m:
        return m.group(1)
    # Last resort: any 'via' route on the device (classless static routes).
    res = _run(['ip', '-4', 'route', 'show', 'dev', iface], timeout=5)
    m = re.search(r'\bvia\s+(\d+\.\d+\.\d+\.\d+)', res['out'])
    return m.group(1) if m else None


def _iface_dns(iface):
    """Per-link nameservers + search domains for one interface, from
    systemd-resolved (resolvectl) or NetworkManager — i.e. what THAT
    interface's DHCP lease advertised, not the merged global view.
    Returns (domains, nameservers, source_or_None)."""
    domains, ns = [], []
    if _have('resolvectl'):
        r = _run(['resolvectl', 'dns', iface], timeout=5)
        if r['rc'] == 0:
            # "Link 3 (wlan1): 192.168.8.1 fd00::1"
            _, _, after = r['out'].partition(':')
            for tok in after.split():
                if tok not in ns:
                    ns.append(tok)
        r = _run(['resolvectl', 'domain', iface], timeout=5)
        if r['rc'] == 0:
            _, _, after = r['out'].partition(':')
            for tok in after.split():
                tok = tok.lstrip('~')
                if tok and tok != '.' and tok not in domains:
                    domains.append(tok)
        if ns or domains:
            return domains, ns, 'resolvectl (per-link)'
    if _have('nmcli'):
        r = _run(['nmcli', '-t', '-f', 'IP4.DNS,IP4.DOMAINS', 'device', 'show',
                  iface], timeout=6)
        if r['rc'] == 0:
            for line in r['out'].splitlines():
                key, _, v = line.partition(':')
                v = v.strip()
                if not v or v == '--':
                    continue
                if key.startswith('IP4.DNS') and v not in ns:
                    ns.append(v)
                elif key.startswith('IP4.DOMAINS') and v not in domains:
                    domains.append(v)
        if ns or domains:
            return domains, ns, 'nmcli (per-device)'
    return domains, ns, None


def _default_route_iface():
    """Return the interface carrying the IPv4 default route, or None. Used to
    tell whether this host's internet traffic egresses through a VPN tunnel."""
    res = _run(['ip', '-4', 'route', 'show', 'default'], timeout=5)
    # First (lowest-metric) default route is the active one.
    m = re.search(r'default\b.*?\bdev\s+(\S+)', res['out'])
    return m.group(1) if m else None


def _capture_iface(preferred=None):
    """Best interface for segment-scoped passive capture (the L2/L3 Watch
    scanners). Order: the caller's/configured preference, then a wired
    (non-wireless, non-virtual) interface with link up — preferring the
    default-route interface when it is itself wired — then the default-route
    interface. The wired preference matters for the sensor deployment: Ragnar
    plugged into a switch port to watch it (mirror/SPAN or isolated VLAN, no
    gateway on that leg) while managed over WiFi — the default route sits on
    wlan0, but STP/DTP/CDP/VTP/FHRP frames only exist on the cable."""
    if _valid_iface(preferred or ''):
        return preferred
    wired = []
    for name in _list_iface_names(include_virtual=False):
        if _is_wireless(name) or name.startswith(('tun', 'tap', 'wg', 'zt', 'tailscale')):
            continue
        try:
            with open(f'/sys/class/net/{name}/carrier') as f:
                if f.read().strip() == '1':
                    wired.append(name)
        except OSError:      # admin-down or vanished — not a candidate
            continue
    dflt = _default_route_iface()
    if wired:
        return dflt if dflt in wired else sorted(wired)[0]
    return dflt


# Substrings that mark a public egress as a commercial-VPN / VPN-hosting ASN.
# Brand names are high-confidence; the trailing hosting backbones (M247,
# DataCamp/DataPacket, 31173 = Mullvad's operator) are where most consumer VPNs
# terminate, so a *public egress* on them is very likely a VPN -- reported as
# best-effort ("likely VPN").
_VPN_PROVIDER_HINTS = (
    'mullvad', 'nordvpn', 'expressvpn', 'protonvpn', 'proton ag', 'surfshark',
    'cyberghost', 'ipvanish', 'tunnelbear', 'windscribe', 'vyprvpn', 'hide.me',
    'purevpn', 'torguard', 'azirevpn', 'perfect privacy', 'mozilla vpn',
    'private internet access', 'privateinternetaccess',
    'm247', 'datacamp', 'datapacket', '31173',
)


def _vpn_provider_match(*fields):
    """Return the matched VPN-provider hint if any egress field looks like a VPN
    provider/hosting ASN, else None."""
    hay = ' '.join(str(f) for f in fields if f).lower()
    return next((k for k in _VPN_PROVIDER_HINTS if k in hay), None)


# --------------------------------------------------------------------------
# Known-VPN egress IP ranges (X4BNet lists_vpn, ASN-derived, rebuilt upstream
# daily). This is the signal that catches a VPN running on the *router*: the
# public egress IP is the VPN server's no matter where the tunnel terminates,
# so an IP-range match works even when Ragnar's own NIC looks ordinary and
# the ISP-name match misses (most VPN ASNs don't carry a brand name).
# Synced to a local file and checked offline -- no per-lookup network call.
# --------------------------------------------------------------------------

_VPN_LIST_URL = 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt'
_VPN_LIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'data', 'vpn_ip_ranges.txt')
_VPN_LIST_MAX_AGE = 7 * 24 * 3600  # ASN-derived, moves slowly; weekly is plenty
_VPN_LIST_MIN_BYTES = 10000        # sanity floor -- the real list is ~150 KB
_vpn_list_lock = threading.Lock()
_vpn_list_ranges = None            # sorted [(first_int, last_int)], parsed cache
_vpn_list_mtime = None             # mtime the cache was parsed from


def _vpn_list_refresh():
    """Ensure a reasonably fresh local copy of the VPN-range list; download
    (atomically) when missing or older than _VPN_LIST_MAX_AGE. Returns the
    path if a usable -- possibly stale -- file exists afterwards, else None."""
    try:
        if time.time() - os.path.getmtime(_VPN_LIST_PATH) < _VPN_LIST_MAX_AGE:
            return _VPN_LIST_PATH
    except OSError:
        pass
    if _have('curl'):
        try:
            os.makedirs(os.path.dirname(_VPN_LIST_PATH), exist_ok=True)
        except OSError:
            pass
        tmp = _VPN_LIST_PATH + '.tmp'
        res = _run(['curl', '-sf', '--max-time', '20', '-o', tmp, _VPN_LIST_URL],
                   timeout=25)
        try:
            if res['rc'] == 0 and os.path.getsize(tmp) >= _VPN_LIST_MIN_BYTES:
                os.replace(tmp, _VPN_LIST_PATH)
                return _VPN_LIST_PATH
            os.unlink(tmp)
        except OSError:
            pass
    return _VPN_LIST_PATH if os.path.exists(_VPN_LIST_PATH) else None


def _vpn_list_load():
    """Sorted (first, last) int ranges from the cached list, reparsed only when
    the file changes. Returns None when no list is available (never synced and
    currently offline)."""
    global _vpn_list_ranges, _vpn_list_mtime
    with _vpn_list_lock:
        path = _vpn_list_refresh()
        if not path:
            return None
        try:
            mtime = os.path.getmtime(path)
            if _vpn_list_ranges is not None and mtime == _vpn_list_mtime:
                return _vpn_list_ranges
            ranges = []
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                    except ValueError:
                        continue
                    if net.version == 4:
                        ranges.append((int(net.network_address),
                                       int(net.broadcast_address)))
        except OSError:
            return _vpn_list_ranges  # keep whatever was parsed before
        ranges.sort()
        _vpn_list_ranges = ranges
        _vpn_list_mtime = mtime
        return _vpn_list_ranges


def _vpn_ip_lookup(ip):
    """Is this public IP inside a known VPN-provider range? True/False, or
    None when it can't be checked (no list available, or not an IPv4)."""
    try:
        n = int(ipaddress.IPv4Address(ip))
    except (ValueError, TypeError):
        return None
    ranges = _vpn_list_load()
    if not ranges:
        return None
    i = bisect.bisect_right(ranges, (n, 0xFFFFFFFF)) - 1
    return i >= 0 and ranges[i][1] >= n


def _tor_exit_check(iface):
    """Authoritatively detect whether egress through `iface` leaves via a Tor
    exit node, by asking the Tor Project's own checker (which sees our exit IP).

    This is the only reliable way to catch Tor/VPN running on the *router*: in
    that case Ragnar's own interface is an ordinary LAN NIC, so the interface
    heuristics and the commercial-VPN ISP name match both miss it. Bound to the
    interface like the geo lookup. Returns True/False, or None if the check
    couldn't be performed (offline / curl missing)."""
    if not _have('curl'):
        return None
    res = _run(['curl', '-s', '--max-time', '8', '--interface', iface,
                'https://check.torproject.org/api/ip'], timeout=12)
    if res['rc'] == 0 and res['out'].strip():
        try:
            return bool(json.loads(res['out']).get('IsTor'))
        except ValueError:
            pass
    return None


def _reverse_dns(ip):
    """Reverse-DNS an IP via getent (honours nsswitch, bounded by _run's
    timeout). Returns the PTR hostname or None."""
    if not ip:
        return None
    res = _run(['getent', 'hosts', ip], timeout=5)
    if res['rc'] != 0:
        return None
    # Format: "192.168.1.1   gateway.lan alias1 alias2"
    parts = res['out'].split()
    if len(parts) >= 2 and parts[1] != ip:
        return parts[1]
    return None


def do_network_identity(interface=None):
    """Best-effort identity of the network Ragnar is attached to: DNS search
    domain(s), nameservers, this host's name/FQDN, and the default gateway
    (with reverse-DNS). No single source is authoritative, so several are
    merged and the provenance is reported.

    With `interface` set, the gateway, nameservers and search domains are
    scoped to THAT interface (its own routes + DHCP lease), so a second test
    uplink can be inspected while another NIC carries the default route.
    Hostname/FQDN stay host-global."""
    sources = []
    stub = False

    if interface:
        domains, nameservers, src = _iface_dns(interface)
        if src:
            sources.append(src)
        if not (nameservers or domains):
            # No per-link DNS source on this system (no resolved/NM manages
            # the iface) — fall back to the global view, flagged as such.
            domains, nameservers, stub = _read_resolv_conf()
            sources.append('resolv.conf (global fallback — no per-link DNS source)')
    else:
        rc_domains, rc_ns, stub = _read_resolv_conf()

        # Search domains: union of resolv.conf and NetworkManager (DHCP option
        # 15 / 119). NM is preferred when resolv.conf is the systemd stub.
        domains = list(rc_domains)
        for d in _nmcli_global_values('IP4.DOMAINS'):
            if d not in domains:
                domains.append(d)
        if rc_domains:
            sources.append('resolv.conf')
        if _have('nmcli'):
            sources.append('nmcli')

        # Nameservers: resolv.conf, unless it only holds the local stub --
        # then use the upstream servers NetworkManager learned from DHCP.
        nameservers = list(rc_ns)
        nm_ns = _nmcli_global_values('IP4.DNS')
        if stub or not nameservers:
            nameservers = nm_ns or nameservers
        else:
            for n in nm_ns:
                if n not in nameservers:
                    nameservers.append(n)

    # Hostname / FQDN. `hostname -f` can resolve the FQDN via DNS; bounded by
    # _run's timeout so a misconfigured resolver can't hang the request.
    hostname = None
    res = _run(['hostname'], timeout=5)
    if res['rc'] == 0:
        hostname = res['out'].strip() or None
    fqdn = None
    resf = _run(['hostname', '-f'], timeout=5)
    if resf['rc'] == 0:
        cand = resf['out'].strip()
        if cand and cand != hostname and '.' in cand:
            fqdn = cand

    gw_ip = _iface_gateway(interface) if interface else _default_gateway()
    gateway = {'ip': gw_ip, 'ptr': _reverse_dns(gw_ip)} if gw_ip else None

    # Is this host's traffic egressing through a VPN? True when the default
    # route leaves via a tunnel interface (full-tunnel VPN / exit node), even
    # if the physical uplink is a normal eth0/wlan0. When scoped, judge the
    # selected interface itself.
    route_if = interface or _default_route_iface()
    route_vpn = _iface_vpn_info(route_if) if route_if else {'is_vpn': False, 'kind': None, 'endpoint': None}
    vpn_egress = {'interface': route_if,
                  'via_vpn': route_vpn['is_vpn'],
                  'kind': route_vpn['kind'],
                  'endpoint': route_vpn['endpoint']}

    # If no explicit search domain but the gateway/FQDN reveals one, surface it
    # as a best-effort guess so the field isn't just empty.
    guessed_domain = None
    for cand in (fqdn, gateway['ptr'] if gateway else None):
        if cand and '.' in cand:
            guessed_domain = cand.split('.', 1)[1]
            break

    return {
        'success': True,
        'interface': interface,
        'hostname': hostname,
        'fqdn': fqdn,
        'domains': domains,
        'guessed_domain': guessed_domain if not domains else None,
        'nameservers': nameservers,
        'dns_stub': stub,
        'gateway': gateway,
        'vpn_egress': vpn_egress,
        'sources': sources,
    }


# --------------------------------------------------------------------------
# Per-interface ISP / WAN detection (multi-WAN troubleshooting)
# --------------------------------------------------------------------------

def _parse_ipinfo_org(org):
    """ipinfo.io returns org as 'AS3301 Telia Company AB'. Split the leading
    ASN from the ISP/org name."""
    if not org:
        return None, None
    m = re.match(r'^(AS\d+)\s+(.*)$', org.strip())
    if m:
        return m.group(1), m.group(2).strip() or None
    return None, org.strip() or None


def _isp_lookup_iface(iface):
    """Query a public geo-IP/ASN service *through* one interface, so on a
    multi-WAN box each WAN's own public IP + ISP is reported. curl --interface
    binds the socket to that device (SO_BINDTODEVICE), forcing egress out it
    regardless of the routing table."""
    # The interface itself may be a VPN tunnel (egress is definitionally VPN).
    vpn = _iface_vpn_info(iface)
    iface_is_vpn = vpn['is_vpn']
    vpn_fields = {'iface_is_vpn': iface_is_vpn,
                  'vpn_kind': vpn['kind'], 'vpn_endpoint': vpn['endpoint']}

    def _vpn_only_result():
        """A tunnel we can't reach a geo service through isn't a dead WAN --
        present it as the VPN it is (kind/endpoint), not a red error row."""
        return {'interface': iface, 'behind_vpn': True,
                'isp': vpn['kind'] or 'VPN tunnel',
                'note': 'VPN tunnel — no separate internet egress to geolocate',
                **vpn_fields}

    if not _have('curl'):
        if iface_is_vpn:
            return _vpn_only_result()
        return {'interface': iface, 'behind_vpn': False,
                'error': 'curl is not installed', 'missing_tool': 'curl', **vpn_fields}

    # Fast pre-check: probing binds to the device (SO_BINDTODEVICE), which
    # needs a default route via that device. On a dual-homed box where only
    # the other uplink got a gateway (e.g. LAN segment without a DHCP gateway
    # while WiFi carries the default route) every probe is doomed — say so
    # immediately instead of burning ~24 s of Tor + geo timeouts per NIC.
    route_check = _run(['ip', '-4', 'route', 'show', 'default', 'dev', iface],
                       timeout=5)
    if route_check['rc'] == 0 and not route_check['out'].strip():
        if iface_is_vpn:
            return _vpn_only_result()
        return {'interface': iface, 'behind_vpn': False, 'no_route': True,
                'error': 'no default route via this interface — the kernel '
                         'routes internet traffic through another uplink, so '
                         'egress cannot be probed here (check the gateway/DHCP '
                         'on this segment)', **vpn_fields}

    # Is this egress a Tor exit? Catches Tor/VPN on the *router* (Ragnar's own
    # NIC looks ordinary in that case, so the geo ISP-name match alone misses it).
    tor_exit = _tor_exit_check(iface)
    vpn_fields['tor_exit'] = bool(tor_exit)

    # Primary: ipinfo.io over HTTPS (no API key needed for basic fields).
    res = _run(['curl', '-s', '--max-time', '8', '--interface', iface,
                'https://ipinfo.io/json'], timeout=12)
    if res['rc'] == 0 and res['out'].strip():
        try:
            d = json.loads(res['out'])
            if d.get('ip'):
                asn, isp = _parse_ipinfo_org(d.get('org'))
                vp = _vpn_provider_match(isp, d.get('org'), asn) or ('Tor' if tor_exit else None)
                ip_match = _vpn_ip_lookup(d.get('ip'))
                return {'interface': iface, 'public_ip': d.get('ip'),
                        'isp': isp, 'asn': asn, 'org': d.get('org'),
                        'vpn_provider': vp, 'vpn_ip_match': ip_match,
                        'behind_vpn': bool(vp or iface_is_vpn or tor_exit or ip_match),
                        'city': d.get('city'), 'region': d.get('region'),
                        'country': d.get('country'), 'source': 'ipinfo.io', **vpn_fields}
        except ValueError:
            pass

    # Fallback: ip-api.com (HTTP only on the free tier).
    res = _run(['curl', '-s', '--max-time', '8', '--interface', iface,
                'http://ip-api.com/json/?fields=status,message,query,isp,org,as,country,city,regionName'],
               timeout=12)
    if res['rc'] == 0 and res['out'].strip():
        try:
            d = json.loads(res['out'])
            if d.get('status') == 'success':
                asn, _ = _parse_ipinfo_org(d.get('as'))
                vp = _vpn_provider_match(d.get('isp'), d.get('org'), d.get('as')) or ('Tor' if tor_exit else None)
                ip_match = _vpn_ip_lookup(d.get('query'))
                return {'interface': iface, 'public_ip': d.get('query'),
                        'isp': d.get('isp'), 'asn': asn, 'org': d.get('org') or d.get('as'),
                        'vpn_provider': vp, 'vpn_ip_match': ip_match,
                        'behind_vpn': bool(vp or iface_is_vpn or tor_exit or ip_match),
                        'city': d.get('city'), 'region': d.get('regionName'),
                        'country': d.get('country'), 'source': 'ip-api.com', **vpn_fields}
        except ValueError:
            pass

    if iface_is_vpn:
        return _vpn_only_result()
    return {'interface': iface, 'behind_vpn': False,
            'error': 'could not reach a geo-IP service through this interface '
                     '(no internet via this WAN, or both services unreachable)',
            **vpn_fields}


def do_isp(interface=None):
    """Detect the public IP and ISP/ASN reached through each network interface.
    On a multi-WAN box this reveals which physical link goes to which ISP --
    essential for troubleshooting when one of several uplinks is flaky.

    Makes an outbound call to a third-party geo-IP service (ipinfo.io, then
    ip-api.com) per interface, bound to that interface. On-demand only."""
    if not _have('curl'):
        return {'success': False,
                'error': 'curl is not installed. Click Install to add it.',
                'missing_tool': 'curl', 'results': []}

    # Candidate interfaces: real (non-virtual) NICs that hold a routable-ish
    # IPv4 (skip loopback 127.* and APIPA 169.254.*). Private addresses are
    # kept -- they egress to a public IP via NAT, which is exactly what we
    # want to identify per WAN. NICs *without* a usable IPv4 are not silently
    # dropped any more -- they get an explanatory row, so a LAN port that
    # never completed DHCP (or has no carrier) is visible instead of missing.
    ifaces = do_interfaces(include_virtual=False).get('interfaces', [])
    candidates, skipped = [], []
    for i in ifaces:
        if interface and i['name'] != interface:
            continue
        v4 = [a.split('/')[0] for a in (i.get('ipv4') or [])]
        v4 = [a for a in v4 if not a.startswith('127.') and not a.startswith('169.254.')]
        if v4:
            candidates.append(i['name'])
        else:
            if i.get('link_detected') is False or i.get('operstate') == 'DOWN':
                why = 'no link (cable unplugged / not associated)'
            elif i.get('ip_method') == 'dhcp-failed':
                why = 'DHCP failed (APIPA 169.254.x address) — no usable IPv4'
            else:
                why = 'no IPv4 address — DHCP not completed or unconfigured'
            skipped.append({'interface': i['name'], 'behind_vpn': False,
                            'error': why, 'no_ipv4': True})

    if not candidates and not skipped:
        return {'success': False,
                'error': 'No interface has a usable IPv4 address to query through.',
                'results': []}

    results = [_isp_lookup_iface(name) for name in candidates] + skipped
    return {'success': True, 'results': results, 'count': len(results)}


def do_vpn_check(interface=None):
    """Egress VPN verdict, combining every signal we have. Catches both a VPN
    on this host (tunnel default route) and one running upstream on the
    router, where the local interface looks ordinary: the egress public IP is
    then the VPN server's, so the known-VPN IP-range match and the Tor exit
    check still see it.

    By default the check follows the *default route* (whatever uplink the
    kernel actually uses — on a dual-homed box that's the lowest-metric one,
    often WiFi). Pass `interface` to force the check through a specific NIC
    instead, e.g. to test the LAN path while WiFi carries the default route.

    verdict: 'vpn'     -- confirmed (local tunnel, Tor exit, or egress IP in a
                          known VPN range)
             'likely'  -- ISP/ASN name looks like a VPN provider/hosting
                          backbone, but the IP-range list didn't confirm
             'no'      -- egress identified and no signal fired
             'unknown' -- couldn't identify the egress (offline / no route)

    Makes outbound calls (geo-IP + Tor checker); on-demand only."""
    route_if = interface or _default_route_iface()
    if not route_if:
        return {'success': True, 'verdict': 'unknown', 'interface': None,
                'reasons': ['no default route -- this host has no internet egress']}

    r = _isp_lookup_iface(route_if)
    reasons = []
    if r.get('iface_is_vpn'):
        via = (r.get('vpn_kind') or 'tunnel') \
            + (' → ' + r['vpn_endpoint'] if r.get('vpn_endpoint') else '')
        reasons.append(f'default route is a local tunnel ({via})')
    if r.get('tor_exit'):
        reasons.append('egress is a Tor exit node (check.torproject.org)')
    if r.get('vpn_ip_match'):
        reasons.append('egress IP is in a known VPN-provider range')
    confirmed = bool(reasons)
    if r.get('vpn_provider') and r['vpn_provider'] != 'Tor':
        reasons.append(f"ISP/ASN name matches '{r['vpn_provider']}'")

    if confirmed:
        verdict = 'vpn'
    elif r.get('vpn_provider'):
        verdict = 'likely'
    elif r.get('public_ip'):
        verdict = 'no'
    else:
        verdict = 'unknown'
        reasons.append(r.get('error') or 'could not identify the public egress')

    return {'success': True, 'verdict': verdict, 'interface': route_if,
            'reasons': reasons, 'public_ip': r.get('public_ip'),
            'isp': r.get('isp'), 'asn': r.get('asn'),
            'tor_exit': r.get('tor_exit'), 'vpn_ip_match': r.get('vpn_ip_match'),
            'vpn_provider': r.get('vpn_provider'),
            'iface_is_vpn': r.get('iface_is_vpn'),
            'vpn_kind': r.get('vpn_kind'), 'vpn_endpoint': r.get('vpn_endpoint'),
            # was the IP-range list actually consulted? (None = unavailable)
            'ip_list_checked': r.get('vpn_ip_match') is not None}


# --------------------------------------------------------------------------
# DNS Doctor / Path-MTU / Captive-portal diagnostics
# --------------------------------------------------------------------------

def _system_resolvers():
    """This host's real upstream DNS servers (resolv.conf, or nmcli when only
    the systemd-resolved stub is present)."""
    _, ns, _ = _read_resolv_conf()
    if not ns or ns in (['127.0.0.53'], ['127.0.0.1']):
        nm = _nmcli_global_values('IP4.DNS')
        if nm:
            ns = nm
    return ns


def _dig(name, resolver=None, rtype='A'):
    """One dig query; returns status/AD-flag/query-time/answers, parsed."""
    cmd = ['dig', '+tries=1', '+time=3']
    if resolver:
        cmd.append('@' + resolver)
    cmd += [name, rtype, '+dnssec']
    res = _run(cmd, timeout=8)
    out = res['out']
    m = re.search(r'status:\s*(\w+)', out)
    status = m.group(1) if m else None
    ad = bool(re.search(r'flags:[^;]*\bad\b', out))
    m = re.search(r'Query time:\s*(\d+)\s*msec', out)
    query_ms = int(m.group(1)) if m else None
    answers, in_ans = [], False
    for line in out.splitlines():
        if line.startswith(';; ANSWER SECTION'):
            in_ans = True
            continue
        if in_ans:
            if not line.strip() or line.startswith(';'):
                in_ans = False
                continue
            # Answer line: NAME TTL CLASS TYPE RDATA. Keep only the queried
            # record type, so DNSSEC RRSIG/NSEC records don't pollute the set.
            parts = line.split()
            if len(parts) >= 5 and parts[3] == rtype:
                answers.append(parts[-1])
    return {'status': status, 'ad': ad, 'query_ms': query_ms, 'answers': answers,
            'error': None if (status or answers) else
                     ((res['err'] or 'no response').strip()[:120])}


# Hostname TLDs that are legitimately internal, so a private/RFC1918 answer for
# them is expected rather than a hijack signal.
_INTERNAL_TLDS = ('.local', '.lan', '.internal', '.home', '.corp', '.intranet',
                  '.localdomain', '.home.arpa')


def _looks_public_name(name):
    """True if `name` is a public FQDN (has a dot and a non-internal TLD), so a
    private/loopback answer for it would be a hijack smell rather than normal
    intranet resolution. Bare hostnames and internal TLDs return False."""
    n = (name or '').strip().lower().rstrip('.')
    if not n or '.' not in n:
        return False
    try:
        ipaddress.ip_address(n)   # a literal IP isn't a name to poison
        return False
    except ValueError:
        pass
    return not n.endswith(_INTERNAL_TLDS)


def _is_bogon(ip):
    """True if `ip` is a private / loopback / link-local / unspecified / reserved
    address — i.e. not a real public destination a public name should resolve to."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_private or a.is_loopback or a.is_unspecified
            or a.is_link_local or a.is_reserved or a.is_multicast)


def _dns_nxdomain_probe(resolver, nonce_name):
    """Ask `resolver` to resolve a random name that cannot exist. A well-behaved
    resolver returns NXDOMAIN; a resolver that *synthesizes* an address (ISP
    NXDOMAIN-redirect / typo-squat / portal) is rewriting DNS. Returns
    {'rewriting': bool, 'redirect_ip': str|None, 'status': str|None}."""
    d = _dig(nonce_name, resolver)
    rewriting = (d['status'] == 'NOERROR' and bool(d['answers']))
    return {'rewriting': rewriting,
            'redirect_ip': d['answers'][0] if d['answers'] else None,
            'status': d['status']}


def _doh_lookup(name, rtype='A'):
    """Resolve `name` over Cloudflare DNS-over-HTTPS (encrypted, tamper-resistant
    to on-path :53 spoofing). Returns a set of A-record answers, or None when the
    check couldn't run (curl missing / offline). An empty set means the encrypted
    path returned no address (NXDOMAIN / no A record)."""
    if not _have('curl'):
        return None
    q = urllib.parse.quote((name or '').strip(), safe='')
    res = _run(['curl', '-s', '--max-time', '6',
                '-H', 'accept: application/dns-json',
                f'https://cloudflare-dns.com/dns-query?name={q}&type={rtype}'],
               timeout=10)
    if res['rc'] != 0 or not res['out'].strip():
        return None
    try:
        d = json.loads(res['out'])
    except ValueError:
        return None
    return {a['data'] for a in (d.get('Answer') or [])
            if a.get('type') == 1 and a.get('data')}   # type 1 = A record


def do_dns_doctor(name):
    """Resolve `name` through every system resolver plus public 1.1.1.1 / 8.8.8.8,
    reporting per-resolver answers, query latency and the DNSSEC AD flag, whether
    the resolvers agree (split-DNS / hijack smell), and DoH/DoT reachability.

    Also runs active DNS-poisoning / hijack probes: an NXDOMAIN-rewrite test (a
    random name that must not resolve), a private-IP-for-a-public-name check, a
    SERVFAIL/DNSSEC-bogus check, and a DoH cross-check comparing the encrypted
    answer against the plaintext one. The combined verdict is in `poison`."""
    name = (name or '').strip()
    if not name:
        return {'success': False, 'error': 'hostname required'}
    if not _have('dig'):
        return {'success': False, 'missing_tool': 'dig',
                'error': 'dig is not installed. Click Install to add it.'}

    tested, seen = [], set()
    for r in _system_resolvers():
        tested.append((r, 'system'))
        seen.add(r)
    for pub in ('1.1.1.1', '8.8.8.8'):
        if pub not in seen:
            tested.append((pub, 'public'))

    public_name = _looks_public_name(name)
    nonce_name = 'nx-' + secrets.token_hex(10) + '.com'   # cannot be registered

    results, answer_sets = [], []
    for resolver, kind in tested:
        d = _dig(name, resolver)
        d.update({'resolver': resolver, 'kind': kind})
        # Private/loopback answer for a public name = redirect/portal/blocklist.
        d['bogon_answers'] = ([a for a in d['answers'] if _is_bogon(a)]
                              if public_name else [])
        # NXDOMAIN-rewrite probe against this same resolver (random name).
        nx = _dns_nxdomain_probe(resolver, nonce_name)
        d['nxdomain_rewrite'] = nx['rewriting']
        d['nxdomain_redirect_ip'] = nx['redirect_ip']
        results.append(d)
        if d['answers']:
            answer_sets.append(set(d['answers']))
    # "Consistent" = the resolvers share at least one answer. Exact-match is too
    # strict: CDN/anycast names legitimately return different IP subsets per
    # resolver, so only a *disjoint* answer set (no address in common) is the
    # real split-DNS / hijack smell.
    consistent = len(answer_sets) < 2 or bool(set.intersection(*answer_sets))

    # --- Poisoning / hijack verdict -------------------------------------------
    # Public resolvers (1.1.1.1 / 8.8.8.8) are the trust anchor; the system/ISP
    # resolvers are what an attacker or captive network would tamper with.
    public_union = set()
    for r in results:
        if r['kind'] == 'public' and r['answers']:
            public_union |= set(r['answers'])

    reasons = []

    # 1. NXDOMAIN rewriting: a resolver invented an address for a name that
    #    cannot exist. Public resolvers act as the control (they must NXDOMAIN).
    nx_rewriters = [{'resolver': r['resolver'], 'kind': r['kind'],
                     'redirect_ip': r['nxdomain_redirect_ip']}
                    for r in results if r['nxdomain_rewrite']]
    if nx_rewriters:
        who = ', '.join(x['resolver'] for x in nx_rewriters)
        reasons.append(f'NXDOMAIN rewriting: {who} synthesized an address for a '
                       f'name that does not exist (ISP redirect / portal / typo page)')

    # 2. Private/bogon address returned for a public name.
    bogon_hits = [{'resolver': r['resolver'], 'kind': r['kind'],
                   'ips': r['bogon_answers']}
                  for r in results if r['bogon_answers']]
    if bogon_hits:
        who = ', '.join(x['resolver'] for x in bogon_hits)
        reasons.append(f'private/bogon address for a public name from {who} '
                       f'(redirect, blocklist sinkhole or captive portal)')

    # 3. SERVFAIL where another resolver answered — a validating resolver
    #    refusing a name others resolve is the DNSSEC-bogus (tampered) signature.
    servfail = [r['resolver'] for r in results if r['status'] == 'SERVFAIL']
    if servfail and answer_sets:
        reasons.append(f'SERVFAIL from {", ".join(servfail)} while other resolvers '
                       f'answered — possible DNSSEC validation failure (tampered record)')

    # 4. System resolver's answer shares nothing with the public resolvers'.
    #    Soft signal (CDN/anycast can legitimately differ), so it's "suspected".
    sys_disjoint = [r['resolver'] for r in results
                    if r['kind'] == 'system' and r['answers']
                    and public_union and set(r['answers']).isdisjoint(public_union)]
    if sys_disjoint:
        reasons.append(f'{", ".join(sys_disjoint)} returned an answer with nothing in '
                       f'common with public resolvers (split-DNS, or a hijack if unexpected)')

    # 5. DoH cross-check: compare the encrypted (tamper-resistant) answer with the
    #    plaintext public answer. Disjoint => on-path :53 spoofing of the clear path.
    doh_answers = _doh_lookup(name)
    doh = {'checked': doh_answers is not None,
           'answers': sorted(doh_answers) if doh_answers else [],
           'mismatch': None}
    if doh_answers is not None and doh_answers and public_union:
        doh['mismatch'] = doh_answers.isdisjoint(public_union)
        if doh['mismatch']:
            reasons.append('DoH (encrypted) answer disjoint from the plaintext answer '
                           '— strong sign of on-path DNS spoofing')

    # Strong = confirmed tampering; soft = worth a second look.
    strong = bool(nx_rewriters or bogon_hits or doh['mismatch'])
    soft = bool(servfail or sys_disjoint)
    verdict = 'hijacked' if strong else ('suspicious' if soft else 'clean')

    poison = {
        'verdict': verdict,                 # clean | suspicious | hijacked
        'hijack_suspected': verdict != 'clean',
        'reasons': reasons,
        'public_name': public_name,
        'nxdomain_rewriters': nx_rewriters,
        'bogon_hits': bogon_hits,
        'servfail_resolvers': servfail,
        'system_disjoint_resolvers': sys_disjoint,
        'doh': doh,
    }

    return {'success': True, 'name': name, 'results': results,
            'consistent': consistent,
            'dnssec_ok': any(r['ad'] for r in results),
            'doh_reachable': _tcp_reachable('1.1.1.1', 443),
            'dot_reachable': _tcp_reachable('1.1.1.1', 853),
            'poison': poison}


def _tcp_reachable(host, port, timeout=4):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def do_pmtu(target):
    """Discover the path MTU to `target` and flag an MTU black hole (a hop that
    silently drops full-size packets -- the classic 'ping works, big transfers
    hang' fault).

    Uses a `ping -M do` (don't-fragment) binary search: the largest payload that
    gets through without fragmentation gives the path MTU. This needs no extra
    tool and, unlike a full tracepath, doesn't stall on unresponsive hops."""
    target = (target or '').strip()
    if not target:
        return {'success': False, 'error': 'target required'}
    if not _have('ping'):
        return {'success': False, 'missing_tool': 'ping',
                'error': 'ping is not installed. Click Install to add it.'}

    def fits(mtu):
        # payload = MTU - 28 (20-byte IP header + 8-byte ICMP header)
        r = _run(['ping', '-n', '-c', '1', '-W', '2', '-M', 'do', '-s', str(mtu - 28), target],
                 timeout=6)
        return r['rc'] == 0

    if fits(1500):
        pmtu = 1500
    elif not fits(576):
        # Even a 576-byte DF probe fails: the path likely filters ICMP or blocks
        # DF. Fall back to a plain ping to say whether the host is reachable.
        reach = _run(['ping', '-n', '-c', '1', '-W', '2', target], timeout=6)['rc'] == 0
        return {'success': True, 'target': target, 'pmtu': None, 'reduced': False,
                'reachable': reach,
                'note': 'Could not measure PMTU — the path filters ICMP or blocks '
                        'don\'t-fragment probes. ' + ('Host answers normal pings.'
                        if reach else 'Host did not answer normal pings either.')}
    else:
        lo, hi = 576, 1500
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if fits(mid):
                lo = mid
            else:
                hi = mid - 1
        pmtu = lo

    reduced = pmtu < 1500
    return {'success': True, 'target': target, 'pmtu': pmtu, 'reduced': reduced,
            'reachable': True,
            'note': (f'Largest unfragmented packet is {pmtu} bytes — below the standard '
                     '1500, which points to tunnel overhead (PPPoE/VPN) or an MTU-mismatched '
                     'hop.' if reduced else 'Full 1500-byte path — no MTU black hole.')}


_CAPTIVE_CHECKS = (
    ('http://connectivitycheck.gstatic.com/generate_204', '204', ''),
    ('http://captive.apple.com/hotspot-detect.html', '200', 'Success'),
)


def do_captive_portal():
    """Detect a captive portal (hotel/guest-WiFi HTTP hijack) by probing the
    same connectivity-check endpoints operating systems use. A mismatch (wrong
    status, a redirect, or a login page instead of the expected body) means the
    network is intercepting HTTP."""
    if not _have('curl'):
        return {'success': False, 'missing_tool': 'curl',
                'error': 'curl is not installed. Click Install to add it.'}
    checks, portal = [], False
    for url, expect_code, expect_body in _CAPTIVE_CHECKS:
        res = _run(['curl', '-s', '-m', '6', '-o', '-',
                    '-w', '\n__HTTP__%{http_code}__%{redirect_url}', url], timeout=10)
        m = re.search(r'\n__HTTP__(\d+)__(.*)$', res['out'], re.S)
        code = m.group(1) if m else None
        redirect = ((m.group(2) or '').strip() or None) if m else None
        body = res['out'][:m.start()] if m else res['out']
        ok = (code == expect_code) and (expect_body in body if expect_body else True)
        if not ok:
            portal = True
        checks.append({'url': url, 'code': code, 'redirect': redirect, 'ok': ok})
    return {'success': True, 'captive_portal': portal, 'checks': checks}


# --------------------------------------------------------------------------
# iperf3 LAN throughput (client to a peer, + optional built-in server)
# --------------------------------------------------------------------------

_IPERF3_PORT = 5201
_iperf3_server = {'proc': None}


def do_iperf3_client(server, port=_IPERF3_PORT, duration=5, reverse=False, udp=False):
    """Measure real throughput to an iperf3 peer on the LAN — the thing an
    internet speed test can't do (switch/cable/link validation between two
    nodes). `reverse` tests download (peer->here); `udp` reports jitter/loss."""
    server = (server or '').strip()
    if not server:
        return {'success': False, 'error': 'iperf3 server address required'}
    if not _have('iperf3'):
        return {'success': False, 'missing_tool': 'iperf3',
                'error': 'iperf3 is not installed. Click Install to add it.'}
    # iperf3 `-c` takes the host only (port is `-p`). Accept a "host:port" or
    # "[v6addr]:port" typed into the server box: split the port out so the
    # common mistake works, and it doubles as a way to target a non-5201 port.
    m6 = re.match(r'^\[(.+)\]:(\d+)$', server)
    m4 = re.match(r'^([^:]+):(\d+)$', server)
    if m6:
        server, port = m6.group(1), m6.group(2)
    elif m4:
        server, port = m4.group(1), m4.group(2)
    server = server.strip('[]')
    port = _clamp_int(port, _IPERF3_PORT, 1, 65535)
    duration = _clamp_int(duration, 5, 1, 30)
    cmd = ['iperf3', '-c', server, '-p', str(port), '-t', str(duration), '-J']
    if reverse:
        cmd.append('-R')
    if udp:
        cmd.append('-u')
    res = _run(cmd, timeout=duration + 15)
    try:
        d = json.loads(res['out'])
    except ValueError:
        return {'success': False,
                'error': (res['err'] or res['out'] or 'iperf3 failed').strip()[:200]}
    if d.get('error'):
        return {'success': False, 'error': d['error']}
    end = d.get('end', {})
    out = {'success': True, 'server': server, 'port': port,
           'direction': 'download' if reverse else 'upload',
           'protocol': 'UDP' if udp else 'TCP', 'duration_s': duration}
    if udp:
        s = end.get('sum', {})
        out['mbps'] = round(s.get('bits_per_second', 0) / 1e6, 2)
        out['jitter_ms'] = round(s.get('jitter_ms', 0), 3)
        out['lost_percent'] = round(s.get('lost_percent', 0), 2)
    else:
        sent = end.get('sum_sent', {})
        recv = end.get('sum_received', {})
        out['mbps'] = round(recv.get('bits_per_second', 0) / 1e6, 2)
        out['sent_mbps'] = round(sent.get('bits_per_second', 0) / 1e6, 2)
        out['retransmits'] = sent.get('retransmits')
    return out


def do_iperf3_server(action):
    """Run/stop a built-in iperf3 server so another device can throughput-test
    *against* this box. Returns the addresses to point the other end at."""
    if not _have('iperf3'):
        return {'success': False, 'missing_tool': 'iperf3',
                'error': 'iperf3 is not installed. Click Install to add it.'}
    proc = _iperf3_server['proc']
    running = proc is not None and proc.poll() is None

    if action == 'start':
        if not running:
            try:
                _iperf3_server['proc'] = subprocess.Popen(
                    ['iperf3', '-s', '-p', str(_IPERF3_PORT)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                running = True
            except OSError as e:
                return {'success': False, 'error': f'could not start iperf3 server: {e}'}
    elif action == 'stop':
        if running:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        _iperf3_server['proc'] = None
        running = False

    addrs = []
    for i in do_interfaces(include_virtual=False).get('interfaces', []):
        for cidr in (i.get('ipv4') or []):
            ip = cidr.split('/')[0]
            if not ip.startswith('127.'):
                addrs.append(ip)
    return {'success': True, 'running': running, 'port': _IPERF3_PORT, 'addresses': addrs}


# --------------------------------------------------------------------------
# Locate Port: flap a wired link so its switch LED blinks (find the port on an
# unmanaged switch, the way a cable tester / toner probe does)
# --------------------------------------------------------------------------

_locate_lock = threading.Lock()
_locate_active = {}  # interface -> True while a flap sequence is running


def _flap_sequence(interface, count, on_ms, off_ms):
    """Bring the link down/up `count` times so the switch's LINK LED blinks in
    a recognisable cadence. Always leaves the interface up when finished."""
    try:
        for _ in range(count):
            _run(['ip', 'link', 'set', interface, 'down'], timeout=10)
            time.sleep(off_ms / 1000.0)
            _run(['ip', 'link', 'set', interface, 'up'], timeout=10)
            time.sleep(on_ms / 1000.0)
    finally:
        # Never leave the port down, whatever happened above.
        _run(['ip', 'link', 'set', interface, 'up'], timeout=10)
        with _locate_lock:
            _locate_active.pop(interface, None)


def _burst_sequence(interface, count, on_ms, off_ms):
    """Blink the switch's ACTIVITY/TRAFFIC LED by sending dense bursts of raw
    Ethernet frames out `interface`, idling between them, so the LED pulses in
    the same recognisable on/off cadence as a flap — but the LINK stays up the
    whole time. Some switches only blink their per-port LED on traffic, not on
    link state, which is exactly what this covers. Raw AF_PACKET egress needs
    no IP/route on the interface (it goes straight out the wire)."""
    import socket
    sock = None
    try:
        # The switch only sees traffic if the link is up first.
        _run(['ip', 'link', 'set', interface, 'up'], timeout=10)
        try:
            with open('/sys/class/net/%s/address' % interface) as f:
                mac = f.read().strip()
            src = bytes(int(b, 16) for b in mac.split(':'))
        except (OSError, ValueError):
            src = b'\x02\x00\x00\x00\x00\x01'          # locally-administered fallback
        # Broadcast dst + a local-experimental EtherType (0x88b5); a tagged
        # payload so the frames are identifiable on a capture, padded to the
        # 60-byte minimum Ethernet frame.
        frame = (b'\xff\xff\xff\xff\xff\xff' + src + b'\x88\xb5'
                 + b'RAGNAR-LOCATE-PORT')
        frame += b'\x00' * (60 - len(frame))
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.bind((interface, 0))
        except OSError:
            return                                     # no raw-socket perms / iface gone
        for _ in range(count):
            end = time.time() + on_ms / 1000.0
            while time.time() < end:
                for _ in range(64):                    # dense burst -> LED clearly lit
                    try:
                        sock.send(frame)
                    except OSError:
                        end = 0                        # link/iface dropped mid-burst
                        break
                time.sleep(0.002)                      # ~32k pps ceiling, CPU-friendly
            time.sleep(off_ms / 1000.0)                # idle window -> LED dark
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        with _locate_lock:
            _locate_active.pop(interface, None)


def do_locate_port(interface, count=6, on_ms=800, off_ms=800, force=False, method='flap'):
    """Physically locate which switch port this device is plugged into by
    blinking a per-port LED in a timed cadence. Managed switches already report
    the port via LLDP/CDP (Switch Discovery) -- this is the fallback for
    unmanaged switches. Runs in the background and returns at once.

    Two methods, because switches differ in which LED they drive:
    - 'flap'  — links the port down/up so the **LINK** LED blinks (the link
                drops for a moment each cycle). Refuses the default-route
                interface unless force=True, since it briefly cuts Ragnar's own
                connectivity.
    - 'burst' — floods traffic bursts so the **ACTIVITY** LED blinks while the
                link stays up. Never drops connectivity, so no force is needed
                — safe even on the default route."""
    interface = (interface or '').strip()
    auto = not interface
    if auto:
        # _capture_iface prefers a link-up wired port — exactly what locate
        # needs; if it falls through to a wireless default route, the
        # ethernet check below rejects it with the auto-specific message.
        interface = _capture_iface(None) or ''
    method = (method or 'flap').strip().lower()
    if method not in ('flap', 'burst'):
        method = 'flap'

    match = next((i for i in do_interfaces(include_virtual=True).get('interfaces', [])
                  if i['name'] == interface), None)
    if match is None:
        return {'success': False, 'error': f'unknown interface: {interface}'
                if interface else 'no wired Ethernet port found — plug in a cable or pick an interface.'}
    if match.get('type') != 'ethernet' or not interface.startswith(('eth', 'en')):
        if auto:
            return {'success': False,
                    'error': 'no wired Ethernet port with link found — locating a '
                             'switch port needs a cable; pick an interface explicitly '
                             'if one exists.'}
        return {'success': False,
                'error': f'{interface} is not a physical Ethernet port; locating '
                         'a switch port only works on a wired link.'}

    count = _clamp_int(count, 6, 1, 30)
    on_ms = _clamp_int(on_ms, 800, 100, 3000)
    off_ms = _clamp_int(off_ms, 800, 100, 3000)

    # Guard: only the flap method cuts our uplink; burst keeps the link up.
    if method == 'flap' and not force and _default_route_iface() == interface:
        return {'success': False, 'needs_force': True, 'interface': interface,
                'error': f'{interface} carries this device\'s default route — flapping '
                         'it will briefly drop Ragnar\'s connectivity (the UI freezes '
                         'until the sequence finishes, then it auto-restores). Confirm '
                         'to proceed anyway — or use the Traffic-burst method, which '
                         'keeps the link up.'}

    with _locate_lock:
        if _locate_active.get(interface):
            return {'success': False, 'error': f'a locate sequence is already running on {interface}.'}
        _locate_active[interface] = True

    seq = _burst_sequence if method == 'burst' else _flap_sequence
    threading.Thread(target=seq, args=(interface, count, on_ms, off_ms),
                     daemon=True).start()
    total = round(count * (on_ms + off_ms) / 1000.0, 1)
    verb = 'Bursting traffic on' if method == 'burst' else 'Flapping'
    led = 'ACTIVITY' if method == 'burst' else 'LINK'
    return {'success': True, 'interface': interface, 'count': count, 'method': method,
            'on_ms': on_ms, 'off_ms': off_ms, 'duration_s': total,
            'message': f'{verb} {interface} {count}× (~{round(total)}s). Watch the switch — '
                       f'the port whose {led} LED blinks in this cadence is the one.'}


# --------------------------------------------------------------------------
# L2 Link Health: a short passive capture that flags Layer-2 problems
# --------------------------------------------------------------------------

def do_l2_health(interface, seconds=12):
    """Listen passively for a few seconds and report Layer-2 health: STP root
    bridge(s) and topology churn (loop smell), CDP/LLDP/DTP/VTP control frames,
    broadcast/multicast storm rate, rogue DHCP servers, rogue IPv6 RA sources,
    and duplicate IPs (conflicting ARP). One 'what's wrong at L2' snapshot."""
    interface = _capture_iface((interface or '').strip() or None)
    if not interface:
        return {'success': False, 'error': 'No suitable interface found — pick one explicitly.'}
    if not _have('tcpdump'):
        return {'success': False, 'missing_tool': 'tcpdump',
                'error': 'tcpdump is not installed. Click Install to add it.'}
    if interface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {interface}'}
    seconds = _clamp_int(seconds, 12, 3, 30)

    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface,
                '-nn', '-e', '-t', '-s', '256', '-c', '20000'], timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()):
        return {'success': False, 'error': res['err'].strip()[:200]}

    total = bcast = mcast = tcn = 0
    protos = {}
    stp_roots, dhcp_servers, ra_sources = set(), set(), set()
    arp_ip_macs = {}

    def bump(p):
        protos[p] = protos.get(p, 0) + 1

    for line in out.splitlines():
        if not line.strip():
            continue
        total += 1
        m = re.match(r'^(\S+)\s+>\s+([0-9a-fA-F:]{17})', line)
        src = m.group(1).lower() if m else None
        dst = m.group(2).lower() if m else None
        if dst == 'ff:ff:ff:ff:ff:ff':
            bcast += 1
        elif dst:
            try:
                if int(dst[0:2], 16) & 1:
                    mcast += 1
            except ValueError:
                pass
        if 'STP' in line or '802.1d' in line or '802.1w' in line:
            bump('STP')
            rr = re.search(r'root-id\s+([0-9a-fA-F.:]+)', line) or re.search(r'\broot\s+([0-9a-fA-F.:]+)', line)
            if rr:
                stp_roots.add(rr.group(1))
            if 'TCN' in line or 'topology' in line.lower():
                tcn += 1
        if 'CDP' in line:
            bump('CDP')
        if 'LLDP' in line:
            bump('LLDP')
        if 'DTP' in line:
            bump('DTP')
        if 'VTP' in line:
            bump('VTP')
        if 'router advertisement' in line.lower():
            bump('IPv6-RA')
            sm = re.search(r'ethertype IPv6.*?:\s*([0-9a-fA-F:]+)\s*>', line)
            ra_sources.add(sm.group(1) if sm else (src or '?'))
        if 'BOOTP/DHCP' in line or 'DHCP' in line:
            bump('DHCP')
            if any(k in line for k in ('Reply', 'Offer', 'ACK')):
                sm = (re.search(r'(\d+\.\d+\.\d+\.\d+)\.67\s*>', line)
                      or re.search(r'server-id\s+(\d+\.\d+\.\d+\.\d+)', line))
                if sm:
                    dhcp_servers.add(sm.group(1))
        if 'ARP' in line:
            bump('ARP')
            am = re.search(r'(\d+\.\d+\.\d+\.\d+) is-at ([0-9a-fA-F:]{17})', line)
            if am:
                arp_ip_macs.setdefault(am.group(1), set()).add(am.group(2).lower())

    dup_ips = {ip: sorted(macs) for ip, macs in arp_ip_macs.items() if len(macs) > 1}
    rate = round((bcast + mcast) / seconds, 1)

    findings = []
    if len(stp_roots) > 1:
        findings.append(('warn', f'Multiple STP root bridges seen ({len(stp_roots)}) — possible L2 loop or merged/segmented domains'))
    if tcn > 5:
        findings.append(('warn', f'{tcn} STP topology-change notifications — flapping or a loop somewhere'))
    if 'STP' not in protos:
        findings.append(('info', 'No STP/BPDUs seen — the switch may have STP disabled or filtered on this port'))
    if len(dhcp_servers) > 1:
        findings.append(('warn', 'Multiple DHCP servers answering: ' + ', '.join(sorted(dhcp_servers)) + ' — possible rogue DHCP'))
    if len(ra_sources) > 1:
        findings.append(('warn', f'Multiple IPv6 RA sources ({len(ra_sources)}) — possible rogue Router Advertisement'))
    if dup_ips:
        findings.append(('warn', 'Duplicate IP(s) via conflicting ARP: ' + ', '.join(dup_ips.keys())))
    if rate > 100:
        findings.append(('warn', f'High broadcast/multicast rate ({rate}/s) — possible broadcast storm'))
    if 'DTP' in protos:
        findings.append(('info', 'DTP (Dynamic Trunking) frames seen — this port may auto-negotiate a trunk; consider hard-setting the mode'))
    if not findings:
        findings.append(('ok', 'No obvious Layer-2 problems in the capture window.'))

    return {'success': True, 'interface': interface, 'seconds': seconds,
            'packets': total, 'broadcast': bcast, 'multicast': mcast,
            'bcast_mcast_per_s': rate, 'protocols': protos,
            'stp_roots': sorted(stp_roots), 'tcn': tcn,
            'dhcp_servers': sorted(dhcp_servers), 'ra_sources': sorted(ra_sources),
            'duplicate_ips': dup_ips,
            'findings': [{'level': l, 'text': t} for l, t in findings]}


# --------------------------------------------------------------------------
# IGMP Watch: passive IGMP-snooping security scanner (detection-only)
# --------------------------------------------------------------------------
# IGMP is the low-volume control plane of IPv4 multicast: hosts announce group
# membership (reports/joins), the multicast router periodically queries. That
# makes it a cheap, high-signal thing to watch on a Pi Zero 2 W — a few
# packets a minute on a healthy segment. This scanner is PASSIVE: one short
# tcpdump window, parsed and classified. It never joins a group, never sends a
# query, never becomes a querier. Four things it looks for:
#   1. Storm / flood   — an IGMP report/query rate far above normal noise
#      (report floods are a real multicast DoS and a switch-CPU exhaustion vector).
#   2. Anomaly         — >1 querier on the segment. There must be exactly one;
#      a second, lower-IP querier is the classic "become the querier to draw all
#      multicast to yourself" attack, plus version downgrades (v3->v2/v1).
#   3. Reconnaissance  — one host joining a wide spread of distinct groups (or
#      sweeping group-specific queries): multicast stream enumeration.
#   4. Unauthorized join — a host joining an admin-scoped / globally-scoped group
#      it has never been seen on, measured against a learned baseline.
#
# Passive-floor doctrine (see MAC Watch / L2 Health): thresholds sit above the
# ordinary chatter (mDNS 224.0.0.251, SSDP 239.255.255.250, ~125s general
# queries) so a normal segment reads clean. First run learns the querier(s) and
# host->group memberships into data/igmp_watch.json; "Trust current" re-learns.

_IGMP_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'data', 'igmp_watch.json')
_igmp_watch_lock = threading.Lock()

# Total IGMP messages/sec at or above which the window is a storm. IGMP is
# intrinsically low-rate, so even a modest sustained rate is abnormal.
_IGMP_STORM_RATE = 30.0
# One source emitting at or above this many messages in the window is flooding
# on its own (report-flood DoS), independent of the aggregate rate.
_IGMP_SRC_FLOOD = 120
# One source joining at or above this many distinct groups in the window is
# enumerating multicast (reconnaissance).
_IGMP_RECON_GROUPS = 20
# Keep at most this many anomaly events in the store (newest wins).
_IGMP_EVENTS_CAP = 200

# Well-known multicast groups, for readable output and to avoid flagging normal
# service discovery as an unauthorized join.
_IGMP_WELL_KNOWN = {
    '224.0.0.1': 'all-hosts', '224.0.0.2': 'all-routers',
    '224.0.0.5': 'OSPF', '224.0.0.6': 'OSPF-DR', '224.0.0.9': 'RIPv2',
    '224.0.0.13': 'PIM', '224.0.0.18': 'VRRP', '224.0.0.22': 'IGMPv3',
    '224.0.0.102': 'HSRPv2/GLBP', '224.0.0.251': 'mDNS', '224.0.0.252': 'LLMNR',
    '224.0.1.1': 'NTP', '224.0.1.129': 'PTP', '239.255.255.250': 'SSDP/UPnP',
    '239.255.255.253': 'SLP',
}


def _igmp_scope(group):
    """Classify a multicast group address into a readable scope. Returns
    (scope, sensitive) — sensitive=True means a join there is worth policing
    (admin/global/SSM), False for link-local control traffic (normal)."""
    try:
        octets = [int(x) for x in group.split('.')]
        if len(octets) != 4:
            return ('invalid', False)
    except (ValueError, AttributeError):
        return ('invalid', False)
    a, b, c, _d = octets
    if a == 224 and b == 0 and c == 0:
        return ('link-local control', False)   # 224.0.0.0/24 — normal
    if a == 239:
        return ('admin-scoped (private)', True)  # 239.0.0.0/8
    if a == 232:
        return ('source-specific (SSM)', True)   # 232.0.0.0/8
    if 224 <= a <= 238:
        return ('globally-scoped', True)
    return ('other', False)


_IGMP_IP_RE = r'(\d{1,3}(?:\.\d{1,3}){3})'


def _igmp_is_multicast(ip):
    """True if `ip` is in the IPv4 multicast range 224.0.0.0/4 (224–239)."""
    try:
        return 224 <= int(ip.split('.')[0]) <= 239
    except (ValueError, AttributeError, IndexError):
        return False


def _parse_igmp_capture(output):
    """Parse `tcpdump -nn -t -v 'igmp'` text into a list of membership events:
    {src, group, kind, version, ttl}. kind is 'query' | 'report' | 'leave'.

    Handles v1/v2 reports (dst == group), v2 leaves, and v3 reports whose group
    records tcpdump prints as `gaddr <addr> ...` (one event per group record).
    With -v, tcpdump prints an IP-header line ('... proto IGMP (2), ttl N ...')
    just before each message; its TTL is captured and attached to the next event
    (IGMP must be TTL 1 — anything else is off-link injection). Robust to tcpdump
    version differences: it keys off the `igmp` keyword and pulls every group
    address it can find rather than a single rigid format."""
    events = []
    ver_re = re.compile(r'igmp\s+v(\d)', re.I)
    src_re = re.compile(r'^' + _IGMP_IP_RE + r'\s*>\s*' + _IGMP_IP_RE)
    gaddr_re = re.compile(r'gaddr\s+' + _IGMP_IP_RE, re.I)
    ttl_re = re.compile(r'\bttl\s+(\d+)', re.I)
    # v3 record modes that mean "leaving / no interest" vs joining.
    leave_modes = ('to_in', 'is_in', 'block')
    pending_ttl = None
    for raw in output.splitlines():
        line = raw.strip()
        low = line.lower()
        # IP-header line for an IGMP datagram: grab the TTL for the next event.
        if 'proto igmp' in low and 'ttl' in low and not src_re.search(line):
            tm = ttl_re.search(line)
            pending_ttl = int(tm.group(1)) if tm else None
            continue
        if 'igmp' not in low:
            continue
        sm = src_re.search(line)
        src = sm.group(1) if sm else None
        dst = sm.group(2) if sm else None
        vm = ver_re.search(line)
        version = int(vm.group(1)) if vm else 2
        ttl = pending_ttl
        pending_ttl = None
        low = line.lower()
        if 'query' in low:
            events.append({'src': src, 'group': None, 'kind': 'query',
                           'version': version, 'ttl': ttl})
            continue
        if 'leave' in low:
            # v2 leave-group: the left group is named after "leave" or is dst.
            lm = re.search(r'leave.*?' + _IGMP_IP_RE, low)
            grp = (lm.group(1) if lm else None) or (dst if dst != '224.0.0.2' else None)
            events.append({'src': src, 'group': grp, 'kind': 'leave',
                           'version': version, 'ttl': ttl})
            continue
        if 'report' in low:
            gaddrs = gaddr_re.findall(line)
            if gaddrs:
                # v3 report — one event per group record.
                for g in gaddrs:
                    # crude record-mode read near this gaddr; default to report.
                    seg = low.split(g.lower(), 1)[-1][:24]
                    kind = 'leave' if any(m in seg for m in leave_modes) and '{ }' in seg else 'report'
                    events.append({'src': src, 'group': g, 'kind': kind,
                                   'version': version, 'ttl': ttl})
            else:
                # v1/v2 report — the destination address IS the group.
                grp = None
                rm = re.search(r'report\s+' + _IGMP_IP_RE, low)
                grp = rm.group(1) if rm else (dst if dst and dst not in _IGMP_WELL_KNOWN else dst)
                events.append({'src': src, 'group': grp, 'kind': 'report',
                               'version': version, 'ttl': ttl})
    return events


def _igmp_watch_load():
    try:
        with open(_IGMP_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _igmp_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_IGMP_WATCH_PATH), exist_ok=True)
        tmp = _IGMP_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _IGMP_WATCH_PATH)
    except OSError:
        pass


def do_igmp_baseline(action='get'):
    """Manage the learned IGMP baseline (trusted querier(s) + known host->group
    memberships). action='reset' clears it so the current segment is re-learned
    on the next scan (use after a legitimate multicast/router change)."""
    with _igmp_watch_lock:
        if action == 'reset':
            _igmp_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _igmp_watch_load()
        return {'success': True, 'baseline': {
            'queriers': sorted(b.get('queriers') or []),
            'groups': sorted((b.get('members') or {}).keys()),
        }}


def _igmp_analyze(events, seconds, baseline, learn=True):
    """Pure classifier over parsed IGMP events. Returns the result payload
    (minus interface). Separated from capture so the self-test can drive it with
    synthetic packets. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))
    total = len(events)
    rate = round(total / seconds, 1)

    queriers = sorted({e['src'] for e in events if e['kind'] == 'query' and e['src']})
    per_src = {}
    src_groups = {}
    members = {}
    per_src_leave = {}
    sg_kinds = {}                 # (src, group) -> set of {'report','leave'}
    bad_ttl = {}                  # (src, ttl) -> a representative kind
    for e in events:
        s = e.get('src')
        if s:
            per_src[s] = per_src.get(s, 0) + 1
        g = e.get('group')
        if g and e['kind'] == 'report':
            src_groups.setdefault(s, set()).add(g)
            members.setdefault(g, set()).add(s)
        if s and e['kind'] == 'leave':
            per_src_leave[s] = per_src_leave.get(s, 0) + 1
        if g and e['kind'] in ('report', 'leave'):
            sg_kinds.setdefault((s, g), set()).add(e['kind'])
        ttl = e.get('ttl')
        if ttl is not None and ttl != 1 and s:
            bad_ttl.setdefault((s, ttl), e['kind'])

    trusted_q = set(baseline.get('queriers') or [])
    known_members = {g: set(v) for g, v in (baseline.get('members') or {}).items()}
    learned = False
    # Learn-on-first-run: an empty baseline adopts the current querier(s) and
    # memberships as trusted (mirrors ARP/DHCP baseline behaviour).
    if learn and not trusted_q and not known_members and (queriers or members):
        baseline['queriers'] = queriers
        baseline['members'] = {g: sorted(v) for g, v in members.items()}
        learned = True
        trusted_q = set(queriers)
        known_members = {g: set(v) for g, v in members.items()}

    findings = []       # (level, category, text)
    categories = set()

    # (1) storm / flood
    if rate >= _IGMP_STORM_RATE:
        categories.add('storm')
        findings.append(('crit', 'storm',
                         f'IGMP rate {rate}/s over {seconds}s ({total} msgs) — '
                         'far above normal; multicast report/query flood'))
    floods = sorted([(s, n) for s, n in per_src.items() if n >= _IGMP_SRC_FLOOD],
                    key=lambda x: -x[1])
    for s, n in floods:
        categories.add('storm')
        findings.append(('crit', 'storm',
                         f'{s} sent {n} IGMP messages in {seconds}s — single-source flood'))

    # (2) anomaly — rogue / extra querier, version downgrade
    if len(queriers) > 1:
        categories.add('anomaly')
        extra = [q for q in queriers if q not in trusted_q] or queriers[1:]
        findings.append(('crit', 'anomaly',
                         f'{len(queriers)} IGMP queriers on the segment '
                         f'({", ".join(queriers)}) — there must be exactly one; '
                         f'possible rogue querier ({", ".join(extra)}) drawing multicast'))
    elif queriers and trusted_q and queriers[0] not in trusted_q:
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         f'querier is {queriers[0]}, not the trusted '
                         f'{", ".join(sorted(trusted_q))} — querier takeover'))
    q_versions = sorted({e['version'] for e in events if e['kind'] == 'query'})
    if len(q_versions) > 1:
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         f'mixed IGMP query versions {q_versions} — possible '
                         'version-downgrade to force weaker v1/v2'))

    # (2b) crafted / off-link / bogus-group anomalies. These are signatures of a
    # forged or injected message rather than a policy question, so they fire in
    # both learn and enforce modes.
    if any(e['kind'] == 'query' and e.get('src') == '0.0.0.0' for e in events):
        categories.add('anomaly')
        findings.append(('crit', 'anomaly',
                         'IGMP query sourced from 0.0.0.0 — a spoofed querier '
                         '(a real querier sends from its interface IP)'))
    for (s, t), kind in sorted(bad_ttl.items()):
        categories.add('anomaly')
        findings.append(('crit', 'anomaly',
                         f'IGMP {kind} from {s} arrived with IP TTL {t} (must be 1) '
                         '— off-link injection / spoofed multicast control'))
    for (s, g) in sorted(k for k in sg_kinds if k[1] and not _igmp_is_multicast(k[1])):
        categories.add('anomaly')
        findings.append(('crit', 'anomaly',
                         f'{s} sent a report/leave for {g}, which is not a multicast '
                         '(224.0.0.0/4) address — crafted/malformed message'))
    for g in sorted(members):
        if g in ('224.0.0.1', '224.0.0.2'):
            for s in sorted(members[g]):
                categories.add('anomaly')
                findings.append(('crit', 'anomaly',
                                 f'{s} reported membership in reserved group {g} '
                                 f'({_IGMP_WELL_KNOWN.get(g)}) — bogus/crafted (these '
                                 'are never joined via IGMP)'))
    for (s, g) in sorted(k for k, v in sg_kinds.items()
                         if k[1] and 'report' in v and 'leave' in v):
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         f'{s} both joined and left {g} in {seconds}s — join/leave '
                         'flap (thrashes the snooping table)'))
    leave_floods = sorted([(s, n) for s, n in per_src_leave.items()
                           if n >= _IGMP_SRC_FLOOD], key=lambda x: -x[1])
    for s, n in leave_floods:
        categories.add('storm')
        findings.append(('warn', 'storm',
                         f'{s} sent {n} IGMP leaves in {seconds}s — leave flood '
                         '(forces repeated group-specific queries; snooping DoS)'))

    # (3) reconnaissance — a source joining many distinct groups
    recon = sorted([(s, len(g)) for s, g in src_groups.items() if len(g) >= _IGMP_RECON_GROUPS],
                   key=lambda x: -x[1])
    recon_srcs = {s for s, _n in recon}
    for s, n in recon:
        categories.add('recon')
        findings.append(('warn', 'recon',
                         f'{s} joined {n} distinct multicast groups in {seconds}s '
                         '— multicast group enumeration (reconnaissance)'))

    # (4) unauthorized join — a new host on a sensitive (admin/global/SSM) group.
    # A source already flagged as recon is folded under that finding — its joins
    # are the enumeration, not N separate unauthorized alerts.
    unauth = []
    if trusted_q or known_members:   # only meaningful once a baseline exists
        for g, srcs in members.items():
            scope, sensitive = _igmp_scope(g)
            if not sensitive:
                continue
            for s in srcs:
                if s in recon_srcs:
                    continue
                if s not in known_members.get(g, set()):
                    unauth.append((s, g, scope))
    for s, g, scope in unauth:
        categories.add('unauthorized')
        name = _IGMP_WELL_KNOWN.get(g)
        findings.append(('warn', 'unauthorized',
                         f'{s} joined {g}{" (" + name + ")" if name else ""} '
                         f'[{scope}] — not in the learned baseline (unauthorized join)'))

    # verdict = most severe triggered category
    order = ['storm', 'anomaly', 'unauthorized', 'recon']
    verdict = next((c for c in order if c in categories), 'clean')
    if not findings:
        findings.append(('ok', 'clean', 'No IGMP anomalies in the capture window.'))

    groups_out = []
    for g in sorted(members.keys()):
        scope, sensitive = _igmp_scope(g)
        srcs = sorted(members[g])
        new = bool((trusted_q or known_members) and
                   any(s not in known_members.get(g, set()) for s in srcs))
        groups_out.append({'group': g, 'name': _IGMP_WELL_KNOWN.get(g),
                           'scope': scope, 'sensitive': sensitive,
                           'members': srcs, 'new': new})

    top_joiners = sorted(([{'src': s, 'groups': len(g)} for s, g in src_groups.items()]),
                         key=lambda x: -x['groups'])[:8]

    return {
        'success': True, 'verdict': verdict, 'seconds': seconds,
        'packets': total, 'rate_per_s': rate, 'learned': learned,
        'queriers': queriers, 'trusted_queriers': sorted(trusted_q),
        'groups': groups_out, 'top_joiners': top_joiners,
        'findings': [{'level': l, 'category': c, 'text': t} for l, c, t in findings],
        'reasons': [t for _l, _c, t in findings if _l != 'ok'],
    }


def _igmp_capture(interface, seconds):
    """Run one passive tcpdump IGMP window and return (raw_text, error)."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface,
                '-nn', '-t', '-v', '-s', '256', '-c', '20000', 'igmp'],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_igmp_watch(interface=None, seconds=12, learn=True, quick=False):
    """Passive IGMP-snooping security scanner (detection-only). Captures IGMP for
    a few seconds and classifies the segment: storm / anomaly / recon /
    unauthorized / clean. Learns the querier(s) + memberships on first run."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 12, 4, 30)

    text, err = _igmp_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    events = _parse_igmp_capture(text)

    with _igmp_watch_lock:
        baseline = _igmp_watch_load()
        result = _igmp_analyze(events, seconds, baseline, learn=learn)
        # Persist a freshly-learned baseline, and append anomaly events to history.
        if result.get('learned'):
            _igmp_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _igmp_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_IGMP_EVENTS_CAP:]
            _igmp_watch_save(b)

    result['interface'] = iface
    return result


def _igmp_selftest():
    """Self-test the IGMP detectors with synthetic captures (no root, no live
    traffic). Feeds crafted tcpdump text through the real parser + classifier,
    and — if Scapy is available — also builds real IGMP packets into a pcap and
    parses them back through tcpdump, exercising the capture->parse path end to
    end (mirrors the MAC Watch self-test approach). Returns a results dict."""
    scenarios = []

    def run(name, text, seconds, baseline, expect):
        events = _parse_igmp_capture(text)
        res = _igmp_analyze(events, seconds, dict(baseline), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect,
                          'got': res['verdict'], 'events': len(events),
                          'pass': ok})
        return res

    # 1. clean: one querier + normal service-discovery joins.
    clean = "\n".join([
        "192.168.1.1 > 224.0.0.1: igmp query v2",
        "192.168.1.50 > 224.0.0.251: igmp v2 report 224.0.0.251",
        "192.168.1.51 > 239.255.255.250: igmp v2 report 239.255.255.250",
    ])
    run('clean', clean, 12, {}, 'clean')

    # 2. storm: a report flood from one host.
    storm = "\n".join(
        [f"192.168.1.77 > 239.1.2.3: igmp v2 report 239.1.2.3" for _ in range(400)])
    run('storm', storm, 5, {'queriers': ['192.168.1.1'], 'members': {}}, 'storm')

    # 3. anomaly: a second (rogue) querier appears.
    anomaly = "\n".join([
        "192.168.1.1 > 224.0.0.1: igmp query v2",
        "192.168.1.9 > 224.0.0.1: igmp query v2",
    ])
    run('anomaly', anomaly, 12, {'queriers': ['192.168.1.1'], 'members': {}}, 'anomaly')

    # 4. recon: one host enumerates many groups.
    recon = "\n".join(
        [f"192.168.1.66 > 239.0.0.{i}: igmp v2 report 239.0.0.{i}" for i in range(1, 41)])
    run('recon', recon, 10, {'queriers': ['192.168.1.1'],
                             'members': {'239.0.0.1': ['192.168.1.66']}}, 'recon')

    # 5. unauthorized: a new host joins an admin-scoped group not in baseline.
    unauth = "192.168.1.200 > 239.5.5.5: igmp v2 report 239.5.5.5"
    run('unauthorized', unauth, 12,
        {'queriers': ['192.168.1.1'], 'members': {'239.1.1.1': ['192.168.1.50']}},
        'unauthorized')

    # 6. spoofed querier: a general query sourced from 0.0.0.0.
    run('spoofed-querier', "0.0.0.0 > 224.0.0.1: igmp query v2", 12, {}, 'anomaly')
    # 7. bad TTL: IGMP must be TTL 1; the IP-header line carries a higher TTL.
    badttl = "\n".join([
        "IP (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto IGMP (2), length 28)",
        "    10.0.0.9 > 239.1.1.1: igmp v2 report 239.1.1.1"])
    run('bad-ttl', badttl, 12, {'queriers': ['192.168.1.1'], 'members': {}}, 'anomaly')
    # 8. non-multicast group in a report — crafted.
    run('non-multicast-group', "10.0.0.5 > 10.0.0.5: igmp v2 report 10.0.0.5", 12,
        {'queriers': ['192.168.1.1'], 'members': {}}, 'anomaly')
    # 9. reserved-group membership report (all-hosts).
    run('reserved-group', "10.0.0.9 > 224.0.0.1: igmp v2 report 224.0.0.1", 12,
        {'queriers': ['192.168.1.1'], 'members': {}}, 'anomaly')
    # 10. join/leave flap: same host toggles a group.
    flap = "\n".join([
        "10.0.0.7 > 239.2.2.2: igmp v2 report 239.2.2.2",
        "10.0.0.7 > 224.0.0.2: igmp v2 leave 239.2.2.2"])
    run('join-leave-flap', flap, 12, {'queriers': ['192.168.1.1'], 'members': {}},
        'anomaly')
    # 11. leave flood from one source.
    leave_storm = "\n".join(
        ["10.0.0.8 > 224.0.0.2: igmp v2 leave 239.3.3.3" for _ in range(130)])
    run('leave-storm', leave_storm, 5, {'queriers': ['192.168.1.1'], 'members': {}},
        'storm')

    # 12. v3 group-record parse (via gaddr) — assert the group is extracted.
    v3 = ("192.168.1.50 > 224.0.0.22: igmp v3 report, 1 group record(s) "
          "[gaddr 239.9.9.9 to_ex { }]")
    v3_events = _parse_igmp_capture(v3)
    v3_ok = any(e['group'] == '239.9.9.9' and e['kind'] == 'report' for e in v3_events)
    scenarios.append({'name': 'v3-parse', 'expect': 'group 239.9.9.9',
                      'got': str([e.get('group') for e in v3_events]),
                      'pass': v3_ok})

    # Optional Scapy end-to-end: craft real IGMP packets -> pcap -> tcpdump -> parse.
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import IP, Ether, wrpcap  # noqa
        try:
            from scapy.contrib.igmp import IGMP
        except Exception:
            IGMP = None
        if IGMP is not None and _have('tcpdump'):
            pkts = [Ether() / IP(src='192.168.1.50', dst='239.7.7.7') /
                    IGMP(type=0x16, gaddr='239.7.7.7')]
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, pkts)
            res = _run(['tcpdump', '-nn', '-t', '-v', '-r', pcap_path, 'igmp'],
                       timeout=10)
            evs = _parse_igmp_capture(res['out'])
            got = [e.get('group') for e in evs]
            scapy_result = {'ran': True, 'groups': got,
                            'pass': any(g == '239.7.7.7' for g in got),
                            'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and \
        (not scapy_result.get('ran') or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# IPv6 First-Hop Watch: rogue Router Advertisement / DHCPv6 scanner (passive)
# --------------------------------------------------------------------------
# The most-overlooked LAN attack today. Every modern OS ships with IPv6 on and
# *prefers* it, even on "IPv4-only" networks nobody manages. So a rogue Router
# Advertisement (ICMPv6 type 134) or a rogue DHCPv6 server silently becomes the
# default gateway and/or DNS for the whole segment — the SLAAC / mitm6 attack —
# and a tech watching only IPv4/ARP/DHCP never sees it. This scanner is PASSIVE:
# one short tcpdump window over RA/RS/Redirect + DHCPv6, parsed and classified.
# It never sends an RA, never answers a solicit, never touches routing. What it
# flags:
#   * rogue-ra      — a Router Advertisement from a router not in the learned
#     baseline (new default gateway), a *second* conflicting router, an RA that
#     injects a DNS server (RDNSS option) or prefix you didn't have, an RA with
#     'pref high' (attacker biasing host selection), or router-lifetime 0 (an RA
#     that deprecates the real router — the RA "kill" / DoS trick).
#   * rogue-dhcpv6  — a DHCPv6 ADVERTISE/REPLY/RECONFIGURE from a server not in
#     the baseline. mitm6's signature: it answers DHCPv6 solicits handing out the
#     attacker as DNS (no gateway, pairs with WPAD) to relay/NTLM-capture.
#   * storm         — an RA flood (THC fake_router6 / RA-flood DoS) by rate.
#   * anomaly       — first-hop IPv6 seen where the baseline expected none, or a
#     managed/other-flag flip that changes host addressing behaviour.
# First run learns the trusted router(s) + DHCPv6 server(s) into
# data/ipv6_watch.json; "Trust current" re-learns after a legitimate change.
# Mitigation advisory points at switch RA-Guard (RFC 6105) / DHCPv6 snooping.

_IPV6_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'data', 'ipv6_watch.json')
_ipv6_watch_lock = threading.Lock()

# Router Advertisements are intrinsically rare (every ~200s per router). A
# sustained rate at/above this is a flood (fake_router6 / RA storm DoS).
_IPV6_RA_FLOOD_RATE = 5.0
# Keep at most this many anomaly events in the store (newest wins).
_IPV6_EVENTS_CAP = 200

# DHCPv6 message types sent by *servers* (a client should never see these from a
# peer that isn't a real DHCPv6 server) — the rogue-server tell.
_IPV6_DHCP6_SERVER_MSGS = ('advertise', 'reply', 'reconfigure', 'relay-reply')

_IPV6_ADDR_RE = r'([0-9A-Fa-f:]+(?:%\w+)?)'


def _parse_ipv6_capture(output):
    """Parse `tcpdump -nn -t -v` text (RA/RS/Redirect + DHCPv6) into events.

    tcpdump prints one packet as a non-indented header line followed by indented
    option lines, so we group by packet block first, then read each block. Each
    event is a dict with a 'kind':
      ra    : {src, dst, lifetime, pref, managed, other, prefixes[], rdnss[],
               mac, mtu}
      rs    : {src}                      (router solicitation — normal from hosts)
      redirect: {src}
      dhcp6 : {src, msgtype, dns[], is_server}
    """
    events = []
    # --- group lines into per-packet blocks ---
    blocks, cur = [], []
    hdr_re = re.compile(r'^\S.*\s>\s\S')
    for raw in output.splitlines():
        if not raw.strip():
            continue
        if not raw[0].isspace() and hdr_re.match(raw):
            if cur:
                blocks.append(cur)
            cur = [raw]
        elif cur:
            cur.append(raw)
    if cur:
        blocks.append(cur)

    src_re = re.compile(r'^' + _IPV6_ADDR_RE + r'\s*>\s*' + _IPV6_ADDR_RE)
    for block in blocks:
        text = '\n'.join(block)
        low = text.lower()
        m = src_re.match(block[0].strip())
        src = m.group(1) if m else None
        dst = m.group(2) if m else None

        if 'router advertisement' in low:
            ev = {'kind': 'ra', 'src': src, 'dst': dst,
                  'lifetime': None, 'pref': 'medium', 'managed': False,
                  'other': False, 'prefixes': [], 'rdnss': [], 'mac': None,
                  'mtu': None}
            lt = re.search(r'router lifetime\s+(\d+)s', low)
            if lt:
                ev['lifetime'] = int(lt.group(1))
            pf = re.search(r'pref\s+(low|medium|high)', low)
            if pf:
                ev['pref'] = pf.group(1)
            # RA-level flags line (managed/other) — the one with 'router lifetime'
            for line in block:
                ll = line.lower()
                if 'router lifetime' in ll or 'hop limit' in ll:
                    fl = re.search(r'flags\s+\[([^\]]*)\]', ll)
                    if fl:
                        flags = fl.group(1)
                        ev['managed'] = 'managed' in flags
                        ev['other'] = 'other' in flags
                    break
            ev['prefixes'] = re.findall(r'prefix info option.*?:\s*'
                                        r'([0-9A-Fa-f:]+/\d+)', low)
            for line in block:
                if 'rdnss' in line.lower():
                    ev['rdnss'].extend(re.findall(r'addr:\s*([0-9A-Fa-f:]+)',
                                                  line.lower()))
            mac = re.search(r'source link-address option.*?:\s*'
                            r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})', low)
            if mac:
                ev['mac'] = mac.group(1)
            mtu = re.search(r'mtu option.*?:\s*(\d+)', low)
            if mtu:
                ev['mtu'] = int(mtu.group(1))
            events.append(ev)
        elif 'router solicitation' in low:
            events.append({'kind': 'rs', 'src': src})
        elif 'redirect' in low:
            events.append({'kind': 'redirect', 'src': src})
        elif 'dhcp6' in low:
            mt = re.search(r'dhcp6\s+([a-z-]+)', low)
            msgtype = mt.group(1) if mt else 'unknown'
            dns = re.findall(r'dns[- ]server[^0-9A-Fa-f]*'
                             r'([0-9A-Fa-f:]+)', low)
            events.append({'kind': 'dhcp6', 'src': src, 'msgtype': msgtype,
                           'dns': dns,
                           'is_server': msgtype in _IPV6_DHCP6_SERVER_MSGS})
    return events


def _ipv6_watch_load():
    try:
        with open(_IPV6_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _ipv6_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_IPV6_WATCH_PATH), exist_ok=True)
        tmp = _IPV6_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _IPV6_WATCH_PATH)
    except OSError:
        pass


def do_ipv6_baseline(action='get'):
    """Manage the learned IPv6 first-hop baseline (trusted RA router(s) + their
    RDNSS/prefixes, trusted DHCPv6 server(s)). action='reset' re-learns the
    current segment on the next scan (use after a legitimate IPv6 change)."""
    with _ipv6_watch_lock:
        if action == 'reset':
            _ipv6_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _ipv6_watch_load()
        return {'success': True, 'baseline': {
            'routers': sorted((b.get('routers') or {}).keys()),
            'dhcp6_servers': sorted(b.get('dhcp6_servers') or []),
        }}


def _ipv6_analyze(events, seconds, baseline, learn=True):
    """Pure classifier over parsed IPv6 first-hop events. Returns the result
    payload (minus interface). Separated from capture so the self-test can drive
    it with synthetic packets. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))
    ra_events = [e for e in events if e['kind'] == 'ra']
    dhcp6_srv = [e for e in events if e['kind'] == 'dhcp6' and e.get('is_server')]
    ra_count = len(ra_events)
    ra_rate = round(ra_count / seconds, 2)

    known_routers = dict(baseline.get('routers') or {})
    known_servers = set(baseline.get('dhcp6_servers') or [])
    had_baseline = bool(known_routers or known_servers)

    # Aggregate observed routers (by link-local source).
    routers = {}
    for e in ra_events:
        r = routers.setdefault(e['src'], {
            'src': e['src'], 'lifetime': e['lifetime'], 'pref': e['pref'],
            'managed': e['managed'], 'other': e['other'],
            'prefixes': set(), 'rdnss': set(), 'mac': e.get('mac'), 'count': 0})
        r['count'] += 1
        r['prefixes'].update(e['prefixes'])
        r['rdnss'].update(e['rdnss'])
        if e['pref'] == 'high':
            r['pref'] = 'high'
        if e['lifetime'] is not None:
            r['lifetime'] = e['lifetime']

    servers = {}
    for e in dhcp6_srv:
        s = servers.setdefault(e['src'], {'src': e['src'], 'msgtypes': set(),
                                          'dns': set()})
        s['msgtypes'].add(e['msgtype'])
        s['dns'].update(e['dns'])

    # Learn-on-first-run: adopt whatever's on the wire as the trusted baseline.
    learned = False
    if learn and not had_baseline and (routers or servers):
        baseline['routers'] = {src: {'prefixes': sorted(r['prefixes']),
                                     'rdnss': sorted(r['rdnss'])}
                               for src, r in routers.items()}
        baseline['dhcp6_servers'] = sorted(servers.keys())
        learned = True
        known_routers = dict(baseline['routers'])
        known_servers = set(baseline['dhcp6_servers'])

    reasons = []
    verdict = 'clean'

    # --- storm: RA flood ---
    if ra_rate >= _IPV6_RA_FLOOD_RATE and ra_count >= _IPV6_RA_FLOOD_RATE * seconds:
        verdict = 'storm'
        reasons.append(f"Router Advertisement flood: {ra_count} RAs in {seconds}s "
                       f"({ra_rate}/s) — RA-flood DoS (e.g. fake_router6)")

    rogue_routers = [src for src in routers if src not in known_routers]
    rogue_servers = [src for src in servers if src not in known_servers]

    # --- rogue RA (highest single-host severity) ---
    if verdict == 'clean' and rogue_routers:
        verdict = 'rogue-ra'
        for src in rogue_routers:
            r = routers[src]
            extra = []
            if r['rdnss']:
                extra.append(f"DNS {', '.join(sorted(r['rdnss']))}")
            if r['prefixes']:
                extra.append(f"prefix {', '.join(sorted(r['prefixes']))}")
            if r['pref'] == 'high':
                extra.append("pref HIGH")
            tail = (' — ' + '; '.join(extra)) if extra else ''
            reasons.append(f"Rogue Router Advertisement from {src}"
                           f"{' (MAC ' + r['mac'] + ')' if r['mac'] else ''}"
                           f"{tail} — becomes a default gateway/DNS via SLAAC")
        if not had_baseline:
            reasons.append("No IPv6 router was known for this segment — first-hop "
                           "IPv6 appeared where a tech would never look (classic "
                           "overlooked attack vector)")

    # --- rogue DHCPv6 (mitm6) ---
    if verdict in ('clean', 'rogue-ra') and rogue_servers:
        if verdict == 'clean':
            verdict = 'rogue-dhcpv6'
        for src in rogue_servers:
            s = servers[src]
            dns = f" handing out DNS {', '.join(sorted(s['dns']))}" if s['dns'] else ''
            reasons.append(f"Rogue DHCPv6 server {src} "
                           f"({'/'.join(sorted(s['msgtypes']))}){dns} — the mitm6 "
                           f"DNS-takeover / NTLM-relay signature")

    # --- anomalies (lower severity, don't override a rogue verdict) ---
    if verdict == 'clean':
        # >1 distinct router where the baseline knew <=1 = conflicting RAs.
        if len(routers) > 1 and len(known_routers) <= 1:
            verdict = 'anomaly'
            reasons.append(f"{len(routers)} routers advertising on one segment: "
                           f"{', '.join(sorted(routers))} — RA conflict/spoof")
        # RA that deprecates a router (lifetime 0) from a known router.
        for src, r in routers.items():
            if r['lifetime'] == 0:
                verdict = 'anomaly' if verdict == 'clean' else verdict
                reasons.append(f"RA from {src} with router-lifetime 0 — deprecates "
                               f"the IPv6 default route (RA 'kill' / DoS)")
        # A known router that started injecting a brand-new RDNSS DNS server.
        for src, r in routers.items():
            if src in known_routers:
                base_dns = set(known_routers[src].get('rdnss') or [])
                new_dns = set(r['rdnss']) - base_dns
                if new_dns:
                    verdict = 'rogue-ra'
                    reasons.append(f"Known router {src} now advertising new DNS "
                                   f"{', '.join(sorted(new_dns))} (RDNSS) — DNS "
                                   f"hijack via RA")

    # --- rogue ICMPv6 Redirect (type 137): the IPv6 twin of the ICMP redirect
    # MITM. A legitimate Redirect only comes from the host's first-hop router, so a
    # Redirect from any source that isn't a known router steers IPv6 traffic through
    # an attacker. (Captured all along; now classified.)
    redirect_srcs = sorted({e['src'] for e in events
                            if e['kind'] == 'redirect' and e.get('src')})
    rogue_redirects = [s for s in redirect_srcs if s not in known_routers]
    if rogue_redirects and verdict in ('clean', 'anomaly'):
        verdict = 'rogue-redirect'
    for src in rogue_redirects:
        reasons.append(f"ICMPv6 Redirect from {src} (not a known router) — steers "
                       f"IPv6 traffic through a rogue next-hop (Layer-3 MITM). Harden "
                       f"hosts with net.ipv6.conf.*.accept_redirects=0 (see RA Guard).")

    advisories = []
    if routers or servers or redirect_srcs:
        advisories.append("Enable switch RA-Guard (RFC 6105) and DHCPv6 snooping on "
                          "access ports; if IPv6 is unused, filter ICMPv6 RA/"
                          "DHCPv6 or disable IPv6 on hosts to remove the vector.")

    def _pub_router(r):
        return {'src': r['src'], 'lifetime': r['lifetime'], 'pref': r['pref'],
                'managed': r['managed'], 'other': r['other'], 'mac': r['mac'],
                'prefixes': sorted(r['prefixes']), 'rdnss': sorted(r['rdnss']),
                'count': r['count'], 'baseline': r['src'] in known_routers}

    def _pub_server(s):
        return {'src': s['src'], 'msgtypes': sorted(s['msgtypes']),
                'dns': sorted(s['dns']), 'baseline': s['src'] in known_servers}

    return {
        'success': True,
        'verdict': verdict,
        'reasons': reasons or (['No IPv6 first-hop traffic seen — segment quiet']
                               if not (routers or servers) else
                               ['All routers/servers match the trusted baseline']),
        'learned': learned,
        'ra_count': ra_count,
        'dhcp6_count': len([e for e in events if e['kind'] == 'dhcp6']),
        'redirect_count': len([e for e in events if e['kind'] == 'redirect']),
        'rate': ra_rate,
        'routers': [_pub_router(routers[s]) for s in sorted(routers)],
        'dhcp6_servers': [_pub_server(servers[s]) for s in sorted(servers)],
        'advisories': advisories,
    }


def _ipv6_capture(interface, seconds):
    """Run one passive tcpdump window over IPv6 first-hop traffic (RA/RS/Redirect
    + DHCPv6) and return (raw_text, error)."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    # ICMPv6 RA(134)/RS(133)/Redirect(137) + DHCPv6 (udp 546/547). ip6[40] is the
    # ICMPv6 type when there are no extension headers, which RAs never carry.
    bpf = ('(icmp6 and (ip6[40] == 134 or ip6[40] == 133 or ip6[40] == 137)) '
           'or (udp and (port 547 or port 546))')
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface,
                '-nn', '-t', '-v', '-s', '512', '-c', '20000', bpf],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()
                                   or 'syntax error' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_ipv6_watch(interface=None, seconds=12, learn=True, quick=False):
    """Passive IPv6 first-hop security scanner (detection-only). Captures RA /
    DHCPv6 for a few seconds and classifies the segment: storm / rogue-ra /
    rogue-dhcpv6 / anomaly / clean. Learns the trusted router(s)+server(s) on
    first run."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 12, 4, 40)

    text, err = _ipv6_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    events = _parse_ipv6_capture(text)

    with _ipv6_watch_lock:
        baseline = _ipv6_watch_load()
        result = _ipv6_analyze(events, seconds, baseline, learn=learn)
        if result.get('learned'):
            _ipv6_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _ipv6_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_IPV6_EVENTS_CAP:]
            _ipv6_watch_save(b)

    result['interface'] = iface
    return result


def _ipv6_selftest():
    """Self-test the IPv6 first-hop detectors with synthetic captures (no root, no
    live traffic). Feeds crafted tcpdump text through the real parser + classifier,
    and — if Scapy is available — builds a real RA into a pcap and parses it back
    through tcpdump end to end. Returns a results dict."""
    scenarios = []

    def run(name, text, seconds, baseline, expect):
        events = _parse_ipv6_capture(text)
        res = _ipv6_analyze(events, seconds, dict(baseline), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'events': len(events), 'pass': ok})
        return res

    # A realistic multi-line RA block from tcpdump -v.
    def ra(src, lifetime=1800, pref='medium', prefix='2001:db8:1::/64',
           rdnss=None, mac='00:11:22:33:44:55'):
        lines = [f"{src} > ff02::1: ICMP6, router advertisement, length 88",
                 f"\thop limit 64, Flags [other stateful], pref {pref}, "
                 f"router lifetime {lifetime}s, reachable time 0ms, retrans timer 0ms",
                 f"\t  source link-address option (1), length 8 (1): {mac}",
                 f"\t  prefix info option (3), length 32 (4): {prefix}, "
                 f"Flags [onlink, auto], valid time 2592000s, pref. time 604800s"]
        if rdnss:
            lines.append(f"\t  rdnss option (25), length 24 (3):  lifetime 1800s, "
                         f"addr: {rdnss}")
        return "\n".join(lines)

    base_one = {'routers': {'fe80::1': {'prefixes': ['2001:db8:1::/64'],
                                        'rdnss': ['2001:db8:1::53']}},
                'dhcp6_servers': []}

    # 1. clean: the known router re-advertising the same prefix/DNS.
    run('clean', ra('fe80::1', rdnss='2001:db8:1::53'), 12, base_one, 'clean')

    # 2. rogue-ra: an unknown router advertises itself as gateway + DNS.
    run('rogue-ra', ra('fe80::bad', pref='high', prefix='2001:db8:66::/64',
                       rdnss='2001:db8:66::53'), 12, base_one, 'rogue-ra')

    # 3. rogue-dhcpv6 (mitm6): an unknown DHCPv6 server hands out DNS.
    mitm6 = ("fe80::evil > fe80::a: dhcp6 advertise (xid=0x112233 "
             "(client-ID ...) (server-ID ...) (DNS-server 2001:db8:66::53) "
             "(IA_NA ...))")
    run('rogue-dhcpv6', mitm6, 12, base_one, 'rogue-dhcpv6')

    # 4. storm: an RA flood.
    flood = "\n".join(ra(f"fe80::{i}") for i in range(80))
    run('storm', flood, 5, base_one, 'storm')

    # 5. anomaly: a known router deprecates the default route (lifetime 0).
    run('anomaly', ra('fe80::1', lifetime=0, rdnss='2001:db8:1::53'), 12,
        base_one, 'anomaly')

    # 5b. rogue-redirect: an ICMPv6 Redirect from a host that isn't a known router.
    run('rogue-redirect',
        "fe80::bad > fe80::a: ICMP6, redirect, length 88", 12, base_one,
        'rogue-redirect')

    # 6. parse: multi-line RA extracts prefix + RDNSS + MAC.
    pev = _parse_ipv6_capture(ra('fe80::1', rdnss='2001:db8:1::53'))
    p_ok = (len(pev) == 1 and pev[0]['kind'] == 'ra'
            and '2001:db8:1::/64' in pev[0]['prefixes']
            and '2001:db8:1::53' in pev[0]['rdnss']
            and pev[0]['mac'] == '00:11:22:33:44:55')
    scenarios.append({'name': 'ra-parse', 'expect': 'prefix+rdnss+mac',
                      'got': str(pev[0] if pev else None)[:80], 'pass': p_ok})

    # Optional Scapy end-to-end: craft a real RA -> pcap -> tcpdump -> parse.
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import Ether, wrpcap
        from scapy.layers.inet6 import (IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo,
                                        ICMPv6NDOptRDNSS)
        if _have('tcpdump'):
            ra_pkt = (Ether() / IPv6(src='fe80::dead', dst='ff02::1') /
                      ICMPv6ND_RA(routerlifetime=1800) /
                      ICMPv6NDOptPrefixInfo(prefix='2001:db8:99::', prefixlen=64) /
                      ICMPv6NDOptRDNSS(dns=['2001:db8:99::53']))
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, [ra_pkt])
            res = _run(['tcpdump', '-nn', '-t', '-v', '-r', pcap_path], timeout=10)
            evs = _parse_ipv6_capture(res['out'])
            ra_evs = [e for e in evs if e['kind'] == 'ra']
            got_pref = ra_evs[0]['prefixes'] if ra_evs else []
            scapy_result = {'ran': True, 'routers': [e['src'] for e in ra_evs],
                            'prefixes': got_pref,
                            'pass': any('2001:db8:99' in p for p in got_pref),
                            'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and \
        (not scapy_result.get('ran') or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# NDP Watch: passive IPv6 Neighbor Discovery spoofing detector (detection-only)
# --------------------------------------------------------------------------
# The IPv6 twin of ARP Watch. ARP Watch catches IPv4 cache poisoning; IPv6
# First-Hop Watch catches rogue RA / DHCPv6 (mitm6) — but neither catches the
# direct IPv6 analogue of ARP poisoning: a forged Neighbor Advertisement (ICMPv6
# type 136) claiming someone else's address, which poisons every neighbour's ND
# cache and puts an attacker on-path (THC parasite6). On any dual-stack LAN this
# is the open door a v4-only defender never sees. This scanner is PASSIVE: one
# short tcpdump window over Neighbor Solicitation/Advertisement (135/136), parsed
# and classified. It never sends an NA, never answers a solicit. What it flags:
#   * spoofed  — two+ MACs claim one target address (parasite6), the default
#     router advertised by a MAC other than the trusted one (router poisoning /
#     MITM), or a learned host's owner-MAC changing (ND cache takeover).
#   * dad-dos  — one MAC answering the Duplicate Address Detection probe for many
#     addresses it doesn't own (THC dos-new-ip6): defends every claim so no host
#     can pick an IPv6 address — a SLAAC denial of service.
#   * storm    — a Neighbor Advertisement flood (flood_advertise6) by rate.
# First run learns the trusted target->MAC bindings + the default router into
# data/ndp_watch.json; "Trust current" re-learns after a legitimate change.
# Mitigation advisory points at switch IPv6 Snooping / ND Inspection (SAVI, RFC
# 6620) — the RA-Guard family that also binds the neighbour table.

_NDP_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'data', 'ndp_watch.json')
_ndp_watch_lock = threading.Lock()

# One MAC that NA-defends at least this many distinct DAD targets is running the
# dos-new-ip6 attack (answering every address claim so no host can join).
_NDP_DAD_DEFENDER_MIN = 4
# Sustained NA rate at/above this is a flood (parasite6 / flood_advertise6). NAs
# are normally rare (a handful per host as caches refresh), so the floor is high.
_NDP_NA_FLOOD_RATE = 20.0
# Keep at most this many anomaly events in the store (newest wins).
_NDP_EVENTS_CAP = 200

_NDP_MAC_RE = r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})'


def _default_gateway6():
    """Return (ipv6_gateway, dev) for the IPv6 default route, or (None, None).
    The gateway is usually a link-local fe80:: address."""
    res = _run(['ip', '-6', 'route', 'show', 'default'], timeout=5)
    addr = re.search(r'default\s+via\s+' + _IPV6_ADDR_RE, res['out'])
    dev = re.search(r'default\b.*?\bdev\s+(\S+)', res['out'])
    return (addr.group(1) if addr else None, dev.group(1) if dev else None)


def _neigh6_mac(ip):
    """Current MAC bound to an IPv6 `ip` in the kernel neighbour table, or None."""
    if not ip:
        return None
    res = _run(['ip', '-6', 'neigh', 'show'], timeout=5)
    for line in res['out'].splitlines():
        m = re.match(r'^' + _IPV6_ADDR_RE + r'\b.*?\blladdr\s+' + _NDP_MAC_RE, line)
        if m and m.group(1) == ip:
            return m.group(2).lower()
    return None


def _ndp_watch_load():
    try:
        with open(_NDP_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _ndp_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_NDP_WATCH_PATH), exist_ok=True)
        tmp = _NDP_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _NDP_WATCH_PATH)
    except OSError:
        pass


def do_ndp_baseline(action='get'):
    """Manage the learned NDP baseline (trusted target->MAC bindings + the default
    router's MAC). action='reset' re-learns the current segment on the next scan
    (use after a legitimate device/router change)."""
    with _ndp_watch_lock:
        if action == 'reset':
            _ndp_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _ndp_watch_load()
        return {'success': True, 'baseline': {
            'bindings': b.get('bindings') or {},
            'router': b.get('router') or {},
        }}


def _parse_ndp_capture(output):
    """Parse `tcpdump -e -nn -t -v` NS/NA text into events.

    With -e each packet's header line begins with the Ethernet src/dst MAC and
    carries ', ethertype '; option lines are indented. Events:
      na : {kind, eth_src, src, tgt, flags{router,solicited,override}, lladdr}
      ns : {kind, eth_src, src, tgt, dad, lladdr}
    `lladdr` for an NA is the *claimed owner* of tgt (target link-layer address
    option, which tcpdump prints as 'destination link-address option (2)'); it
    falls back to the Ethernet source when the option is absent. That binding
    (tgt -> lladdr) is exactly what a spoofer forges.
    """
    events = []
    blocks, cur = [], []
    for raw in output.splitlines():
        if not raw.strip():
            continue
        if not raw[0].isspace() and ', ethertype ' in raw:
            if cur:
                blocks.append(cur)
            cur = [raw]
        elif cur:
            cur.append(raw)
    if cur:
        blocks.append(cur)

    hdr_re = re.compile(r'^' + _NDP_MAC_RE + r'\s*>\s*' + _NDP_MAC_RE)
    inner_re = re.compile(r'ethertype IPv6[^:]*:\s*' + _IPV6_ADDR_RE +
                          r'\s*>\s*' + _IPV6_ADDR_RE + r':')
    for block in blocks:
        head = block[0]
        text = '\n'.join(block)
        low = text.lower()
        hm = hdr_re.match(head.strip())
        eth_src = hm.group(1).lower() if hm else None
        im = inner_re.search(head)
        src = im.group(1) if im else None

        if 'neighbor advertisement' in low:
            tm = re.search(r'tgt is\s+' + _IPV6_ADDR_RE, text)
            fl = re.search(r'flags\s+\[([^\]]*)\]', low)
            flags = fl.group(1) if fl else ''
            om = re.search(r'destination link-address option \(2\).*?:\s*' +
                           _NDP_MAC_RE, low, re.S)
            events.append({'kind': 'na', 'eth_src': eth_src, 'src': src,
                           'tgt': tm.group(1) if tm else None,
                           'lladdr': (om.group(1).lower() if om else eth_src),
                           'flags': {'router': 'router' in flags,
                                     'solicited': 'solicited' in flags,
                                     'override': 'override' in flags}})
        elif 'neighbor solicitation' in low:
            wm = re.search(r'who has\s+' + _IPV6_ADDR_RE, text)
            om = re.search(r'source link-address option \(1\).*?:\s*' +
                           _NDP_MAC_RE, low, re.S)
            events.append({'kind': 'ns', 'eth_src': eth_src, 'src': src,
                           'tgt': wm.group(1) if wm else None,
                           'dad': (src == '::'),
                           'lladdr': (om.group(1).lower() if om else eth_src)})
    return events


def _ndp_analyze(events, seconds, baseline, learn=True):
    """Pure classifier over parsed NS/NA events. Returns the result payload (minus
    interface). Separated from capture so the self-test can drive it with
    synthetic packets. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))
    na = [e for e in events if e['kind'] == 'na' and e.get('tgt')]
    ns = [e for e in events if e['kind'] == 'ns' and e.get('tgt')]
    na_count = len(na)
    na_rate = round(na_count / seconds, 2)

    known = dict(baseline.get('bindings') or {})          # ipv6 -> mac
    router = baseline.get('router') or {}                  # {addr, mac}
    had_baseline = bool(known or router.get('mac'))

    # tgt -> set of MACs claiming to own it (from each NA's target-lladdr).
    claims = {}
    for e in na:
        claims.setdefault(e['tgt'], set()).add(e['lladdr'])

    # Learn-on-first-run: adopt every *unambiguous* binding on the wire.
    learned = False
    if learn and not had_baseline and claims:
        known = {ip: next(iter(macs)) for ip, macs in claims.items()
                 if len(macs) == 1}
        baseline['bindings'] = dict(known)
        learned = True

    reasons = []
    verdict = 'clean'

    # --- storm: NA flood (parasite6 / flood_advertise6) ---
    if na_rate >= _NDP_NA_FLOOD_RATE and na_count >= _NDP_NA_FLOOD_RATE * seconds:
        verdict = 'storm'
        reasons.append(f"Neighbor Advertisement flood: {na_count} NAs in {seconds}s "
                       f"({na_rate}/s) — NDP flood DoS (e.g. flood_advertise6)")

    # --- spoofed: two+ MACs claim one target, a baseline binding changed, or the
    # default router is advertised by a MAC other than the trusted one ---
    conflicts = {ip: sorted(macs) for ip, macs in claims.items() if len(macs) > 1}
    changed = {ip: (known[ip], next(iter(macs)))
               for ip, macs in claims.items()
               if ip in known and len(macs) == 1 and next(iter(macs)) != known[ip]}
    router_hit = None
    if router.get('addr') and router['addr'] in claims:
        rmacs = claims[router['addr']]
        if router.get('mac') and (len(rmacs) > 1 or
                                  next(iter(rmacs)) != router['mac']):
            router_hit = sorted(rmacs)

    if conflicts or changed or router_hit:
        verdict = 'spoofed' if verdict == 'clean' else verdict
        if router_hit:
            reasons.append(f"Default router {router['addr']} advertised by "
                           f"{', '.join(router_hit)} (trusted {router['mac']}) — "
                           f"NDP router poisoning / IPv6 MITM")
        for ip, macs in conflicts.items():
            if router_hit and ip == router.get('addr'):
                continue
            reasons.append(f"{ip} claimed by {len(macs)} MACs ({', '.join(macs)}) "
                           f"— spoofed Neighbor Advertisement (parasite6), the IPv6 "
                           f"twin of ARP cache poisoning")
        for ip, (was, now) in changed.items():
            reasons.append(f"{ip} owner MAC changed from trusted {was} to {now} "
                           f"— NDP cache poisoning / MITM")

    # --- dad-dos: one MAC NA-defends many distinct DAD'd targets (dos-new-ip6) ---
    dad_targets = {e['tgt'] for e in ns if e.get('dad')}
    defender = {}                                          # mac -> set(targets)
    for e in na:
        if e['tgt'] in dad_targets and not e['flags'].get('solicited'):
            defender.setdefault(e['lladdr'], set()).add(e['tgt'])
    dad_dos = {mac: sorted(t) for mac, t in defender.items()
               if len(t) >= _NDP_DAD_DEFENDER_MIN}
    if dad_dos and verdict == 'clean':
        verdict = 'dad-dos'
    for mac, tgts in dad_dos.items():
        reasons.append(f"MAC {mac} defends {len(tgts)} address claims via NA "
                       f"(DAD responses) — dos-new-ip6: blocks every host from "
                       f"picking an IPv6 address (SLAAC DoS)")

    advisories = []
    if claims or dad_targets:
        advisories.append("Enable IPv6 Snooping / ND Inspection (RA-Guard family, "
                          "RFC 6620 SAVI) on access ports; if IPv6 is unused, disable "
                          "it on hosts to remove the neighbour-cache attack surface.")

    hosts = [{'ip': ip, 'macs': sorted(macs),
              'baseline': known.get(ip), 'conflict': len(macs) > 1}
             for ip, macs in sorted(claims.items())]

    return {
        'success': True,
        'verdict': verdict,
        'reasons': reasons or (['No Neighbor Discovery traffic seen — segment quiet']
                               if not (na or ns) else
                               ['All neighbour bindings consistent; no NA conflicts']),
        'learned': learned,
        'na_count': na_count,
        'ns_count': len(ns),
        'dad_count': len(dad_targets),
        'rate': na_rate,
        'hosts': hosts,
        'advisories': advisories,
    }


def _ndp_capture(interface, seconds):
    """Run one passive tcpdump window over Neighbor Solicitation/Advertisement
    (ICMPv6 135/136) and return (raw_text, error). -e keeps the Ethernet source
    MAC, which the spoof correlation needs."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    # ip6[40] is the ICMPv6 type when there are no extension headers, which NS/NA
    # never carry.
    bpf = 'icmp6 and (ip6[40] == 135 or ip6[40] == 136)'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface,
                '-e', '-nn', '-t', '-v', '-s', '512', '-c', '20000', bpf],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()
                                   or 'syntax error' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_ndp_watch(interface=None, seconds=12, learn=True, quick=False):
    """Passive IPv6 Neighbor Discovery spoofing scanner (detection-only). Captures
    NS/NA for a few seconds and classifies the segment: storm / spoofed / dad-dos
    / clean. Learns the trusted target->MAC bindings + default router on first
    run. The IPv6 twin of ARP Watch."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 12, 4, 40)

    text, err = _ndp_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    events = _parse_ndp_capture(text)

    with _ndp_watch_lock:
        baseline = _ndp_watch_load()
        # Seed the trusted default-router binding from the kernel on first run so
        # router poisoning is named even before we see the router advertise.
        if learn and not (baseline.get('router') or {}).get('mac'):
            gw6, _ = _default_gateway6()
            gw_mac = _neigh6_mac(gw6) if gw6 else None
            if gw6 and gw_mac:
                baseline['router'] = {'addr': gw6, 'mac': gw_mac}
        result = _ndp_analyze(events, seconds, baseline, learn=learn)
        if result.get('learned') or (baseline.get('router') or {}).get('mac'):
            _ndp_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _ndp_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_NDP_EVENTS_CAP:]
            _ndp_watch_save(b)

    result['interface'] = iface
    return result


def _ndp_selftest():
    """Self-test the NDP spoofing detectors with synthetic captures (no root, no
    live traffic). Feeds crafted tcpdump text through the real parser + classifier,
    and — if Scapy is available — builds a real NA into a pcap and parses it back
    through tcpdump end to end. Returns a results dict."""
    scenarios = []

    def run(name, text, seconds, baseline, expect):
        events = _parse_ndp_capture(text)
        res = _ndp_analyze(events, seconds, dict(baseline), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'events': len(events), 'pass': ok})
        return res

    def na(eth, tgt, lladdr=None, flags='router, solicited, override', src=None):
        src = src or tgt
        ll = lladdr or eth
        return (f"{eth} > 11:22:33:44:55:66, ethertype IPv6 (0x86dd), length 86: "
                f"{src} > ff02::1: ICMP6, neighbor advertisement, length 32, "
                f"tgt is {tgt}, Flags [{flags}]\n"
                f"\t  destination link-address option (2), length 8 (1): {ll}")

    def ns(eth, tgt, src=None):
        src = src or 'fe80::aaaa'
        line = (f"{eth} > 33:33:ff:00:00:01, ethertype IPv6 (0x86dd), length 86: "
                f"{src} > ff02::1:ff00:1: ICMP6, neighbor solicitation, length 32, "
                f"who has {tgt}")
        if src != '::':
            line += f"\n\t  source link-address option (1), length 8 (1): {eth}"
        return line

    base = {'bindings': {'2001:db8::10': 'aa:bb:cc:00:00:10'},
            'router': {'addr': 'fe80::1', 'mac': 'aa:bb:cc:00:00:01'}}

    # 1. clean: the known host re-advertises its own address with its own MAC.
    run('clean', na('aa:bb:cc:00:00:10', '2001:db8::10'), 12, base, 'clean')
    # 2. spoofed: two MACs both claim one target (parasite6).
    run('spoofed-conflict',
        na('aa:bb:cc:00:00:10', '2001:db8::10') + "\n" +
        na('de:ad:be:ef:00:99', '2001:db8::10'), 12, base, 'spoofed')
    # 3. spoofed: the default router advertised by a rogue MAC (router poison).
    run('spoofed-router', na('de:ad:be:ef:00:99', 'fe80::1'), 12, base, 'spoofed')
    # 4. spoofed: a known host's binding changed to a new single MAC.
    run('spoofed-changed',
        na('de:ad:be:ef:00:99', '2001:db8::10'), 12, base, 'spoofed')
    # 5. dad-dos: one MAC answers NA (unsolicited) for many DAD'd targets.
    dad = "\n".join(
        ns('00:00:00:00:00:00', f'2001:db8::{i}', src='::') + "\n" +
        na('de:ad:be:ef:00:99', f'2001:db8::{i}', flags='override')
        for i in range(1, 7))
    run('dad-dos', dad, 12, base, 'dad-dos')
    # 6. storm: an NA flood.
    flood = "\n".join(na(f'aa:bb:cc:00:{i//256:02x}:{i%256:02x}',
                         f'2001:db8:f::{i}', flags='override')
                      for i in range(300))
    run('storm', flood, 5, base, 'storm')

    # 7. parse: NA target-lladdr option is read as the claimed owner, not eth_src.
    pev = _parse_ndp_capture(na('aa:bb:cc:00:00:10', '2001:db8::10',
                                lladdr='aa:bb:cc:00:00:aa'))
    p_ok = (len(pev) == 1 and pev[0]['kind'] == 'na'
            and pev[0]['tgt'] == '2001:db8::10'
            and pev[0]['lladdr'] == 'aa:bb:cc:00:00:aa'
            and pev[0]['flags']['override'])
    scenarios.append({'name': 'na-parse', 'expect': 'tgt+lladdr+flags',
                      'got': str(pev[0] if pev else None)[:80], 'pass': p_ok})
    # 8. parse: DAD NS (unspecified source ::) is flagged.
    dev = _parse_ndp_capture(ns('00:00:00:00:00:00', '2001:db8::9', src='::'))
    d_ok = len(dev) == 1 and dev[0]['kind'] == 'ns' and dev[0]['dad']
    scenarios.append({'name': 'dad-parse', 'expect': 'dad=True',
                      'got': str(dev[0] if dev else None)[:80], 'pass': d_ok})

    # Optional Scapy end-to-end: craft a real NA -> pcap -> tcpdump -e -> parse.
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import Ether, wrpcap
        from scapy.layers.inet6 import IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
        if _have('tcpdump'):
            pkt = (Ether(src='de:ad:be:ef:00:99') /
                   IPv6(src='fe80::99', dst='ff02::1') /
                   ICMPv6ND_NA(tgt='fe80::1', R=1, S=0, O=1) /
                   ICMPv6NDOptDstLLAddr(lladdr='de:ad:be:ef:00:99'))
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, [pkt])
            res = _run(['tcpdump', '-e', '-nn', '-t', '-v', '-r', pcap_path],
                       timeout=10)
            evs = _parse_ndp_capture(res['out'])
            nas = [e for e in evs if e['kind'] == 'na']
            scapy_result = {'ran': True,
                            'tgt': nas[0]['tgt'] if nas else None,
                            'lladdr': nas[0]['lladdr'] if nas else None,
                            'pass': bool(nas) and nas[0]['tgt'] == 'fe80::1'
                                    and nas[0]['lladdr'] == 'de:ad:be:ef:00:99',
                            'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and \
        (not scapy_result.get('ran') or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# IPv6 RA Guard: host first-hop posture check + hardening (active, local)
# --------------------------------------------------------------------------
# Where IPv6 First-Hop Watch *detects* a rogue RA / DHCPv6 / ICMPv6-Redirect on the
# wire, RA Guard is the *defence*: it audits THIS host's own IPv6 knobs and can
# harden them so a rogue first-hop can't take effect even if it reaches the host.
# It never sends a packet — it reads /proc/sys/net/ipv6/conf and the routing table.
# The knobs that matter for first-hop security:
#   * accept_redirects      — accepting an ICMPv6 Redirect lets any on-link host
#     reroute your traffic (L3 MITM). A host should never accept them -> harden to 0.
#   * accept_ra_rtr_pref     — honouring the RA Router-Preference lets a rogue
#     "pref high" RA jump ahead of the real router -> harden to 0.
#   * accept_ra              — accepting RAs at all (SLAAC). Left ALONE by harden:
#     turning it off would drop IPv6 connectivity on legit SLAAC networks; it is
#     only safe with upstream switch RA-Guard, which we surface as advice.
# Hardening writes the two safe sysctls live and persists them so they survive a
# reboot; accept_ra is deliberately untouched.
_RAGUARD_SYSCTL_FILE = '/etc/sysctl.d/99-ragnar-raguard.conf'
_RAGUARD_KEYS = ('accept_ra', 'accept_ra_defrtr', 'accept_ra_rtr_pref',
                 'accept_ra_pinfo', 'accept_redirects', 'autoconf', 'forwarding',
                 'disable_ipv6', 'use_tempaddr')
# (key, target) pairs applied by Harden — safe, do not break SLAAC connectivity.
_RAGUARD_HARDEN = (('accept_redirects', 0), ('accept_ra_rtr_pref', 0))
_RAGUARD_PRIORITY = ['redirect-open', 'ra-pref-open', 'ra-open', 'hardened',
                     'ipv6-off']
# Virtual / container / VPN interfaces — hardened by the same all-scope sysctl, but
# not the untrusted-facing NICs, so the UI collapses them.
_RAGUARD_VIRTUAL_RE = re.compile(
    r'^(veth|br-|docker|virbr|vmnet|vnet|tap|tun|wg\d|zt|tailscale|cni|flannel|'
    r'cali|kube|nomad|dummy|bond|team|ifb|gre|sit|ip6tnl|erspan)', re.IGNORECASE)


def _raguard_read_conf(iface):
    """Read the relevant net.ipv6.conf.<iface>.* knobs from /proc (None if absent)."""
    base = f'/proc/sys/net/ipv6/conf/{iface}'
    out = {}
    for k in _RAGUARD_KEYS:
        try:
            with open(f'{base}/{k}') as f:
                out[k] = int(f.read().strip())
        except (OSError, ValueError):
            out[k] = None
    return out


def _raguard_ifaces():
    """Real IPv6-capable interfaces (exclude the all/default templates and lo)."""
    try:
        names = sorted(os.listdir('/proc/sys/net/ipv6/conf'))
    except OSError:
        return []
    return [n for n in names if n not in ('all', 'default', 'lo')]


def _raguard_accepted_gateways():
    """The IPv6 default route(s) the host has actually installed — the first hop it
    trusts right now — and whether each came from an RA (proto ra)."""
    res = _run(['ip', '-6', 'route', 'show', 'default'], timeout=5)
    gws = []
    for line in (res.get('out') or '').splitlines():
        m = re.search(r'default\s+via\s+(\S+)\s+dev\s+(\S+)', line)
        if m:
            gws.append({'gw': m.group(1), 'dev': m.group(2),
                        'from_ra': 'proto ra' in line})
    return gws


def _raguard_analyze(all_conf, ifaces_conf, gateways=None):
    """Pure classifier over the host's IPv6 first-hop posture. Grades each interface
    (worst-case: a knob is 'on' if either the interface OR the all-scope has it set),
    rolls up the worst, and builds the harden plan. Separated for the self-test."""
    all_conf = all_conf or {}
    gateways = gateways or []

    def on(c, key):
        return c.get(key) == 1 or all_conf.get(key) == 1

    per = []
    for iface in sorted(ifaces_conf):
        c = ifaces_conf[iface]
        ipv6_off = c.get('disable_ipv6') == 1
        redirect_open = on(c, 'accept_redirects')
        ra_on = c.get('accept_ra') not in (0, None)
        rtr_pref_on = on(c, 'accept_ra_rtr_pref')
        if ipv6_off:
            v, why = 'ipv6-off', 'IPv6 disabled on this interface'
        elif redirect_open:
            v, why = ('redirect-open',
                      'accepts ICMPv6 Redirects (accept_redirects=1) — open to a '
                      'redirect MITM')
        elif ra_on and rtr_pref_on:
            v, why = ('ra-pref-open',
                      'honours RA Router-Preference (accept_ra_rtr_pref=1) — a rogue '
                      '"pref high" RA can hijack the default route')
        elif ra_on:
            v, why = ('ra-open',
                      'accepts Router Advertisements (SLAAC) — safe only if the '
                      'switch enforces RA-Guard')
        else:
            v, why = 'hardened', 'ignores RAs and ICMPv6 Redirects'
        per.append({'iface': iface, 'verdict': v, 'reason': why,
                    'virtual': bool(_RAGUARD_VIRTUAL_RE.match(iface)),
                    'accept_ra': c.get('accept_ra'),
                    'accept_ra_rtr_pref': c.get('accept_ra_rtr_pref'),
                    'accept_redirects': c.get('accept_redirects'),
                    'forwarding': c.get('forwarding'),
                    'disable_ipv6': c.get('disable_ipv6'),
                    'redirect_open': redirect_open, 'rtr_pref_on': rtr_pref_on})

    # Physical/untrusted-facing NICs first, then virtuals.
    per.sort(key=lambda p: (p['virtual'], p['iface']))
    # Overall reflects the worst *physical* interface when there is one (virtuals are
    # covered by the same all-scope harden but aren't the exposed surface).
    phys = [p['verdict'] for p in per if not p['virtual']]
    verdicts = phys or [p['verdict'] for p in per] or ['ipv6-off']
    overall = min(verdicts, key=_RAGUARD_PRIORITY.index)

    # Does anything need hardening? (redirect or rtr-pref open anywhere, incl. all-scope)
    needs = any(p['redirect_open'] or p['rtr_pref_on'] for p in per) \
        or on({}, 'accept_redirects') or on({}, 'accept_ra_rtr_pref')

    reasons = []
    for p in per:
        if not p['virtual'] and p['verdict'] not in ('hardened', 'ipv6-off'):
            reasons.append(f"{p['iface']}: {p['reason']}")
    virt_exposed = sum(1 for p in per if p['virtual']
                       and p['verdict'] not in ('hardened', 'ipv6-off'))
    if virt_exposed:
        reasons.append(f"…and {virt_exposed} virtual/container interface(s) with the "
                       f"same exposure (covered by the same all-scope harden)")
    if not reasons:
        reasons = ['Host ignores ICMPv6 Redirects and rogue RA preferences — '
                   'first-hop hardened' if overall != 'ipv6-off'
                   else 'IPv6 is disabled on all interfaces — no IPv6 first-hop surface']

    remediation = []
    if needs:
        for scope in ('all', 'default'):
            for key, val in _RAGUARD_HARDEN:
                remediation.append(f'net.ipv6.conf.{scope}.{key} = {val}')

    advisories = []
    if any(p['verdict'] == 'ra-open' or p['verdict'] == 'ra-pref-open' for p in per):
        advisories.append('This host accepts Router Advertisements (SLAAC). That is '
                          'only safe if the access switch enforces RA-Guard (RFC '
                          '6105); otherwise a rogue RA can still add a gateway/DNS. '
                          'Pair this with IPv6 First-Hop Watch to catch it on the wire.')

    return {
        'success': True,
        'verdict': overall,
        'reasons': reasons,
        'interfaces': per,
        'gateways': gateways,
        'needs_hardening': needs,
        'remediation': remediation,
        'advisories': advisories,
    }


def _raguard_apply():
    """Harden: set the safe sysctls live for all/default + every IPv6 interface, and
    persist them. Leaves accept_ra untouched. Returns what changed."""
    live, errors = [], []
    scopes = ['all', 'default'] + _raguard_ifaces()
    for scope in scopes:
        for key, val in _RAGUARD_HARDEN:
            name = f'net.ipv6.conf.{scope}.{key}'
            res = _run(['sysctl', '-w', f'{name}={val}'], timeout=5)
            if res.get('rc', 0) == 0 and 'error' not in (res.get('err') or '').lower():
                live.append(name)
            else:
                errors.append(f"{name}: {(res.get('err') or 'failed').strip()[:80]}")
    # Persist (all/default cover interfaces created later; explicit per-if too).
    body = ["# Ragnar IPv6 RA-Guard hardening — closes the ICMPv6-redirect and rogue",
            "# RA-preference holes. accept_ra is intentionally left untouched so SLAAC",
            "# connectivity keeps working. Managed by Ragnar; edit via the RA Guard tool.",
            ""]
    for scope in scopes:
        for key, val in _RAGUARD_HARDEN:
            body.append(f'net.ipv6.conf.{scope}.{key} = {val}')
    persisted = None
    try:
        with open(_RAGUARD_SYSCTL_FILE, 'w') as f:
            f.write("\n".join(body) + "\n")
        persisted = _RAGUARD_SYSCTL_FILE
    except OSError as e:
        errors.append(f"persist {_RAGUARD_SYSCTL_FILE}: {e}")
    return {'live': live, 'persisted': persisted, 'errors': errors}


def do_raguard(action='check'):
    """IPv6 RA Guard: audit (and optionally harden) the host's IPv6 first-hop
    posture. action='check' reads only; action='harden' applies the safe sysctls
    (accept_redirects=0, accept_ra_rtr_pref=0) live + persisted, then re-checks."""
    applied = None
    if action == 'harden':
        applied = _raguard_apply()
    all_conf = _raguard_read_conf('all')
    ifaces = _raguard_ifaces()
    ifaces_conf = {i: _raguard_read_conf(i) for i in ifaces}
    if not ifaces_conf:
        return {'success': True, 'verdict': 'ipv6-off', 'interfaces': [],
                'reasons': ['No IPv6-capable interfaces found'], 'gateways': [],
                'needs_hardening': False, 'remediation': [], 'advisories': [],
                'applied': applied, 'all': all_conf}
    result = _raguard_analyze(all_conf, ifaces_conf, _raguard_accepted_gateways())
    result['all'] = all_conf
    result['applied'] = applied
    result['persist_file'] = _RAGUARD_SYSCTL_FILE
    return result


def _raguard_selftest():
    """Self-test the RA Guard grader with synthetic posture dicts (no root, no host
    change), plus a read-only live 'check' leg that exercises the /proc path."""
    scenarios = []
    allz = {k: 0 for k in _RAGUARD_KEYS}    # all-scope neutral (nothing forced on)

    def conf(**kw):
        c = {k: 0 for k in _RAGUARD_KEYS}
        c.update(kw)
        return c

    def run(name, ifaces_conf, expect, all_conf=None):
        res = _raguard_analyze(all_conf or allz, ifaces_conf)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'pass': ok})
        return res

    # hardened: accept_ra off, redirects off.
    run('hardened', {'eth0': conf(accept_ra=0, accept_redirects=0)}, 'hardened')
    # redirect-open: accepts ICMPv6 redirects.
    run('redirect-open', {'eth0': conf(accept_ra=1, accept_redirects=1)},
        'redirect-open')
    # ra-pref-open: SLAAC + honours router preference.
    run('ra-pref-open',
        {'eth0': conf(accept_ra=1, accept_ra_rtr_pref=1, accept_redirects=0)},
        'ra-pref-open')
    # ra-open: SLAAC but ignores router preference + redirects.
    run('ra-open',
        {'eth0': conf(accept_ra=1, accept_ra_rtr_pref=0, accept_redirects=0)},
        'ra-open')
    # ipv6-off.
    run('ipv6-off', {'eth0': conf(disable_ipv6=1)}, 'ipv6-off')
    # all-scope redirect on overrides a clean interface (worst-case OR).
    run('all-scope-redirect', {'eth0': conf(accept_ra=0, accept_redirects=0)},
        'redirect-open', all_conf=conf(accept_redirects=1))
    # worst-of-many rolls up.
    r = run('rollup',
            {'eth0': conf(accept_ra=1, accept_redirects=0, accept_ra_rtr_pref=0),
             'eth1': conf(accept_ra=1, accept_redirects=1)}, 'redirect-open')
    scenarios.append({'name': 'rollup-needs-harden', 'expect': 'True',
                      'got': str(r['needs_hardening']), 'pass': r['needs_hardening']})

    # Live read-only leg: the real host posture check must succeed and grade ifaces.
    e2e = {'ran': False, 'reason': 'skipped'}
    try:
        live = do_raguard('check')
        ok = live.get('success') and 'verdict' in live
        e2e = {'ran': True, 'verdict': live.get('verdict'),
               'interfaces': len(live.get('interfaces', [])), 'pass': bool(ok)}
    except Exception as e:
        e2e = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and (not e2e.get('ran')
                                                    or e2e.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'e2e': e2e}


# --------------------------------------------------------------------------
# NTP Watch: passive rogue-NTP / time-injection scanner (detection-only)
# --------------------------------------------------------------------------
# NTP (UDP/123) is the network's clock of record. It touches every layer, but the
# attack surface is Layer-7: a rogue NTP server that answers clients (or broadcasts)
# with the *wrong* time silently poisons every downstream timestamp — audit logs,
# TLS/Kerberos validity windows, MFA/TOTP, lab-result and chain-of-custody records.
# In a precision-critical shop (medical, finance, industrial) a few seconds of skew
# is a real-world incident, yet nobody watches 123. This scanner is PASSIVE: one
# short tcpdump window, parsed and classified against a learned baseline of the
# segment's trusted time sources. It never sends an NTP query. What it looks for:
#   * time-injection — a server whose transmit timestamp disagrees with the segment
#     consensus (or, with one source, the local clock) beyond a threshold: the core
#     attack — someone is serving a shifted clock.
#   * rogue-server   — an NTP server answering that isn't in the trusted baseline.
#   * kod            — a Kiss-o'-Death (stratum 0) reply; a rogue can use KoD
#     RATE/DENY to make clients back off legitimate sources (time-sync DoS).
#   * stratum-spoof  — a source claiming Stratum 1 (primary/GPS) it shouldn't, or a
#     known server lowering its stratum to win client preference.
#   * broadcast      — a mode-Broadcast time source (hosts in broadcast client mode
#     accept it blindly — a classic injection vector on modern unicast networks).
#   * recon          — NTP mode 6/7 (ntpq control / monlist) traffic: reconnaissance
#     or amplification abuse.
#   * anomaly        — implausible root dispersion, a leap-alarm (unsynced) source,
#     or a reference-ID loop.
_NTP_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'data', 'ntp_watch.json')
_ntp_watch_lock = threading.Lock()

# Seconds between the NTP timestamp epoch (1900-01-01) and the Unix epoch.
_NTP_UNIX_DELTA = 2208988800
# A server whose served time differs from consensus/local by more than this many
# seconds is injecting a skewed clock. Honest LAN/WAN sources agree to well under a
# second passively (offset ~ one-way delay), so this is far above the noise floor.
_NTP_OFFSET_THRESHOLD = 2.0
# Root dispersion above this (seconds) is implausible for a usable time source.
_NTP_DISP_ALARM = 4.0
_NTP_EVENTS_CAP = 200
# tcpdump mode labels for a *time source* (something a client would sync to).
_NTP_SERVER_MODES = ('Server', 'Broadcast', 'Symmetric Active', 'Symmetric Passive')
# Non-standard modes on 123 = ntpq control (6) / private-monlist (7); some tcpdump
# builds print both as 'Reserved'. Either way it's query/recon/amplification, never
# normal client<->server time exchange.
_NTP_CONTROL_MODES = ('Control Message', 'Private', 'Reserved')
# RFC 5905 Kiss-o'-Death codes (stratum-0 refid as 4 ASCII chars).
_NTP_KOD_CODES = frozenset(('DENY', 'RSTR', 'RATE', 'ACST', 'AUTH', 'AUTO', 'BCST',
                            'CRYP', 'DROP', 'MCST', 'NKEY', 'RMOT', 'INIT', 'STEP'))

_NTP_HDR_RE = re.compile(r'^(\d+\.\d+)\s+IP6?\b')
_NTP_SRC_RE = re.compile(
    r'(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+):\s*'
    r'NTPv(\d+),\s*([^,]+?),\s*length')


def _parse_ntp_capture(output):
    """Parse `tcpdump -nn -tt -v 'udp port 123'` text into per-packet NTP records.

    tcpdump prints one packet as an epoch header line (`<epoch> IP (tos ...)`)
    followed by an indented `SRC.port > DST.port: NTPvN, <Mode>, length` line and
    tab-indented field lines. We group by packet block (new block at each epoch
    header), then read each block. Each record is a dict:
      {rx_epoch, src, dst, sport, dport, ver, mode, stratum, sdesc, refid, disp,
       leap, xmit_unix, offset}
    `offset` is (server transmit time - local capture time); on a healthy source it
    is ~ -(one-way delay), i.e. near zero. `-tt` gives a per-packet Unix epoch so
    the offset is immune to how long the capture window ran.
    """
    records = []
    blocks, cur = [], []
    for raw in output.splitlines():
        if _NTP_HDR_RE.match(raw):
            if cur:
                blocks.append(cur)
            cur = [raw]
        elif cur:
            cur.append(raw)
    if cur:
        blocks.append(cur)

    for block in blocks:
        head = _NTP_HDR_RE.match(block[0])
        try:
            rx_epoch = float(head.group(1))
        except (TypeError, ValueError):
            continue
        text = '\n'.join(block)
        sm = _NTP_SRC_RE.search(text)
        if not sm:
            continue  # not a decodable NTP packet (or truncated non-NTP)
        rec = {'rx_epoch': rx_epoch, 'src': sm.group(1), 'sport': int(sm.group(2)),
               'dst': sm.group(3), 'dport': int(sm.group(4)),
               'ver': int(sm.group(5)), 'mode': sm.group(6).strip(),
               'stratum': None, 'sdesc': '', 'refid': '', 'disp': 0.0,
               'leap': None, 'xmit_unix': None, 'offset': None}

        st = re.search(r'Stratum\s+(\d+)\s*\(([^)]*)\)', text)
        if st:
            rec['stratum'] = int(st.group(1))
            rec['sdesc'] = st.group(2).strip()
        rid = re.search(r'Reference-ID:\s*(\S.*?)\s*$', text, re.MULTILINE)
        if rid:
            rec['refid'] = rid.group(1).strip()
        dp = re.search(r'Root dispersion:\s*([\d.]+)', text)
        if dp:
            try:
                rec['disp'] = float(dp.group(1))
            except ValueError:
                pass
        li = re.search(r'Leap indicator:\s*[^(]*\((\d+)\)', text)
        if li:
            rec['leap'] = int(li.group(1))
        xm = re.search(r'(?<!- )Transmit Timestamp:\s*([\d.]+)', text)
        if xm:
            try:
                ntp_secs = float(xm.group(1))
                if ntp_secs > _NTP_UNIX_DELTA:  # sane, post-1970 timestamp
                    rec['xmit_unix'] = ntp_secs - _NTP_UNIX_DELTA
                    rec['offset'] = round(rec['xmit_unix'] - rx_epoch, 3)
            except ValueError:
                pass
        records.append(rec)
    return records


def _ntp_watch_load():
    try:
        with open(_NTP_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _ntp_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_NTP_WATCH_PATH), exist_ok=True)
        tmp = _NTP_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _NTP_WATCH_PATH)
    except OSError:
        pass


def do_ntp_baseline(action='get'):
    """Manage the learned NTP baseline (trusted time source(s) + their stratum).
    action='reset' re-learns the current segment's servers on the next scan (use
    after a legitimate NTP change)."""
    with _ntp_watch_lock:
        if action == 'reset':
            _ntp_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _ntp_watch_load()
        return {'success': True, 'baseline': {
            'servers': sorted((b.get('servers') or {}).keys()),
        }}


def _ntp_median(vals):
    s = sorted(vals)
    n = len(s)
    if not n:
        return 0.0
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def _ntp_analyze(records, seconds, baseline, learn=True, threshold=None):
    """Pure classifier over parsed NTP records. Returns the result payload (minus
    interface). Separated from capture so the self-test can drive it with synthetic
    packets. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))
    threshold = _NTP_OFFSET_THRESHOLD if threshold is None else threshold

    server_recs = [r for r in records if r['mode'] in _NTP_SERVER_MODES]
    client_recs = [r for r in records if r['mode'] == 'Client']
    control_recs = [r for r in records if r['mode'] in _NTP_CONTROL_MODES]

    # Aggregate time sources by address.
    servers = {}
    for r in server_recs:
        s = servers.setdefault(r['src'], {
            'src': r['src'], 'modes': set(), 'strata': set(), 'refids': set(),
            'offsets': [], 'disp_max': 0.0, 'leaps': set(), 'broadcast': False,
            'count': 0, 'kod': False, 'kod_codes': set()})
        s['count'] += 1
        s['modes'].add(r['mode'])
        if r['stratum'] is not None:
            s['strata'].add(r['stratum'])
        if r['refid']:
            s['refids'].add(r['refid'])
        if r['offset'] is not None:
            s['offsets'].append(r['offset'])
        s['disp_max'] = max(s['disp_max'], r['disp'])
        if r['leap'] is not None:
            s['leaps'].add(r['leap'])
        if r['mode'] == 'Broadcast':
            s['broadcast'] = True
        # A *server* reply at stratum 0 is by definition a Kiss-o'-Death.
        if r['stratum'] == 0:
            s['kod'] = True
            code = re.sub(r'[^A-Za-z]', '', r['refid']).upper()
            if code in _NTP_KOD_CODES:
                s['kod_codes'].add(code)

    known = dict(baseline.get('servers') or {})
    had_baseline = bool(known)

    # Learn-on-first-run: adopt the segment's current time sources as trusted.
    learned = False
    if learn and not had_baseline and servers:
        baseline['servers'] = {
            src: {'stratum': (min(s['strata']) if s['strata'] else None),
                  'refid': (sorted(s['refids'])[0] if s['refids'] else ''),
                  'broadcast': s['broadcast']}
            for src, s in servers.items()}
        learned = True
        known = dict(baseline['servers'])
        had_baseline = True

    PRIORITY = ['time-injection', 'rogue-server', 'kod', 'stratum-spoof',
                'broadcast', 'recon', 'anomaly', 'clean']
    verdict = 'clean'
    reasons = []

    def bump(v):
        nonlocal verdict
        if PRIORITY.index(v) < PRIORITY.index(verdict):
            verdict = v

    # Representative (median) offset per source.
    offsets_by_server = {src: round(_ntp_median(s['offsets']), 3)
                         for src, s in servers.items() if s['offsets']}

    # --- time-injection: someone is serving a shifted clock ---
    if len(offsets_by_server) >= 2:
        consensus = round(_ntp_median(list(offsets_by_server.values())), 3)
        offenders = {src: off for src, off in offsets_by_server.items()
                     if abs(off - consensus) > threshold}
        if offenders:
            for src, off in sorted(offenders.items()):
                bump('time-injection')
                reasons.append(
                    f"NTP server {src} is serving time {off:+.3f}s vs the segment "
                    f"consensus ({consensus:+.3f}s) — active time injection "
                    f"(poisons logs, TLS/Kerberos windows, MFA and audit records)")
        elif abs(consensus) > threshold:
            bump('time-injection')
            reasons.append(
                f"All {len(offsets_by_server)} NTP sources agree but disagree with "
                f"the local clock by {consensus:+.3f}s — the local clock is wrong or "
                f"every source is serving a shifted time")
    elif len(offsets_by_server) == 1:
        src, off = next(iter(offsets_by_server.items()))
        if abs(off) > threshold:
            bump('time-injection')
            reasons.append(
                f"NTP server {src}'s time is off by {off:+.3f}s from the local clock "
                f"— possible time injection (only one source seen, cannot cross-check)")

    # --- rogue-server: a source not in the trusted baseline ---
    if had_baseline:
        for src in sorted(servers):
            if src not in known:
                bump('rogue-server')
                reasons.append(
                    f"Unexpected NTP server {src} answering on the segment (not in "
                    f"the trusted baseline) — clients may silently sync to it")

    # --- kod: Kiss-o'-Death (stratum 0) reply ---
    for src in sorted(servers):
        s = servers[src]
        if s['kod']:
            bump('kod')
            codes = ', '.join(sorted(s['kod_codes'])) or 'stratum-0'
            reasons.append(
                f"Kiss-o'-Death from {src} ({codes}) — a rogue server uses KoD "
                f"RATE/DENY to make clients back off legitimate time (sync DoS)")

    # --- stratum-spoof: forged/lowered stratum to win client preference ---
    for src in sorted(servers):
        s = servers[src]
        good_strata = {n for n in s['strata'] if n and n < 16}
        if not good_strata:
            continue
        claimed = min(good_strata)
        base_stratum = (known.get(src) or {}).get('stratum')
        if src not in known:
            if claimed == 1:
                bump('stratum-spoof')
                reasons.append(
                    f"NTP server {src} claims Stratum 1 (primary/GPS reference) — "
                    f"verify it is a real reference clock; a forged low stratum makes "
                    f"clients prefer this source")
        elif base_stratum and claimed < base_stratum:
            bump('stratum-spoof')
            reasons.append(
                f"Known NTP server {src} now advertises Stratum {claimed} "
                f"(baseline {base_stratum}) — stratum manipulation to win preference")

    # --- broadcast: a mode-Broadcast time source ---
    for src in sorted(servers):
        s = servers[src]
        base_bcast = bool((known.get(src) or {}).get('broadcast'))
        if s['broadcast'] and not base_bcast:
            bump('broadcast')
            reasons.append(
                f"NTP broadcast/multicast server {src} on the segment — hosts in "
                f"broadcast client mode accept it blindly (classic rogue-time vector)")

    # --- recon: mode 6/7 control / monlist ---
    if control_recs:
        srcs = sorted({r['src'] for r in control_recs})
        bump('recon')
        reasons.append(
            f"NTP mode 6/7 (ntpq control / monlist) traffic from {', '.join(srcs)} "
            f"— reconnaissance or amplification abuse; disable 'monitor' and restrict "
            f"mode 6/7")

    # --- anomaly: unusable / forged time source ---
    for src in sorted(servers):
        s = servers[src]
        if s['disp_max'] > _NTP_DISP_ALARM:
            bump('anomaly')
            reasons.append(
                f"NTP server {src} root dispersion {s['disp_max']:.3f}s is "
                f"implausibly large — unreliable/forged time")
        if 3 in s['leaps']:
            bump('anomaly')
            reasons.append(
                f"NTP server {src} leap indicator = alarm (unsynchronized) — "
                f"serving unusable time")
        if src in s['refids']:
            bump('anomaly')
            reasons.append(
                f"NTP server {src} reference-ID equals its own address — reference "
                f"loop / forged sync chain")

    advisories = []
    if servers or control_recs:
        advisories.append(
            "Pin clients to known NTP servers (prefer authenticated NTS or symmetric "
            "keys), restrict inbound/outbound UDP 123 to expected hosts, and disable "
            "mode 6/7 (monlist) on servers. On precision-critical segments "
            "(lab/medical/finance/industrial) alert on any new time source or skew.")

    def _pub(s):
        off = offsets_by_server.get(s['src'])
        return {'src': s['src'], 'modes': sorted(s['modes']),
                'strata': sorted(s['strata']), 'refids': sorted(s['refids']),
                'offset': off, 'disp': round(s['disp_max'], 3), 'count': s['count'],
                'kod': s['kod'], 'broadcast': s['broadcast'],
                'baseline': s['src'] in known}

    if reasons:
        summary = reasons
    elif not (servers or control_recs):
        summary = ['No NTP traffic seen — segment quiet on UDP/123']
    else:
        summary = ['All time sources match the trusted baseline and agree on time']

    return {
        'success': True,
        'verdict': verdict,
        'reasons': summary,
        'learned': learned,
        'server_count': len(servers),
        'packet_count': len(records),
        'client_count': len(client_recs),
        'control_count': len(control_recs),
        'rate': round(len(records) / seconds, 2),
        'servers': [_pub(servers[s]) for s in sorted(servers)],
        'advisories': advisories,
    }


def _ntp_capture(interface, seconds):
    """Run one passive tcpdump window over NTP (UDP/123) and return (raw, error).
    Uses -tt (per-packet Unix epoch) so the served-vs-local time offset is exact."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface,
                '-nn', '-tt', '-v', '-s', '512', '-c', '20000', 'udp port 123'],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()
                                   or 'syntax error' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_ntp_watch(interface=None, seconds=15, learn=True, quick=False):
    """Passive NTP security scanner (detection-only). Captures NTP for a few
    seconds and classifies the segment's time sources: time-injection / rogue-server
    / kod / stratum-spoof / broadcast / recon / anomaly / clean. Learns the trusted
    time source(s) on first run."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 15, 5, 40)

    text, err = _ntp_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    records = _parse_ntp_capture(text)

    with _ntp_watch_lock:
        baseline = _ntp_watch_load()
        result = _ntp_analyze(records, seconds, baseline, learn=learn)
        if result.get('learned'):
            _ntp_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _ntp_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_NTP_EVENTS_CAP:]
            _ntp_watch_save(b)

    result['interface'] = iface
    result['seconds'] = seconds
    return result


def _ntp_selftest():
    """Self-test the NTP detectors with synthetic captures (no root, no live
    traffic). Feeds crafted `tcpdump -tt -v` text through the real parser +
    classifier, and — if Scapy is available — builds a real NTP server reply into a
    pcap and parses it back through tcpdump end to end. Returns a results dict."""
    scenarios = []
    BASE = 1780000000.0  # fixed capture epoch for deterministic offsets

    def block(src, mode='Server', stratum=2, refid='17.253.14.125', xmit_off=0.0,
              disp='0.020000', leap=0, ver=4, rx=BASE, dst='192.168.1.50'):
        """Craft one tcpdump -tt -v NTP packet block. xmit_off is how far the
        server's transmit time is from the capture time (the injected skew)."""
        ntp_secs = rx + xmit_off + _NTP_UNIX_DELTA
        sdesc = {0: 'unspecified', 1: 'primary reference'}.get(
            stratum, 'secondary reference')
        return "\n".join([
            f"{rx:.6f} IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], "
            f"proto UDP (17), length 76)",
            f"    {src}.123 > {dst}.123: NTPv{ver}, {mode}, length 48",
            f"\tLeap indicator:  ({leap}), Stratum {stratum} ({sdesc}), "
            f"poll 10 (1024s), precision -23",
            f"\tRoot Delay: 0.000000, Root dispersion: {disp}, "
            f"Reference-ID: {refid}",
            f"\t  Reference Timestamp:  {ntp_secs - 60:.9f} (2026-05-28T20:00:00Z)",
            f"\t  Originator Timestamp: {ntp_secs - 1:.9f} (2026-05-28T20:26:39Z)",
            f"\t  Receive Timestamp:    {ntp_secs:.9f} (2026-05-28T20:26:40Z)",
            f"\t  Transmit Timestamp:   {ntp_secs:.9f} (2026-05-28T20:26:40Z)",
            f"\t    Originator - Receive Timestamp:  +1.000000000",
            f"\t    Originator - Transmit Timestamp: +1.000000000",
        ])

    def run(name, text, seconds, baseline, expect):
        recs = _parse_ntp_capture(text)
        res = _ntp_analyze(recs, seconds, dict(baseline), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'records': len(recs), 'pass': ok})
        return res

    base = {'servers': {
        '10.0.0.1': {'stratum': 2, 'refid': '17.253.14.125', 'broadcast': False},
        '10.0.0.2': {'stratum': 2, 'refid': '132.163.96.1', 'broadcast': False},
        '10.0.0.3': {'stratum': 2, 'refid': '17.253.14.125', 'broadcast': False}}}

    # 1. clean: three known servers, all agreeing on time.
    run('clean',
        "\n".join([block('10.0.0.1'), block('10.0.0.2'), block('10.0.0.3')]),
        15, base, 'clean')

    # 2. time-injection: a known server now serves time an hour off; two others agree.
    run('time-injection',
        "\n".join([block('10.0.0.1'), block('10.0.0.2'),
                   block('10.0.0.3', xmit_off=3600.0)]),
        15, base, 'time-injection')

    # 3. rogue-server: an unknown server answers with correct time.
    run('rogue-server',
        "\n".join([block('10.0.0.1'), block('10.0.0.9')]),
        15, base, 'rogue-server')

    # 4. kod: a known server sends a stratum-0 Kiss-o'-Death (RATE).
    run('kod', block('10.0.0.1', stratum=0, refid='RATE'), 15, base, 'kod')

    # 5. stratum-spoof: a known secondary now claims Stratum 1 (primary/GPS).
    run('stratum-spoof', block('10.0.0.1', stratum=1, refid='GPS'), 15, base,
        'stratum-spoof')

    # 6. broadcast: a known server now broadcasts time (mode Broadcast).
    run('broadcast', block('10.0.0.1', mode='Broadcast', dst='224.0.1.1'), 15,
        base, 'broadcast')

    # 7. recon: an ntpq/monlist mode-6/7 (Reserved) query on 123.
    recon = ("1780000000.100000 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], "
             "proto UDP (17), length 40)\n"
             "    10.0.0.66.45000 > 10.0.0.1.123: NTPv2, Reserved, length 12\n"
             "\tLeap indicator:  (0)")
    run('recon', recon, 15, base, 'recon')

    # 8. anomaly: a known server with an implausible root dispersion.
    run('anomaly', block('10.0.0.1', disp='9.500000'), 15, base, 'anomaly')

    # 9. parse: a server block yields stratum, refid and a ~0 offset.
    pr = _parse_ntp_capture(block('10.0.0.1'))
    p_ok = (len(pr) == 1 and pr[0]['mode'] == 'Server' and pr[0]['stratum'] == 2
            and pr[0]['refid'] == '17.253.14.125' and pr[0]['offset'] is not None
            and abs(pr[0]['offset']) < 0.001)
    scenarios.append({'name': 'ntp-parse', 'expect': 'stratum2+refid+offset~0',
                      'got': str(pr[0] if pr else None)[:90], 'pass': p_ok})

    # Optional Scapy end-to-end: craft a real NTP reply -> pcap -> tcpdump -> parse.
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import struct
        import tempfile
        import time as _time
        from scapy.all import Ether, IP, UDP, Raw, wrpcap
        if _have('tcpdump'):
            now = _time.time()
            ntp = now + _NTP_UNIX_DELTA

            def _ts(u):
                s = int(u)
                return struct.pack('!II', s, int((u - s) * (1 << 32)))
            payload = (struct.pack('!BBBb', 0x24, 2, 10, -23)  # LI0 VN4 Mode4, str2
                       + struct.pack('!ii', 0, 1310)           # root delay/disp
                       + bytes((17, 253, 14, 125))             # refid
                       + _ts(ntp - 3) + _ts(ntp - 1) + _ts(ntp) + _ts(ntp))
            pkt = (Ether() / IP(src='192.0.2.123', dst='192.0.2.9')
                   / UDP(sport=123, dport=123) / Raw(payload))
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, [pkt])
            res = _run(['tcpdump', '-nn', '-tt', '-v', '-r', pcap_path], timeout=10)
            recs = _parse_ntp_capture(res['out'])
            srv = [r for r in recs if r['src'] == '192.0.2.123']
            ok = bool(srv) and srv[0]['stratum'] == 2 and srv[0]['offset'] is not None
            scapy_result = {'ran': True, 'servers': [r['src'] for r in recs],
                            'stratum': srv[0]['stratum'] if srv else None,
                            'offset': srv[0]['offset'] if srv else None, 'pass': ok,
                            'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and \
        (not scapy_result.get('ran') or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# ICMP Watch: passive ICMP-redirect / L3-injection scanner (detection-only)
# --------------------------------------------------------------------------
# The ICMP Redirect (type 5) is the classic Layer-3 gateway-injection MITM: any
# host on the segment can forge a Redirect that appears to come from the real
# gateway and tell a victim "for destination X, use next-hop Y instead" — steering
# that traffic through the attacker. It needs no ARP poisoning and no gateway
# compromise, and most hosts historically honoured redirects by default. Related
# L3 ICMP abuses live on the same wire: rogue ICMP Router Discovery (IRDP, type 9)
# advertisements that inject a default gateway, ICMP echo floods (ping-flood /
# smurf DoS), ICMP tunnelling / covert channels (oversized echo payloads used to
# exfiltrate data), and host reconnaissance (timestamp / address-mask / information
# requests that leak host facts). This scanner is PASSIVE: one short tcpdump window
# over IPv4 `icmp`, parsed and classified against the host's authoritative default
# gateway. It never sends an ICMP packet. (ICMPv6 Redirects, type 137, are covered
# by IPv6 First-Hop Watch.) What it flags:
#   * redirect    — an ICMP Redirect steering traffic to a next-hop that isn't a
#     known gateway (attacker insertion), or from a source that isn't the gateway
#     (spoofed) — the headline MITM.
#   * rogue-irdp  — an ICMP Router Advertisement (type 9) from a non-gateway host
#     (IRDP default-gateway injection).
#   * flood       — an ICMP storm (echo-flood / smurf, or a redirect flood) by rate.
#   * tunnel      — echo packets with oversized payloads (ICMP covert channel/exfil).
#   * recon       — ICMP timestamp / address-mask / information requests (host recon).
#   * anomaly     — a redirect/IRDP that matches known gateways (rare but benign),
#     or a deprecated type (source quench).
_ICMP_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'data', 'icmp_watch.json')
_icmp_watch_lock = threading.Lock()

# ICMP is intrinsically low-volume passively; a sustained rate at/above this is a
# flood (ping-flood / smurf / redirect storm).
_ICMP_FLOOD_RATE = 50.0
# A normal ping is ~64 bytes of ICMP. An echo whose ICMP length exceeds this is
# carrying a payload no ping needs — the ICMP-tunnel / exfil tell.
_ICMP_TUNNEL_LEN = 1024
_ICMP_EVENTS_CAP = 200

_ICMP_LINE_RE = re.compile(
    r'^\s*(\d+\.\d+\.\d+\.\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+):\s*ICMP\s+(.+)$')
_ICMP_REDIR_RE = re.compile(r'redirect\s+(\S+)\s+to\s+(?:host|net)\s+([\d.]+)')
_ICMP_LEN_RE = re.compile(r'length\s+(\d+)\s*$')


def _parse_icmp_capture(output):
    """Parse `tcpdump -nn -t -v icmp` text into ICMP events. Each ICMP message
    prints a `<src> > <dst>: ICMP <detail>, length N` line (a Redirect carries a
    quoted inner IP packet on following lines, which never matches this pattern
    because it has no `: ICMP`). Each event is a dict with a 'kind':
      redirect  : {src, dst, redirected, new_gw, length}
      echo      : {src, dst, length}
      irdp      : {src, dst}                 (router advertisement, type 9)
      irdp_sol  : {src, dst}                 (router solicitation, type 10)
      recon     : {src, dst, what}           (timestamp / address-mask / information)
      other     : {src, dst, what}           (unreachable / time-exceeded / quench …)
    """
    events = []
    for raw in output.splitlines():
        m = _ICMP_LINE_RE.match(raw)
        if not m:
            continue
        src, dst, rest = m.group(1), m.group(2), m.group(3).strip()
        low = rest.lower()
        lm = _ICMP_LEN_RE.search(rest)
        length = int(lm.group(1)) if lm else None

        if low.startswith('redirect'):
            rm = _ICMP_REDIR_RE.search(rest)
            events.append({'kind': 'redirect', 'src': src, 'dst': dst,
                           'redirected': rm.group(1) if rm else None,
                           'new_gw': rm.group(2) if rm else None, 'length': length})
        elif 'echo' in low:
            events.append({'kind': 'echo', 'src': src, 'dst': dst, 'length': length})
        elif 'router advertisement' in low:
            events.append({'kind': 'irdp', 'src': src, 'dst': dst})
        elif 'router solicitation' in low:
            events.append({'kind': 'irdp_sol', 'src': src, 'dst': dst})
        elif 'time stamp' in low or 'timestamp' in low:
            events.append({'kind': 'recon', 'src': src, 'dst': dst,
                           'what': 'timestamp'})
        elif 'address mask' in low:
            events.append({'kind': 'recon', 'src': src, 'dst': dst,
                           'what': 'address-mask'})
        elif 'information' in low:
            events.append({'kind': 'recon', 'src': src, 'dst': dst,
                           'what': 'information'})
        else:
            events.append({'kind': 'other', 'src': src, 'dst': dst,
                           'what': rest.split(',')[0][:40]})
    return events


def _icmp_watch_load():
    try:
        with open(_ICMP_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _icmp_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_ICMP_WATCH_PATH), exist_ok=True)
        tmp = _ICMP_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _ICMP_WATCH_PATH)
    except OSError:
        pass


def do_icmp_baseline(action='get'):
    """Manage the trusted gateway baseline the ICMP-redirect check compares against
    (the legitimate router(s) allowed to redirect / advertise). action='reset'
    re-seeds from the host's default gateway on the next scan."""
    with _icmp_watch_lock:
        if action == 'reset':
            _icmp_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _icmp_watch_load()
        return {'success': True, 'baseline': {
            'gateways': sorted(b.get('gateways') or []),
        }}


def _icmp_analyze(events, seconds, baseline, sys_gateway=None, learn=True):
    """Pure classifier over parsed ICMP events. The host's authoritative default
    gateway (sys_gateway) is always trusted, plus any learned gateways. Separated
    from capture so the self-test can drive it with synthetic packets. May
    mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))

    # Learn-on-first-run: seed the trusted-gateway baseline from the host's own
    # default gateway (authoritative — never from redirect sources, which could be
    # the attacker).
    learned = False
    if learn and not (baseline.get('gateways')) and sys_gateway:
        baseline['gateways'] = [sys_gateway]
        learned = True
    # The live default gateway is always trusted, on top of the stored baseline.
    known_gw = set(baseline.get('gateways') or [])
    if sys_gateway:
        known_gw.add(sys_gateway)
    had_gw = bool(known_gw)

    redirects = [e for e in events if e['kind'] == 'redirect']
    echoes = [e for e in events if e['kind'] == 'echo']
    irdp = [e for e in events if e['kind'] == 'irdp']
    recon = [e for e in events if e['kind'] == 'recon']
    rate = round(len(events) / seconds, 2)

    PRIORITY = ['redirect', 'rogue-irdp', 'flood', 'tunnel', 'recon', 'anomaly',
                'clean']
    verdict = 'clean'
    reasons = []

    def bump(v):
        nonlocal verdict
        if PRIORITY.index(v) < PRIORITY.index(verdict):
            verdict = v

    # --- redirect: the headline L3 MITM ---
    redir_rows = []
    malicious_redir = False
    for e in redirects:
        spoofed = had_gw and e['src'] not in known_gw
        # steering traffic to a next-hop that isn't a known router = attacker insert
        insert = bool(e['new_gw']) and (not had_gw or e['new_gw'] not in known_gw)
        mal = spoofed or insert or not had_gw
        malicious_redir = malicious_redir or mal
        redir_rows.append({'src': e['src'], 'dst': e['dst'],
                           'redirected': e['redirected'], 'new_gw': e['new_gw'],
                           'malicious': mal})
    if redirects:
        if malicious_redir:
            bump('redirect')
        elif verdict == 'clean':
            verdict = 'anomaly'
        for r in redir_rows:
            if r['malicious']:
                why = []
                if had_gw and r['src'] not in known_gw:
                    why.append(f"source {r['src']} is not the gateway (spoofed)")
                if r['new_gw'] and (not had_gw or r['new_gw'] not in known_gw):
                    why.append(f"steers traffic for {r['redirected'] or '?'} to "
                               f"non-gateway {r['new_gw']} (attacker next-hop)")
                if not had_gw:
                    why.append("no trusted gateway baseline — treat any redirect as "
                               "suspect")
                reasons.append(
                    f"ICMP Redirect from {r['src']} to {r['dst']}: "
                    f"{'; '.join(why)} — L3 man-in-the-middle (route injection)")
            else:
                reasons.append(
                    f"ICMP Redirect from gateway {r['src']} to {r['dst']} "
                    f"(→ {r['new_gw']}) — benign-looking but redirects are rare on "
                    f"switched networks; verify it is expected")

    # --- rogue-irdp: type-9 router advertisement injecting a gateway ---
    for e in irdp:
        if had_gw and e['src'] in known_gw:
            if verdict == 'clean':
                verdict = 'anomaly'
            reasons.append(f"ICMP Router Advertisement (IRDP) from gateway {e['src']} "
                           f"— unusual on modern networks; verify")
        else:
            bump('rogue-irdp')
            reasons.append(
                f"ICMP Router Advertisement (IRDP) from {e['src']} (not a known "
                f"gateway) — injects itself as a default gateway (IRDP spoofing MITM)")

    # --- flood: ICMP storm ---
    if rate >= _ICMP_FLOOD_RATE and len(events) >= _ICMP_FLOOD_RATE * seconds:
        bump('flood')
        talkers = {}
        for e in events:
            talkers[e['src']] = talkers.get(e['src'], 0) + 1
        top = max(talkers, key=talkers.get)
        reasons.append(
            f"ICMP flood: {len(events)} packets in {seconds}s ({rate}/s), mostly "
            f"echo — ping-flood / smurf DoS; top source {top} ({talkers[top]})")

    # --- tunnel: oversized echo payloads (covert channel / exfil) ---
    big = [e for e in echoes if (e['length'] or 0) > _ICMP_TUNNEL_LEN]
    if big:
        bump('tunnel')
        pairs = sorted({f"{e['src']}→{e['dst']}" for e in big})
        maxlen = max(e['length'] for e in big)
        reasons.append(
            f"{len(big)} ICMP echo packet(s) with oversized payloads (up to "
            f"{maxlen}B, normal ping ~64B) between {', '.join(pairs[:4])} — ICMP "
            f"tunnelling / data exfiltration over a covert channel")

    # --- recon: info-leak request types ---
    if recon:
        kinds = sorted({e['what'] for e in recon})
        srcs = sorted({e['src'] for e in recon})
        bump('recon')
        reasons.append(
            f"ICMP {', '.join(kinds)} request(s) from {', '.join(srcs[:4])} — host "
            f"reconnaissance / information leak; block these ICMP types at the edge")

    advisories = []
    if events:
        advisories.append(
            "Ignore ICMP redirects on hosts (net.ipv4.conf.all.accept_redirects=0, "
            "secure_redirects=0) and on the gateway "
            "(send_redirects=0); disable IRDP; rate-limit ICMP and block timestamp/"
            "address-mask/information types at the network edge.")

    counts = {'redirect': len(redirects), 'echo': len(echoes), 'irdp': len(irdp),
              'recon': len(recon),
              'other': len([e for e in events if e['kind'] == 'other'])}

    if reasons:
        summary = reasons
    elif not events:
        summary = ['No ICMP traffic seen — segment quiet']
    else:
        summary = ['ICMP traffic seen but no redirects / injections / floods — clean']

    return {
        'success': True,
        'verdict': verdict,
        'reasons': summary,
        'learned': learned,
        'icmp_count': len(events),
        'rate': rate,
        'counts': counts,
        'redirects': redir_rows,
        'gateways': sorted(known_gw),
        'advisories': advisories,
    }


def _icmp_capture(interface, seconds):
    """Run one passive tcpdump window over IPv4 ICMP and return (raw_text, error)."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface,
                '-nn', '-t', '-v', '-s', '128', '-c', '20000', 'icmp'],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()
                                   or 'syntax error' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_icmp_watch(interface=None, seconds=12, learn=True, quick=False):
    """Passive ICMP L3-security scanner (detection-only). Captures ICMP for a few
    seconds and classifies the segment: redirect / rogue-irdp / flood / tunnel /
    recon / anomaly / clean. Trusts the host's default gateway; learns it on first
    run."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 12, 4, 40)

    text, err = _icmp_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    events = _parse_icmp_capture(text)
    sys_gw = _default_gateway()

    with _icmp_watch_lock:
        baseline = _icmp_watch_load()
        result = _icmp_analyze(events, seconds, baseline, sys_gateway=sys_gw,
                               learn=learn)
        if result.get('learned'):
            _icmp_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _icmp_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_ICMP_EVENTS_CAP:]
            _icmp_watch_save(b)

    result['interface'] = iface
    result['seconds'] = seconds
    return result


def _icmp_selftest():
    """Self-test the ICMP detectors with synthetic captures (no root, no live
    traffic). Feeds crafted `tcpdump -t -v icmp` text through the real parser +
    classifier, and — if Scapy is available — builds a real ICMP Redirect into a
    pcap and parses it back through tcpdump end to end. Returns a results dict."""
    scenarios = []
    GW = '192.168.1.1'

    def redirect(src, dst='192.168.1.50', dest='8.8.8.8', newgw='192.168.1.66'):
        return (f"IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto ICMP "
                f"(1), length 56)\n"
                f"    {src} > {dst}: ICMP redirect {dest} to host {newgw}, length 36\n"
                f"\tIP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP "
                f"(6), length 40)\n"
                f"    {dst} > {dest}: tcp 0")

    def echo(src, dst, length=64):
        return (f"IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto ICMP "
                f"(1), length {length + 20})\n"
                f"    {src} > {dst}: ICMP echo request, id 1, seq 1, length {length}")

    def simple(src, dst, detail):
        return (f"IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto ICMP "
                f"(1), length 40)\n    {src} > {dst}: ICMP {detail}")

    def run(name, text, seconds, expect, gw=GW, baseline=None):
        events = _parse_icmp_capture(text)
        res = _icmp_analyze(events, seconds, dict(baseline or {}),
                            sys_gateway=gw, learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'events': len(events), 'pass': ok})
        return res

    base = {'gateways': ['192.168.1.1']}

    # 1. clean: ordinary echo request/reply between hosts, no redirects.
    run('clean', echo('192.168.1.50', '8.8.8.8') + "\n" +
        echo('8.8.8.8', '192.168.1.50'), 12, 'clean', baseline=base)

    # 2. redirect: a spoofed Redirect steering traffic to a non-gateway next-hop.
    run('redirect', redirect('192.168.1.66'), 12, 'redirect', baseline=base)

    # 3. rogue-irdp: an ICMP Router Advertisement from a non-gateway host.
    run('rogue-irdp',
        simple('192.168.1.66', '224.0.0.1',
               'router advertisement lifetime 1800 1: {192.168.1.66 128}, length 16'),
        12, 'rogue-irdp', baseline=base)

    # 4. flood: an ICMP echo storm.
    flood = "\n".join(echo(f"10.0.0.{i % 250}", '192.168.1.50')
                      for i in range(700))
    run('flood', flood, 5, 'flood', baseline=base)

    # 5. tunnel: echo packets with oversized payloads (covert channel).
    run('tunnel', echo('192.168.1.50', '10.0.0.9', length=1400) + "\n" +
        echo('192.168.1.50', '10.0.0.9', length=1400), 12, 'tunnel', baseline=base)

    # 6. recon: ICMP timestamp + address-mask requests.
    run('recon', simple('192.168.1.66', '192.168.1.50',
                        'time stamp query id 0 seq 0, length 20') + "\n" +
        simple('192.168.1.66', '192.168.1.51', 'address mask request, length 12'),
        12, 'recon', baseline=base)

    # 7. anomaly: a benign redirect from the real gateway to another known gateway.
    run('anomaly', redirect('192.168.1.1', newgw='192.168.1.1'), 12, 'anomaly',
        baseline=base)

    # 8. parse: a redirect yields src, redirected-dest and the new next-hop.
    pev = _parse_icmp_capture(redirect('192.168.1.66'))
    p_ok = (len(pev) == 1 and pev[0]['kind'] == 'redirect'
            and pev[0]['src'] == '192.168.1.66'
            and pev[0]['redirected'] == '8.8.8.8'
            and pev[0]['new_gw'] == '192.168.1.66')
    scenarios.append({'name': 'redirect-parse', 'expect': 'src+dest+newgw',
                      'got': str(pev[0] if pev else None)[:90], 'pass': p_ok})

    # Optional Scapy end-to-end: craft a real Redirect -> pcap -> tcpdump -> parse.
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import Ether, IP, ICMP, Raw, wrpcap
        if _have('tcpdump'):
            pkt = (Ether() / IP(src='192.168.1.1', dst='192.168.1.50')
                   / ICMP(type=5, code=1, gw='192.168.1.66')
                   / IP(src='192.168.1.50', dst='8.8.8.8') / Raw(b'\x00' * 8))
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, [pkt])
            res = _run(['tcpdump', '-nn', '-t', '-v', '-r', pcap_path], timeout=10)
            evs = _parse_icmp_capture(res['out'])
            reds = [e for e in evs if e['kind'] == 'redirect']
            ok = bool(reds) and reds[0]['new_gw'] == '192.168.1.66'
            scapy_result = {'ran': True, 'redirects': len(reds),
                            'new_gw': reds[0]['new_gw'] if reds else None,
                            'pass': ok, 'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and \
        (not scapy_result.get('ran') or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# SNMP Watch: passive cleartext-SNMP (v1/v2c) exposure scanner (detection-only)
# --------------------------------------------------------------------------
# SNMP v1 and v2c authenticate with a plaintext "community string" — effectively a
# device password carried in the clear on every request. Anyone passively sniffing
# the segment harvests it: the read community (often the default "public") exposes
# the full device config/MIB, and a write community (seen on a SetRequest) lets an
# attacker who captured it *reconfigure* the device — change routes, ACLs, SNMP
# itself, or bounce interfaces. v3 fixes this with the User Security Model
# (authentication + privacy/encryption). This scanner is PASSIVE: one short tcpdump
# window over UDP 161/162, parsed and classified. It never sends an SNMP request.
# What it flags:
#   * write-exposed — a SetRequest in v1/v2c: a *write* community is on the wire,
#     i.e. sniff it and you own the device.
#   * cleartext     — any v1/v2c traffic: the community string is exposed (worse
#     when it's a well-known default like "public"/"private").
#   * amplification — a GetBulk with a large max-repetitions: the SNMP reflection/
#     amplification DDoS vector.
#   * enumeration   — one host walking the MIB (many GetNext/GetBulk): SNMP recon.
#   * clean         — only SNMPv3 (or no SNMP) seen.
# A first scan learns the segment's SNMP agents + community strings into
# data/snmp_watch.json so later scans can highlight *new* exposure; the verdict
# always reflects the cleartext reality (v1/v2c is insecure regardless of baseline).
_SNMP_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'data', 'snmp_watch.json')
_snmp_watch_lock = threading.Lock()

# A GetBulk requesting at least this many repetitions is an amplification/DoS-grade
# request (a normal snmpbulkwalk uses ~10).
_SNMP_BULK_AMP = 50
# One source issuing at least this many GetNext/GetBulk in the window is walking the
# MIB (enumeration / recon).
_SNMP_WALK_COUNT = 20
_SNMP_EVENTS_CAP = 200

# Well-known / default community strings — trivially guessable even without a
# sniffer, and the first thing every scanner tries.
_SNMP_DEFAULT_COMMUNITIES = frozenset((
    'public', 'private', 'community', 'cisco', 'manager', 'admin', 'snmp',
    'default', 'write', 'read', 'monitor', 'netman', 'ilo', 'secret', 'password',
    'security', 'router', 'switch', 'test', 'guest', 'tivoli', 'openview', '0', ''))

_SNMP_LINE_RE = re.compile(
    r'^\s*(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+):\s*'
    r'\{\s*SNMP(v1|v2c|v3)\b(.*)$')
_SNMP_COMMUNITY_RE = re.compile(r'C="([^"]*)"')
_SNMP_PDU_RE = re.compile(
    r'\b(GetNextRequest|GetResponse|GetBulk|GetRequest|SetRequest|InformRequest|'
    r'V2Trap|Trap|Response)\b')
_SNMP_MAXREP_RE = re.compile(r'\bM=(\d+)')


def _parse_snmp_capture(output):
    """Parse `tcpdump -nn -t -v 'udp port 161 or 162'` text into SNMP events.

    tcpdump prints each SNMP message on one line as `<src>.<p> > <dst>.<p>:
    { SNMPvN [C="community"] { PDU(..) ... } }`. It *omits* `C="..."` when the
    community is the default "public", so a v1/v2c line with no community is treated
    as "public". v3 uses the USM (no cleartext community). Each event:
      {src, sport, dst, dport, version, community, pdu, max_rep}
    """
    events = []
    for raw in output.splitlines():
        m = _SNMP_LINE_RE.match(raw)
        if not m:
            continue
        src, sport, dst, dport = (m.group(1), int(m.group(2)),
                                  m.group(3), int(m.group(4)))
        version = m.group(5)   # 'v1' | 'v2c' | 'v3'
        rest = m.group(6)
        cm = _SNMP_COMMUNITY_RE.search(rest)
        if cm:
            community = cm.group(1)
        elif version in ('v1', 'v2c'):
            community = 'public'   # tcpdump hides the default community
        else:
            community = None       # v3 — USM, no cleartext community
        pm = _SNMP_PDU_RE.search(rest)
        pdu = pm.group(1) if pm else None
        rp = _SNMP_MAXREP_RE.search(rest)
        max_rep = int(rp.group(1)) if rp else None
        events.append({'src': src, 'sport': sport, 'dst': dst, 'dport': dport,
                       'version': version, 'community': community, 'pdu': pdu,
                       'max_rep': max_rep})
    return events


def _snmp_watch_load():
    try:
        with open(_SNMP_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _snmp_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_SNMP_WATCH_PATH), exist_ok=True)
        tmp = _SNMP_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _SNMP_WATCH_PATH)
    except OSError:
        pass


def do_snmp_baseline(action='get'):
    """Manage the learned SNMP baseline (known agents + community strings). Used to
    highlight *new* exposure on later scans. action='reset' re-learns the segment's
    current SNMP inventory on the next scan."""
    with _snmp_watch_lock:
        if action == 'reset':
            _snmp_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _snmp_watch_load()
        return {'success': True, 'baseline': {
            'agents': sorted((b.get('agents') or {}).keys()),
            'communities': sorted(b.get('communities') or []),
        }}


def _snmp_endpoints(e):
    """Return (agent_ip, manager_ip) for an SNMP event by port role: the agent is
    the SNMP-service side (161), or the device sending a trap (to 162)."""
    if e['dport'] == 161:
        return e['dst'], e['src']       # query -> agent
    if e['sport'] == 161:
        return e['src'], e['dst']       # response from agent
    if e['dport'] == 162:
        return e['src'], e['dst']       # trap/inform from device -> manager
    if e['sport'] == 162:
        return e['dst'], e['src']       # inform response
    return e['dst'], e['src']


def _snmp_analyze(events, seconds, baseline, learn=True):
    """Pure classifier over parsed SNMP events. Returns the result payload (minus
    interface). Separated from capture so the self-test can drive it with synthetic
    packets. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))

    agents = {}          # agent ip -> aggregate
    managers = set()
    communities = {}     # community -> aggregate (v1/v2c only)
    comm_agents = {}     # community -> set of agent ips that accept it
    walk_by_src = {}     # source -> count of GetNext/GetBulk
    bulk_max = 0
    insecure = False     # any v1/v2c seen
    write_seen = []      # (community, agent, manager)

    for e in events:
        agent_ip, mgr_ip = _snmp_endpoints(e)
        a = agents.setdefault(agent_ip, {
            'ip': agent_ip, 'versions': set(), 'communities': set(),
            'pdus': set(), 'writes': False})
        a['versions'].add(e['version'])
        if e['pdu']:
            a['pdus'].add(e['pdu'])
        managers.add(mgr_ip)

        if e['version'] in ('v1', 'v2c'):
            insecure = True
            comm = e['community'] if e['community'] is not None else 'public'
            a['communities'].add(comm)
            comm_agents.setdefault(comm, set()).add(agent_ip)
            c = communities.setdefault(comm, {
                'community': comm, 'versions': set(), 'count': 0, 'writes': False})
            c['versions'].add(e['version'])
            c['count'] += 1
            if e['pdu'] == 'SetRequest':
                a['writes'] = True
                c['writes'] = True
                write_seen.append((comm, agent_ip, mgr_ip))

        if e['pdu'] in ('GetNextRequest', 'GetBulk'):
            walk_by_src[e['src']] = walk_by_src.get(e['src'], 0) + 1
        if e['pdu'] == 'GetBulk' and e['max_rep']:
            bulk_max = max(bulk_max, e['max_rep'])

    known_agents = dict(baseline.get('agents') or {})
    known_comms = set(baseline.get('communities') or [])
    had_baseline = bool(known_agents or known_comms)

    learned = False
    if learn and not had_baseline and (agents or communities):
        baseline['agents'] = {ip: {'versions': sorted(a['versions']),
                                   'communities': sorted(a['communities'])}
                              for ip, a in agents.items()}
        baseline['communities'] = sorted(communities.keys())
        learned = True
        known_agents = dict(baseline['agents'])
        known_comms = set(baseline['communities'])

    PRIORITY = ['write-exposed', 'cleartext', 'amplification', 'enumeration',
                'anomaly', 'clean']
    verdict = 'clean'
    reasons = []

    def bump(v):
        nonlocal verdict
        if PRIORITY.index(v) < PRIORITY.index(verdict):
            verdict = v

    default_comms = sorted(c for c in communities
                           if c.lower() in _SNMP_DEFAULT_COMMUNITIES)
    custom_comms = sorted(c for c in communities
                          if c.lower() not in _SNMP_DEFAULT_COMMUNITIES)

    # --- write-exposed: a SetRequest in cleartext = write community on the wire ---
    if write_seen:
        bump('write-exposed')
        for comm, agent_ip, mgr_ip in write_seen[:6]:
            reasons.append(
                f"SNMP SetRequest (write) in cleartext from {mgr_ip} to agent "
                f"{agent_ip} with community \"{comm}\" — capturing that community "
                f"grants write access to reconfigure the device (takeover)")

    # --- cleartext: any v1/v2c community exposure ---
    if insecure:
        bump('cleartext')
        vers = sorted({v for a in agents.values() for v in a['versions']
                       if v in ('v1', 'v2c')})
        reasons.append(
            f"SNMP {'/'.join(vers)} in use — the community string is sent in "
            f"cleartext; anyone sniffing this segment captures it and gains that "
            f"level of device access. Migrate to SNMPv3 (authPriv).")
        if default_comms:
            reasons.append(
                f"Default/well-known community string(s) exposed: "
                f"{', '.join(chr(34) + c + chr(34) for c in default_comms)} — "
                f"trivially guessable even without a sniffer")
        if custom_comms:
            reasons.append(
                f"Custom community string(s) exposed in cleartext: "
                f"{', '.join(chr(34) + c + chr(34) for c in custom_comms)}")
        new_comms = [c for c in communities if c not in known_comms]
        if had_baseline and new_comms and not learned:
            reasons.append(
                f"NEW community string(s) since baseline: "
                f"{', '.join(chr(34) + c + chr(34) for c in sorted(new_comms))}")

    # --- community reuse: shared-secret blast radius ---
    # A cleartext community accepted by 2+ agents means one sniff owns them all;
    # if that community was ever seen writing, one capture is write access to N.
    community_reuse = []
    for comm in sorted(a for a, ags in comm_agents.items() if len(ags) >= 2):
        ags = sorted(comm_agents[comm])
        writes = communities[comm]['writes']
        community_reuse.append({'community': comm, 'agents': ags,
                                'writes': writes,
                                'severity': 'critical' if writes else 'high'})
        bump('write-exposed' if writes else 'cleartext')
        if writes:
            reasons.append(
                f"Community \"{comm}\" is reused across {len(ags)} agents "
                f"({', '.join(ags)}) AND was seen writing — one capture is write "
                f"access to all of them (blast radius)")
        else:
            reasons.append(
                f"Community \"{comm}\" is reused across {len(ags)} agents "
                f"({', '.join(ags)}) — sniff it once, gain that access on every one "
                f"(shared-secret blast radius)")

    # --- amplification: GetBulk with large max-repetitions ---
    if bulk_max >= _SNMP_BULK_AMP:
        bump('amplification')
        reasons.append(
            f"SNMP GetBulk with max-repetitions {bulk_max} — the SNMP reflection/"
            f"amplification DDoS vector; restrict/rate-limit SNMP and disable it on "
            f"internet-facing interfaces")

    # --- enumeration: a host walking the MIB ---
    walkers = sorted((s for s, n in walk_by_src.items() if n >= _SNMP_WALK_COUNT),
                     key=lambda s: -walk_by_src[s])
    if walkers:
        bump('enumeration')
        for s in walkers[:4]:
            reasons.append(
                f"{s} issued {walk_by_src[s]} GetNext/GetBulk requests — walking the "
                f"MIB (SNMP enumeration / reconnaissance)")

    advisories = []
    if agents or communities:
        advisories.append(
            "Migrate to SNMPv3 with authPriv (SHA + AES). If v1/v2c must remain, "
            "confine SNMP to a management VLAN with ACLs, use unique non-default "
            "read-only community strings, and never carry it over shared/user "
            "segments. Disable SNMP on devices that don't need it.")

    def _pub_agent(a):
        return {'ip': a['ip'], 'versions': sorted(a['versions']),
                'communities': sorted(a['communities']), 'writes': a['writes'],
                'pdus': sorted(a['pdus']),
                'secure': a['versions'] == {'v3'},
                'baseline': a['ip'] in known_agents}

    def _pub_comm(c):
        return {'community': c['community'], 'versions': sorted(c['versions']),
                'count': c['count'], 'writes': c['writes'],
                'default': c['community'].lower() in _SNMP_DEFAULT_COMMUNITIES,
                'baseline': c['community'] in known_comms}

    if reasons:
        summary = reasons
    elif not events:
        summary = ['No SNMP traffic seen — segment quiet on UDP 161/162']
    else:
        summary = ['Only SNMPv3 seen — SNMP traffic is authenticated/encrypted (secure)']

    return {
        'success': True,
        'verdict': verdict,
        'reasons': summary,
        'learned': learned,
        'snmp_count': len(events),
        'rate': round(len(events) / seconds, 2),
        'insecure': insecure,
        'agents': [_pub_agent(agents[a]) for a in sorted(agents)],
        'communities': [_pub_comm(communities[c]) for c in sorted(communities)],
        'community_reuse': community_reuse,
        'managers': sorted(managers),
        'advisories': advisories,
    }


def _snmp_capture(interface, seconds):
    """Run one passive tcpdump window over SNMP (UDP 161/162), return (raw, error)."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface,
                '-nn', '-t', '-v', '-s', '512', '-c', '20000',
                'udp and (port 161 or port 162)'],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()
                                   or 'syntax error' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_snmp_watch(interface=None, seconds=12, learn=True, quick=False):
    """Passive SNMP exposure scanner (detection-only). Captures SNMP for a few
    seconds and classifies the segment: write-exposed / cleartext / amplification /
    enumeration / clean. Learns the segment's SNMP agents + community strings on
    first run."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 12, 4, 40)

    text, err = _snmp_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    events = _parse_snmp_capture(text)

    with _snmp_watch_lock:
        baseline = _snmp_watch_load()
        result = _snmp_analyze(events, seconds, baseline, learn=learn)
        if result.get('learned'):
            _snmp_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _snmp_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_SNMP_EVENTS_CAP:]
            _snmp_watch_save(b)

    result['interface'] = iface
    result['seconds'] = seconds
    return result


def _snmp_selftest():
    """Self-test the SNMP detectors with synthetic captures (no root, no live
    traffic). Feeds crafted `tcpdump -t -v` text through the real parser +
    classifier, and — if Scapy is available — builds real SNMP v2c messages into a
    pcap and parses them back through tcpdump end to end. Returns a results dict."""
    scenarios = []

    def line(src, dst, sport, dport, ver, pdu, community=None, maxrep=None):
        cs = f' C="{community}"' if community is not None else ''
        body = f'{pdu}(25) R=0'
        if maxrep is not None:
            body = f'GetBulk(22) R=0  N=0 M={maxrep}'
        return (f"    {src}.{sport} > {dst}.{dport}:  {{ SNMP{ver}{cs} "
                f"{{ {body}  .1.3.6.1.2.1.1.5.0 }} }}")

    def run(name, text, seconds, baseline, expect):
        events = _parse_snmp_capture(text)
        res = _snmp_analyze(events, seconds, dict(baseline or {}),
                            learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'events': len(events), 'pass': ok})
        return res

    base = {'agents': {'192.168.1.1': {'versions': ['v2c'],
                                       'communities': ['public']}},
            'communities': ['public']}

    # 1. clean: only SNMPv3 (authenticated/encrypted).
    run('clean', line('192.168.1.50', '192.168.1.1', 42000, 161, 'v3',
                      'GetRequest'), 12, base, 'clean')

    # 2. cleartext: a v2c GetRequest with the hidden default "public" community.
    run('cleartext', line('192.168.1.50', '192.168.1.1', 42000, 161, 'v2c',
                          'GetRequest'), 12, base, 'cleartext')

    # 3. write-exposed: a v2c SetRequest exposes a write community.
    run('write-exposed', line('192.168.1.50', '192.168.1.1', 42000, 161, 'v2c',
                              'SetRequest', community='private'), 12, base,
        'write-exposed')

    # 4. amplification: a GetBulk with a large max-repetitions (v3, so not cleartext).
    run('amplification', line('10.0.0.9', '192.168.1.1', 42000, 161, 'v3',
                              'GetBulk', maxrep=200), 12, base, 'amplification')

    # 5. enumeration: one host walking the MIB (v3 GetNext flood).
    walk = "\n".join(line('10.0.0.9', '192.168.1.1', 42000 + i, 161, 'v3',
                          'GetNextRequest') for i in range(25))
    run('enumeration', walk, 12, base, 'enumeration')

    # 5b. community reuse: one community ("netops") on two different agents.
    reuse_text = "\n".join([
        line('192.168.1.50', '192.168.1.1', 42000, 161, 'v2c', 'GetRequest',
             community='netops'),
        line('192.168.1.50', '192.168.1.2', 42001, 161, 'v2c', 'GetRequest',
             community='netops')])
    rr = run('community-reuse', reuse_text, 12,
             {'agents': {}, 'communities': ['netops']}, 'cleartext')
    reuse_ok = (any(r['community'] == 'netops' and r['agents'] == ['192.168.1.1', '192.168.1.2']
                    and r['severity'] == 'high' for r in rr.get('community_reuse', [])))
    scenarios.append({'name': 'community-reuse', 'expect': 'netops on 2 agents (high)',
                      'got': str(rr.get('community_reuse')), 'pass': reuse_ok})
    # 5c. reuse + write => critical blast radius.
    reuse_w = "\n".join([
        line('192.168.1.50', '192.168.1.1', 42000, 161, 'v2c', 'SetRequest',
             community='rwsecret'),
        line('192.168.1.50', '192.168.1.2', 42001, 161, 'v2c', 'GetRequest',
             community='rwsecret')])
    rw = _snmp_analyze(_parse_snmp_capture(reuse_w), 12,
                       {'agents': {}, 'communities': ['rwsecret']}, learn=False)
    rw_ok = any(r['community'] == 'rwsecret' and r['severity'] == 'critical'
                for r in rw.get('community_reuse', []))
    scenarios.append({'name': 'community-reuse-write', 'expect': 'rwsecret critical',
                      'got': str(rw.get('community_reuse')), 'pass': rw_ok})

    # 6. parse: hidden-public + explicit community + v3 (no community).
    pev = _parse_snmp_capture(
        line('192.168.1.50', '192.168.1.1', 42000, 161, 'v2c', 'GetRequest') + "\n" +
        line('192.168.1.50', '192.168.1.1', 42001, 161, 'v2c', 'GetRequest',
             community='secret') + "\n" +
        line('192.168.1.50', '192.168.1.1', 42002, 161, 'v3', 'GetRequest'))
    p_ok = (len(pev) == 3 and pev[0]['community'] == 'public'
            and pev[1]['community'] == 'secret' and pev[2]['community'] is None
            and pev[2]['version'] == 'v3')
    scenarios.append({'name': 'snmp-parse', 'expect': 'public/secret/v3-none',
                      'got': str([e['community'] for e in pev]), 'pass': p_ok})

    # Optional Scapy end-to-end: craft real SNMP v2c -> pcap -> tcpdump -> parse.
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import Ether, IP, UDP, wrpcap
        from scapy.layers.snmp import SNMP, SNMPget, SNMPset, SNMPvarbind
        from scapy.asn1.asn1 import ASN1_OID, ASN1_STRING
        if _have('tcpdump'):
            oid = ASN1_OID('1.3.6.1.2.1.1.5.0')
            pkts = [
                Ether() / IP(src='192.168.1.50', dst='192.168.1.1')
                / UDP(sport=42000, dport=161)
                / SNMP(version=1, community='public',
                       PDU=SNMPget(varbindlist=[SNMPvarbind(oid=oid)])),
                Ether() / IP(src='192.168.1.50', dst='192.168.1.1')
                / UDP(sport=42001, dport=161)
                / SNMP(version=1, community='rwsecret',
                       PDU=SNMPset(varbindlist=[SNMPvarbind(
                           oid=oid, value=ASN1_STRING('x'))])),
            ]
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, pkts)
            res = _run(['tcpdump', '-nn', '-t', '-v', '-r', pcap_path], timeout=10)
            evs = _parse_snmp_capture(res['out'])
            comms = {e['community'] for e in evs}
            wrote = any(e['pdu'] == 'SetRequest' for e in evs)
            ok = ('public' in comms and 'rwsecret' in comms and wrote)
            scapy_result = {'ran': True, 'events': len(evs),
                            'communities': sorted(c for c in comms if c),
                            'write': wrote, 'pass': ok,
                            'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and \
        (not scapy_result.get('ran') or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# Cert Watch: TLS / certificate hygiene checker (active grade + passive discovery)
# --------------------------------------------------------------------------
# Internal networks are full of TLS services — router/switch admin UIs, NAS boxes,
# hypervisors, printers, IoT — with certificates nobody audits: long expired,
# self-signed, hostname-mismatched, or signed with weak crypto. Unlike the passive
# "Watch" scanners, a certificate checker is inherently ACTIVE: it must complete a
# TLS handshake to read the cert, and TLS 1.3 encrypts the Certificate message, so
# passive sniffing can't read modern certs at all. So this tool has two phases:
#   * passive discovery — one short tcpdump window over TLS ClientHellos to find the
#     TLS servers on the segment (server IP:port + SNI), so you don't have to type
#     them. Best-effort; TLS 1.3 SNI is still in the clear in the ClientHello.
#   * active grading — connect to each target, fetch the presented cert even when it
#     fails validation (unverified fallback), and grade it for the full range of
#     TLS/cert hygiene problems.
# Verdicts (worst first): expired / not-yet-valid / self-signed / untrusted /
# hostname-mismatch / weak-crypto / deprecated-tls / expiring / valid. A learned
# fingerprint baseline flags a certificate that *changed* between scans (rotation or
# a possible MITM). Targets are explicit (typed or discovered on the local segment)
# — this is device-hygiene auditing of your own network, not a scanner.
_CERT_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'data', 'cert_watch.json')
_cert_watch_lock = threading.Lock()

_TLS_EXPIRING_DAYS = 21          # a valid cert with fewer days left is "expiring"
_TLS_WEAK_RSA_BITS = 2048        # RSA below this is weak
_TLS_CONNECT_TIMEOUT = 6         # per-target TLS connect/handshake timeout (s)
_TLS_MAX_TARGETS = 32            # cap graded targets per run (this is not a scanner)
_TLS_POOL = 8                    # parallel handshakes
_TLS_DEPRECATED_PROTOS = ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1')
_TLS_WEAK_CIPHER_RE = re.compile(r'RC4|RC2|(?<![A-Z0-9])DES|3DES|NULL|EXPORT|MD5|'
                                 r'ANON|_anon', re.IGNORECASE)
# Severity order used for the per-target verdict and the overall roll-up.
_TLS_PRIORITY = ['expired', 'not-yet-valid', 'self-signed', 'untrusted',
                 'hostname-mismatch', 'weak-crypto', 'deprecated-tls', 'expiring',
                 'valid']


def _tls_is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _tls_parse_targets(text):
    """Parse a free-form string of `host[:port]` targets (comma / space / newline
    separated) into a de-duplicated list of (host, port). Default port 443. Strips
    an accidental scheme/path (https://host/…)."""
    out, seen = [], set()
    for tok in re.split(r'[\s,]+', (text or '').strip()):
        if not tok:
            continue
        tok = re.sub(r'^[a-zA-Z]+://', '', tok)   # drop scheme
        tok = tok.split('/')[0]                    # drop path
        host, port = tok, 443
        # [v6]:port or host:port (but not bare IPv6 with colons)
        m = re.match(r'^\[(.+)\]:(\d+)$', tok)
        if m:
            host, port = m.group(1), int(m.group(2))
        elif tok.count(':') == 1:
            h, p = tok.rsplit(':', 1)
            if p.isdigit():
                host, port = h, int(p)
        if not host or not (1 <= port <= 65535):
            continue
        key = (host.lower(), port)
        if key not in seen:
            seen.add(key)
            out.append((host, port))
    return out


def _cert_watch_load():
    try:
        with open(_CERT_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _cert_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_CERT_WATCH_PATH), exist_ok=True)
        tmp = _CERT_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _CERT_WATCH_PATH)
    except OSError:
        pass


def do_cert_baseline(action='get'):
    """Manage the learned certificate-fingerprint baseline (per host:port). Used to
    flag a cert that *changed* between scans. action='reset' forgets it."""
    with _cert_watch_lock:
        if action == 'reset':
            _cert_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _cert_watch_load()
        return {'success': True, 'baseline': {
            'certs': sorted((b.get('certs') or {}).keys()),
        }}


def _tls_name_cn(name):
    """Best-effort Common Name from an x509 Name."""
    try:
        from cryptography.x509.oid import NameOID
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else name.rfc4514_string()
    except Exception:
        try:
            return name.rfc4514_string()
        except Exception:
            return ''


def _tls_get_san(cert):
    """Return (dns_names, ip_strings) from the SubjectAltName extension."""
    try:
        from cryptography import x509
        ext = cert.extensions.get_extension_for_class(x509.SubjectAltName).value
        dns = ext.get_values_for_type(x509.DNSName)
        ips = [str(ip) for ip in ext.get_values_for_type(x509.IPAddress)]
        return dns, ips
    except Exception:
        return [], []


def _tls_name_matches(name, dns_names, ip_names, cn):
    """Does `name` (the host/SNI we connected to) match the certificate's names?
    Wildcard-aware for DNS; exact for IPs; falls back to CN when no SAN."""
    if not name:
        return True
    candidates = list(dns_names)
    if not candidates and cn:
        candidates = [cn]
    if _tls_is_ip(name):
        try:
            target = ipaddress.ip_address(name)
        except ValueError:
            target = None
        for ip in ip_names:
            try:
                if target is not None and ipaddress.ip_address(ip) == target:
                    return True
            except ValueError:
                continue
        # a few certs put the IP in a DNS SAN / CN as a literal
        return name in candidates
    name = name.lower().rstrip('.')
    for c in candidates:
        c = (c or '').lower().rstrip('.')
        if c == name:
            return True
        if c.startswith('*.'):
            # wildcard matches exactly one left-most label
            if name.split('.', 1)[1:] == [c[2:]] and '.' in name:
                return True
    return False


def _tls_key_desc(cert):
    """Return (description, weak_bool) for the certificate's public key."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            return f'RSA-{pub.key_size}', pub.key_size < _TLS_WEAK_RSA_BITS
        if isinstance(pub, dsa.DSAPublicKey):
            return f'DSA-{pub.key_size}', True          # DSA is deprecated
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return f'EC-{pub.curve.name}', pub.key_size < 256
        return type(pub).__name__.replace('PublicKey', ''), False
    except Exception:
        return '?', False


def _tls_classify(der, check_name, trusted, verify_reason, proto, cipher, now):
    """Pure classifier over one presented certificate + connection facts. Returns a
    per-target result dict. Separated from the network I/O so the self-test can drive
    it with synthetic certs. `check_name` is the host/SNI we connected to."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    cert = x509.load_der_x509_certificate(der)

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    subject_cn = _tls_name_cn(cert.subject)
    issuer_cn = _tls_name_cn(cert.issuer)
    san_dns, san_ip = _tls_get_san(cert)
    self_signed = cert.subject == cert.issuer
    key_desc, weak_key = _tls_key_desc(cert)
    try:
        sig = (cert.signature_hash_algorithm.name
               if cert.signature_hash_algorithm else 'none')
    except Exception:
        sig = 'unknown'
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    expired = now > not_after
    not_yet = now < not_before
    days_left = (not_after - now).days
    hostname_ok = _tls_name_matches(check_name, san_dns, san_ip, subject_cn)
    weak_sig = sig in ('md5', 'sha1')
    deprecated = proto in _TLS_DEPRECATED_PROTOS
    weak_cipher = bool(cipher and _TLS_WEAK_CIPHER_RE.search(cipher))

    names = san_dns + san_ip or ([subject_cn] if subject_cn else [])
    findings = []   # (verdict_key, reason)
    if expired:
        findings.append(('expired', f"certificate EXPIRED {(now - not_after).days} "
                         f"days ago (notAfter {not_after:%Y-%m-%d})"))
    if not_yet:
        findings.append(('not-yet-valid', f"certificate not valid until "
                         f"{not_before:%Y-%m-%d} — clock skew or premature deploy"))
    if not trusted:
        if self_signed:
            findings.append(('self-signed', "self-signed certificate "
                             "(issuer == subject; not anchored to any CA)"))
        else:
            findings.append(('untrusted', "not trusted by the system CA store"
                             + (f": {verify_reason}" if verify_reason else
                                " (incomplete chain or private CA)")))
    if not hostname_ok:
        shown = ', '.join(names[:4]) or '(no names)'
        findings.append(('hostname-mismatch', f"hostname mismatch: certificate is "
                         f"for {shown}, you connected to {check_name}"))
    if weak_sig:
        findings.append(('weak-crypto', f"weak signature algorithm {sig.upper()}"))
    if weak_key:
        findings.append(('weak-crypto', f"weak key {key_desc}"))
    if weak_cipher:
        findings.append(('weak-crypto', f"weak cipher {cipher}"))
    if deprecated:
        findings.append(('deprecated-tls', f"deprecated protocol {proto} negotiated"))
    if not expired and days_left <= _TLS_EXPIRING_DAYS:
        findings.append(('expiring', f"expires in {days_left} days "
                         f"(notAfter {not_after:%Y-%m-%d})"))

    if findings:
        verdict = min((k for k, _ in findings), key=_TLS_PRIORITY.index)
        reasons = [r for _, r in findings]
    else:
        verdict = 'valid'
        reasons = [f"valid — trusted chain, hostname matches, {days_left} days left"]

    return {
        'verdict': verdict, 'reasons': reasons,
        'subject': subject_cn, 'issuer': issuer_cn,
        'san': san_dns + san_ip, 'self_signed': self_signed, 'trusted': trusted,
        'not_before': not_before.strftime('%Y-%m-%d'),
        'not_after': not_after.strftime('%Y-%m-%d'),
        'days_left': days_left, 'sig_alg': sig, 'key': key_desc,
        'proto': proto, 'cipher': cipher, 'fingerprint': fingerprint,
    }


def _tls_grade_connection(host, port, sni, timeout):
    """Do the TLS handshake(s) for one target and return the connection facts:
    reachability, chain-trust result, and the presented cert (DER) + negotiated
    protocol/cipher — fetched even when the cert fails validation."""
    res = {'reachable': False, 'error': None, 'trusted': False,
           'verify_reason': None, 'der': None, 'proto': None, 'cipher': None}
    server_name = sni or host
    if _tls_is_ip(server_name):
        server_name = None   # SNI must not be an IP literal

    # 1. Verifying connection (chain only; hostname is checked separately). On a
    #    healthy cert this is the single round trip and also yields the cert.
    vctx = ssl.create_default_context()
    vctx.check_hostname = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with vctx.wrap_socket(raw, server_hostname=server_name) as ss:
                res.update(reachable=True, trusted=True,
                           der=ss.getpeercert(binary_form=True),
                           proto=ss.version(),
                           cipher=ss.cipher()[0] if ss.cipher() else None)
                return res
    except ssl.SSLCertVerificationError as e:
        res['reachable'] = True
        res['verify_reason'] = getattr(e, 'verify_message', None) or 'verify failed'
    except ssl.SSLError as e:
        res['reachable'] = True
        res['error'] = f'TLS handshake error: {str(e)[:120]}'
    except (socket.timeout, TimeoutError):
        res['error'] = 'connection timed out'
        return res
    except (ConnectionRefusedError, OSError) as e:
        res['error'] = f'{type(e).__name__}: {str(e)[:80]}'
        return res

    # 2. Cert failed validation (or handshake hiccup) — fetch it unverified so we can
    #    say *why* it's invalid.
    uctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    uctx.check_hostname = False
    uctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with uctx.wrap_socket(raw, server_hostname=server_name) as ss:
                res.update(reachable=True, der=ss.getpeercert(binary_form=True),
                           proto=ss.version(),
                           cipher=ss.cipher()[0] if ss.cipher() else None)
    except Exception as e:
        if not res.get('error'):
            res['error'] = f'{type(e).__name__}: {str(e)[:80]}'
    return res


def _tls_check_target(host, port, sni, now):
    """Grade one target end to end: connect, then classify the presented cert."""
    base = {'target': f'{host}:{port}', 'host': host, 'port': port, 'sni': sni}
    try:
        conn = _tls_grade_connection(host, port, sni, _TLS_CONNECT_TIMEOUT)
    except Exception as e:                       # never let one target crash the run
        return {**base, 'verdict': 'unreachable', 'status': 'unreachable',
                'reasons': [f'{type(e).__name__}: {str(e)[:100]}']}
    if not conn.get('der'):
        return {**base, 'verdict': 'unreachable', 'status': 'unreachable',
                'reasons': [conn.get('error') or 'no TLS handshake / no certificate']}
    try:
        graded = _tls_classify(conn['der'], sni or host, conn['trusted'],
                               conn.get('verify_reason'), conn.get('proto'),
                               conn.get('cipher'), now)
    except Exception as e:
        return {**base, 'verdict': 'unreachable', 'status': 'unreachable',
                'reasons': [f'certificate parse error: {str(e)[:100]}']}
    return {**base, 'status': 'graded', **graded}


def _tls_discover(interface, seconds):
    """Passive discovery: one tcpdump window capturing TLS ClientHellos, parsed for
    the server IP:port + SNI. Returns (targets, error). Best-effort — needs Scapy's
    TLS layer for SNI; without it, falls back to server IP:port from tcpdump text."""
    if not _have('tcpdump'):
        return [], 'tcpdump is not installed. Click Install to add it.'
    # BPF: a TCP segment whose first payload byte is 0x16 (TLS handshake record) and
    # whose handshake message type (5 bytes in) is 0x01 (ClientHello).
    bpf = ('tcp and (tcp[((tcp[12:1]&0xf0)>>2)]=0x16) and '
           '(tcp[((tcp[12:1]&0xf0)>>2)+5]=0x01)')
    pcap_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
            pcap_path = tf.name
        res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface, '-nn',
                    '-s', '0', '-c', '2000', '-w', pcap_path, bpf],
                   timeout=seconds + 8)
        err = res.get('err', '')
        if (not os.path.getsize(pcap_path)) and err and (
                'permission' in err.lower() or "couldn't" in err.lower()
                or 'no such device' in err.lower() or 'syntax' in err.lower()):
            return [], err.strip()[:200]
        found = {}
        try:
            from scapy.all import rdpcap, IP, IPv6, TCP
            from scapy.layers.tls.extensions import TLS_Ext_ServerName
            for p in rdpcap(pcap_path):
                if TCP not in p:
                    continue
                ip = p[IP].dst if IP in p else (p[IPv6].dst if IPv6 in p else None)
                if not ip:
                    continue
                key = (ip, int(p[TCP].dport))
                sni = found.get(key)
                if TLS_Ext_ServerName in p:
                    for sn in p[TLS_Ext_ServerName].servernames:
                        try:
                            sni = sn.servername.decode('idna', 'ignore') or sni
                        except Exception:
                            sni = sn.servername.decode('latin-1', 'ignore') or sni
                found[key] = sni
        except Exception:
            # Scapy TLS layer unavailable — fall back to server IP:port from text.
            res2 = _run(['tcpdump', '-nn', '-r', pcap_path], timeout=15)
            for line in res2.get('out', '').splitlines():
                m = re.search(r'>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+):', line)
                if m:
                    found[(m.group(1), int(m.group(2)))] = None
        targets = [{'host': ip, 'port': port, 'sni': sni}
                   for (ip, port), sni in sorted(found.items())]
        return targets, None
    finally:
        if pcap_path:
            try:
                os.remove(pcap_path)
            except OSError:
                pass


def do_cert_watch(targets='', interface=None, seconds=8, discover=False, learn=True):
    """Active TLS/certificate hygiene checker with optional passive discovery.
    Grades each target host:port (typed and/or discovered on the segment) for
    expired / not-yet-valid / self-signed / untrusted / hostname-mismatch /
    weak-crypto / deprecated-tls / expiring certs, and flags a cert that changed
    since the learned fingerprint baseline."""
    try:
        import cryptography  # noqa: F401
    except Exception:
        return {'success': False,
                'error': 'the Python "cryptography" package is required for TLS '
                         'grading (pip install cryptography)'}
    now = datetime.now(timezone.utc)

    # Merge explicit targets with passively-discovered ones (SNI carried along).
    order, sni_of = [], {}
    for host, port in _tls_parse_targets(targets):
        k = (host, port)
        if k not in sni_of:
            sni_of[k] = None
            order.append(k)

    discovered_n, disc_err = 0, None
    if discover:
        iface = interface if _valid_iface(interface or '') else _capture_iface()
        if not iface or iface not in _list_iface_names(include_virtual=True):
            disc_err = 'no interface to capture on for discovery'
        else:
            found, disc_err = _tls_discover(iface, _clamp_int(seconds, 8, 4, 30))
            discovered_n = len(found or [])
            for d in (found or []):
                k = (d['host'], d['port'])
                if k not in sni_of:
                    sni_of[k] = d.get('sni')
                    order.append(k)
                elif d.get('sni') and not sni_of[k]:
                    sni_of[k] = d['sni']

    order = order[:_TLS_MAX_TARGETS]
    if not order:
        return {'success': True, 'verdict': 'clean', 'targets': [], 'counts': {},
                'reasons': [disc_err or 'No TLS targets given or discovered'],
                'discovered': discovered_n, 'discover_error': disc_err,
                'advisories': [], 'interface': interface}

    from concurrent.futures import ThreadPoolExecutor, as_completed
    results = []
    with ThreadPoolExecutor(max_workers=min(_TLS_POOL, len(order))) as ex:
        futs = [ex.submit(_tls_check_target, h, p, sni_of[(h, p)], now)
                for (h, p) in order]
        for fut in as_completed(futs):
            results.append(fut.result())

    # Fingerprint baseline: flag changed certs, then learn.
    with _cert_watch_lock:
        base = _cert_watch_load()
        certs = base.get('certs') or {}
        for r in results:
            fp = r.get('fingerprint')
            if not fp:
                continue
            prev = certs.get(r['target'])
            if prev and prev != fp:
                r['cert_changed'] = True
                r['reasons'] = ['certificate CHANGED since baseline '
                                '(rotation or possible MITM)'] + r.get('reasons', [])
            if learn:
                certs[r['target']] = fp
        if learn:
            base['certs'] = certs
            _cert_watch_save(base)

    # Sort worst-first; roll up an overall verdict from graded targets.
    def sev(r):
        v = r.get('verdict', 'valid')
        return _TLS_PRIORITY.index(v) if v in _TLS_PRIORITY else len(_TLS_PRIORITY) + 1
    results.sort(key=sev)
    counts = {}
    for r in results:
        counts[r['verdict']] = counts.get(r['verdict'], 0) + 1
    graded = [r for r in results if r.get('status') == 'graded']
    bad = [r for r in graded if r['verdict'] != 'valid']
    if not graded:
        overall = 'unreachable'
    elif not bad:
        overall = 'clean'
    else:
        overall = bad[0]['verdict']

    n_bad = len(bad)
    summary = ([f"{n_bad} of {len(graded)} TLS service(s) have certificate/TLS "
                f"problems — worst: {overall}"] if bad else
               ([f"All {len(graded)} TLS service(s) present valid, trusted, "
                 f"in-date certificates"] if graded else
                ['No TLS service could be graded']))
    if counts.get('unreachable'):
        summary.append(f"{counts['unreachable']} target(s) unreachable / not TLS")

    advisories = []
    if bad:
        advisories.append(
            "Replace expired/weak certs and re-issue from a trusted internal CA "
            "(or a public ACME/Let's Encrypt cert for internet-facing services); "
            "include every hostname/IP in the SAN, use RSA≥2048 or ECDSA P-256 "
            "with SHA-256+, and disable TLS 1.0/1.1. Automate renewal so nothing "
            "silently expires.")

    return {
        'success': True,
        'verdict': overall,
        'reasons': summary,
        'counts': counts,
        'targets': results,
        'discovered': discovered_n,
        'discover_error': disc_err,
        'graded': len(graded),
        'learned': bool(learn),
        'advisories': advisories,
        'interface': interface,
    }


def _cert_selftest():
    """Self-test the TLS/cert grader (no root, no network for the classifier legs).
    Builds synthetic certs with `cryptography` and drives the real classifier, then
    — as an end-to-end leg — starts a local TLS server with a self-signed cert and
    grades it through the real handshake path. Returns a results dict."""
    scenarios = []
    now = datetime.now(timezone.utc)

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except Exception as e:
        return {'success': False, 'scenarios': [],
                'error': f'cryptography unavailable: {e}',
                'scapy': {'ran': False, 'reason': 'n/a'}}

    def make(cn, d_from, d_to, bits=2048, sans=None, issuer_cn=None):
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        issuer = (x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
                  if issuer_cn else subject)
        b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now + timedelta(days=d_from))
             .not_valid_after(now + timedelta(days=d_to)))
        if sans:
            b = b.add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(s) for s in sans]), critical=False)
        cert = b.sign(key, hashes.SHA256())
        return key, cert.public_bytes(serialization.Encoding.DER)

    def run(name, der, check, trusted, expect, proto='TLSv1.3',
            cipher='TLS_AES_256_GCM_SHA384', reason=None):
        res = _tls_classify(der, check, trusted, reason, proto, cipher, now)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'pass': ok})
        return res

    # 1. valid: trusted, in-date, hostname matches.
    _, d = make('host.test', -2, 200, sans=['host.test'])
    run('valid', d, 'host.test', True, 'valid')
    # 2. expired.
    _, d = make('host.test', -400, -5, sans=['host.test'])
    run('expired', d, 'host.test', True, 'expired')
    # 3. not-yet-valid.
    _, d = make('host.test', 5, 200, sans=['host.test'])
    run('not-yet-valid', d, 'host.test', True, 'not-yet-valid')
    # 4. self-signed (untrusted + issuer==subject).
    _, d = make('host.test', -2, 200, sans=['host.test'])
    run('self-signed', d, 'host.test', False, 'self-signed',
        reason='self-signed certificate')
    # 5. untrusted (untrusted + issuer != subject = private CA).
    _, d = make('host.test', -2, 200, sans=['host.test'], issuer_cn='Corp Root CA')
    run('untrusted', d, 'host.test', False, 'untrusted',
        reason='unable to get local issuer certificate')
    # 6. hostname-mismatch: trusted cert for other.test, connect to host.test.
    _, d = make('other.test', -2, 200, sans=['other.test'])
    run('hostname-mismatch', d, 'host.test', True, 'hostname-mismatch')
    # 7. weak-crypto: 1024-bit RSA key.
    _, d = make('host.test', -2, 200, bits=1024, sans=['host.test'])
    run('weak-crypto', d, 'host.test', True, 'weak-crypto')
    # 8. deprecated-tls: fine cert but TLS 1.0 negotiated.
    _, d = make('host.test', -2, 200, sans=['host.test'])
    run('deprecated-tls', d, 'host.test', True, 'deprecated-tls', proto='TLSv1')
    # 9. expiring: valid but < 21 days left.
    _, d = make('host.test', -2, 10, sans=['host.test'])
    run('expiring', d, 'host.test', True, 'expiring')
    # 10. wildcard SAN matches sub-domain -> valid.
    _, d = make('*.lan', -2, 200, sans=['*.lan'])
    run('wildcard-match', d, 'nas.lan', True, 'valid')

    # End-to-end: real local TLS server with a self-signed cert, graded live.
    e2e = {'ran': False, 'reason': 'skipped'}
    try:
        import threading as _thr
        skey, sder = make('localhost', -1, 60, sans=['localhost', '127.0.0.1'])
        from cryptography.hazmat.primitives import serialization as _ser
        from cryptography import x509 as _x509
        scert = _x509.load_der_x509_certificate(sder)
        tmpd = tempfile.mkdtemp()
        cp = os.path.join(tmpd, 'c.pem')
        kp = os.path.join(tmpd, 'k.pem')
        with open(cp, 'wb') as f:
            f.write(scert.public_bytes(_ser.Encoding.PEM))
        with open(kp, 'wb') as f:
            f.write(skey.private_bytes(_ser.Encoding.PEM,
                                       _ser.PrivateFormat.TraditionalOpenSSL,
                                       _ser.NoEncryption()))
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(cp, kp)
        lsock = socket.socket()
        lsock.bind(('127.0.0.1', 0))
        lsock.listen(2)
        lport = lsock.getsockname()[1]

        def _serve():
            while True:
                try:
                    conn, _ = lsock.accept()
                except OSError:
                    return
                try:
                    with sctx.wrap_socket(conn, server_side=True) as s:
                        s.recv(16)
                except Exception:
                    pass
        _thr.Thread(target=_serve, daemon=True).start()
        r = _tls_check_target('127.0.0.1', lport, 'localhost', now)
        lsock.close()
        try:
            os.remove(cp)
            os.remove(kp)
            os.rmdir(tmpd)
        except OSError:
            pass
        ok = (r.get('status') == 'graded' and r['verdict'] == 'self-signed'
              and r.get('proto', '').startswith('TLS'))
        e2e = {'ran': True, 'verdict': r.get('verdict'), 'proto': r.get('proto'),
               'trusted': r.get('trusted'), 'pass': ok}
    except Exception as e:
        e2e = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and (not e2e.get('ran')
                                                    or e2e.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'e2e': e2e}


# --------------------------------------------------------------------------
# Relay/Coercion Watch: passive NTLM-relay + authentication-coercion scanner
# --------------------------------------------------------------------------
# The defensive counterpart to Responder-style credential theft (see [[SMB Watch]]):
# SMB Watch catches the *harvest* (a host answering LLMNR/NBT-NS), this catches the
# *relay* and the *coercion* that feed it. NTLM has no channel binding by default, so
# an attacker who obtains an NTLM authentication (via poisoning, or by *coercing* a
# host to authenticate) can relay it to another service and act as the victim. This
# scanner is PASSIVE (tcpdump -> pcap -> Scapy dissect) and flags:
#   * coercion-attempt   — an MSRPC call over 445/135 that forces a host to
#     authenticate: PetitPotam (MS-EFSRPC), PrinterBug/SpoolSample (MS-RPRN opnum
#     65/66), DFSCoerce (MS-DFSNM), ShadowCoerce (MS-FSRVP). Detected by the interface
#     UUID in the RPC bind (and, for the printer bug, the coercion opnum).
#   * relay-suspected    — the *same* NTLMSSP server challenge seen from two different
#     servers: a captured challenge being replayed through a relay.
#   * signing-not-required — a server that negotiated SMB without signing *required*:
#     the posture that makes captured NTLM relayable in the first place.
# Interface UUIDs are matched by their DCE/RPC little-endian wire encoding.
_RELAY_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 'data', 'relay_watch.json')
_relay_watch_lock = threading.Lock()
_RELAY_EVENTS_CAP = 200
_RELAY_COERCION = {
    bytes.fromhex('88d481c650d8d0118c5200c04fd90f7e'): ('PetitPotam', 'MS-EFSRPC'),
    bytes.fromhex('c54119df89fe794ebf10463657acf44d'): ('PetitPotam', 'MS-EFSR'),
    bytes.fromhex('785634123412cdabef000123456789ab'): ('PrinterBug', 'MS-RPRN'),
    bytes.fromhex('e042c74f104acf11827300aa004ae673'): ('DFSCoerce', 'MS-DFSNM'),
    bytes.fromhex('3c65e0a844278943a61d7373df8b2292'): ('ShadowCoerce', 'MS-FSRVP'),
}
# These interfaces are coercion-only in practice — a bind alone is the signal. MS-RPRN
# (spoolss) is also used for legit printing, so it additionally needs the coercion opnum.
_RELAY_STRONG_IFACE = {'MS-EFSRPC', 'MS-EFSR', 'MS-DFSNM', 'MS-FSRVP'}
_RELAY_RPRN_OPNUMS = {65, 66}   # RpcRemoteFindFirstPrinterChangeNotification[Ex]


def _relay_scan_payload(raw):
    """Scan one TCP payload for relay/coercion signals. Returns
    (coercion_ifaces, opnums, ntlm_challenge, smb2_signing_required)."""
    ifaces = []
    for sig, (tech, iface) in _RELAY_COERCION.items():
        if sig in raw:
            ifaces.append((tech, iface))

    opnums = set()
    start = 0
    while True:
        k = raw.find(b'\x05\x00\x00', start)      # DCE/RPC v5.0, ptype at +2
        if k < 0 or k + 24 > len(raw):
            break
        if raw[k + 1] == 0x00 and raw[k + 2] == 0x00:   # minor 0, ptype 0 = request
            op = int.from_bytes(raw[k + 22:k + 24], 'little')
            if op < 1000:
                opnums.add(op)
        start = k + 3

    challenge = None
    i = raw.find(b'NTLMSSP\x00')
    if i >= 0 and i + 32 <= len(raw) and int.from_bytes(raw[i + 8:i + 12], 'little') == 2:
        ch = raw[i + 24:i + 32]
        if ch != b'\x00' * 8:
            challenge = ch.hex()

    signing = None
    j = raw.find(b'\xfeSMB')
    if j >= 0 and len(raw) >= j + 67 and int.from_bytes(raw[j + 12:j + 14], 'little') == 0:
        signing = bool(raw[j + 64 + 2] & 0x02)   # SMB2 NEGOTIATE SecurityMode: REQUIRED

    return ifaces, opnums, challenge, signing


def _parse_relay_packets(packets):
    """Dissect scapy packets into (coercion_findings, challenge_map, signing_map).
    Shared by the live path and the self-test."""
    from scapy.all import IP, IPv6, TCP
    streams = {}
    challenges = {}
    signing = {}
    for pk in packets:
        ipl = pk.getlayer(IP) or pk.getlayer(IPv6)
        if ipl is None or not pk.haslayer(TCP):
            continue
        raw = bytes(pk.getlayer(TCP).payload)
        if not raw:
            continue
        src, dst = ipl.src, ipl.dst
        ifaces, opnums, chal, sign = _relay_scan_payload(raw)
        st = streams.setdefault((src, dst), {'ifaces': set(), 'opnums': set()})
        for ti in ifaces:
            st['ifaces'].add(ti)
        st['opnums'] |= opnums
        if chal:
            challenges.setdefault(chal, set()).add(src)
        if sign is not None:
            # The server sends the NEGOTIATE response; False (any unsigned) wins.
            signing[src] = False if signing.get(src) is False else sign

    coercion = []
    for (src, dst), st in streams.items():
        seen = set()
        for (tech, iface) in st['ifaces']:
            if iface in _RELAY_STRONG_IFACE:
                seen.add((tech, iface))
            elif iface == 'MS-RPRN' and (st['opnums'] & _RELAY_RPRN_OPNUMS):
                seen.add((tech, iface))
        for (tech, iface) in sorted(seen):
            coercion.append({'attacker': src, 'victim': dst, 'technique': tech,
                             'interface': iface})
    return coercion, challenges, signing


def _relay_watch_load():
    try:
        with open(_RELAY_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _relay_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_RELAY_WATCH_PATH), exist_ok=True)
        tmp = _RELAY_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _RELAY_WATCH_PATH)
    except OSError:
        pass


def do_relay_baseline(action='get'):
    """Manage the learned Relay/Coercion baseline (accepted servers that negotiate
    without signing required). Coercion + relay are never baselined away."""
    with _relay_watch_lock:
        if action == 'reset':
            _relay_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _relay_watch_load()
        return {'success': True, 'baseline': {
            'unsigned_servers': b.get('unsigned_servers') or []}}


def _relay_analyze(coercion, challenges, signing, seconds, baseline, learn=True):
    """Pure classifier over parsed relay/coercion signals. Separated from capture for
    the self-test. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))

    unsigned = sorted(ip for ip, req in signing.items() if req is False)
    signed = sorted(ip for ip, req in signing.items() if req is True)
    relays = [{'challenge': c, 'servers': sorted(s)}
              for c, s in sorted(challenges.items()) if len(s) > 1]

    known_unsigned = set(baseline.get('unsigned_servers') or [])
    had_baseline = bool(known_unsigned) or bool(baseline)

    learned = False
    if learn and not had_baseline and (unsigned or signed or coercion):
        baseline['unsigned_servers'] = unsigned
        learned = True
        known_unsigned = set(unsigned)

    PRIORITY = ['coercion-attempt', 'relay-suspected', 'signing-not-required', 'clean']
    verdict = 'clean'
    reasons = []

    def bump(v):
        nonlocal verdict
        if PRIORITY.index(v) < PRIORITY.index(verdict):
            verdict = v

    for c in coercion:
        bump('coercion-attempt')
        reasons.append(
            f"COERCION: {c['attacker']} is coercing {c['victim']} to authenticate via "
            f"{c['technique']} ({c['interface']}) — the forced NTLM auth can be relayed "
            f"to a DC/host. Patch the vector, block the RPC interface, and require SMB/"
            f"LDAP signing + channel binding (EPA)")

    for r in relays:
        bump('relay-suspected')
        reasons.append(
            f"RELAY SUSPECTED: NTLM server challenge {r['challenge']} appeared from "
            f"{len(r['servers'])} servers ({', '.join(r['servers'])}) — the same "
            f"challenge relayed through an attacker (NTLM relay in progress)")

    for ip in unsigned:
        bump('signing-not-required')
        tag = ' (known)' if ip in known_unsigned else ''
        reasons.append(
            f"SMB signing NOT required on {ip}{tag} — captured/coerced NTLM can be "
            f"relayed to it. Set RequireSecuritySignature=1 (GPO 'Microsoft network "
            f"server: Digitally sign communications (always)')")

    advisories = []
    if coercion or relays or unsigned or signed:
        advisories.append(
            "Break NTLM relay: enforce SMB signing everywhere, enable LDAP signing + "
            "LDAP channel binding on DCs, turn on Extended Protection for Authentication "
            "(EPA) on HTTP/LDAPS, disable the Print Spooler on DCs, and apply the "
            "PetitPotam/EFS + DFSCoerce patches (or RPC-filter the interfaces).")

    if reasons:
        summary = reasons
    elif not (coercion or relays or signing):
        summary = ['No coercion, NTLM relay, or unsigned-SMB negotiation seen']
    else:
        summary = ['No coercion or relay detected; SMB signing looks enforced']

    return {
        'success': True,
        'verdict': verdict,
        'reasons': summary,
        'learned': learned,
        'coercion': coercion,
        'relays': relays,
        'signing': {'unsigned': [{'ip': ip, 'known': ip in known_unsigned}
                                 for ip in unsigned],
                    'signed': signed},
        'advisories': advisories,
    }


def _relay_capture(interface, seconds):
    """Capture SMB/MSRPC traffic to a temp pcap via tcpdump -w -> (pcap_path, error).
    Scapy dissects it; snaplen 1024 to keep the RPC bind/opnum + NTLMSSP intact."""
    if not _have('tcpdump'):
        return None, 'tcpdump is not installed. Click Install to add it.'
    if not _have_scapy():
        return None, ('python3-scapy is required to parse MSRPC / NTLM traffic — '
                      'install Scapy (Detector Self-Test → Install Scapy).')
    bpf = 'tcp port 445 or tcp port 139 or tcp port 135'
    import tempfile
    fd, path = tempfile.mkstemp(suffix='.pcap')
    os.close(fd)
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface, '-nn', '-p',
                '-s', '1024', '-c', '20000', '-w', path, bpf], timeout=seconds + 8)
    if (os.path.getsize(path) <= 24 and res['err']
            and ('permission' in res['err'].lower() or "couldn't" in res['err'].lower()
                 or 'no such device' in res['err'].lower()
                 or 'syntax error' in res['err'].lower())):
        try:
            os.remove(path)
        except OSError:
            pass
        return None, res['err'].strip()[:200]
    return path, None


def do_relay_watch(interface=None, seconds=20, learn=True):
    """Passive NTLM-relay + coercion scanner (detection-only). One capture; classifies
    coercion attempts (PetitPotam/PrinterBug/DFSCoerce/ShadowCoerce), suspected relays,
    and SMB-signing-not-required posture. Learns accepted unsigned servers on first run."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 20, 5, 50)

    path, err = _relay_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    try:
        from scapy.all import rdpcap
        packets = rdpcap(path)
    except Exception as e:
        return {'success': False, 'interface': iface,
                'error': f'could not read capture: {type(e).__name__}'}
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    coercion, challenges, signing = _parse_relay_packets(packets)

    with _relay_watch_lock:
        baseline = _relay_watch_load()
        result = _relay_analyze(coercion, challenges, signing, seconds, baseline,
                                learn=learn)
        if result.get('learned'):
            _relay_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _relay_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_RELAY_EVENTS_CAP:]
            _relay_watch_save(b)

    result['interface'] = iface
    result['seconds'] = seconds
    result['packet_count'] = len(packets)
    return result


def _relay_selftest():
    """Self-test Relay/Coercion Watch by building real attack packets into a pcap,
    reading them back through the same Scapy parser, and asserting verdicts."""
    scenarios = []
    try:
        import tempfile
        from scapy.all import Ether, IP, TCP, Raw, wrpcap, rdpcap
    except Exception as e:
        return {'success': True, 'scenarios': [],
                'scapy': {'ran': False, 'reason': f'{type(e).__name__}: {e}'}}

    def pkt(src, dst, raw, sport=50000, dport=445):
        return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                                    flags='PA') / Raw(raw)

    def rpc_bind(uuid_hex):
        return b'\x05\x00\x0b\x03' + b'\x00' * 20 + bytes.fromhex(uuid_hex)

    def rpc_request(opnum):
        return (bytes([5, 0, 0, 3]) + b'\x10\x00\x00\x00' + b'\x00\x00' + b'\x00\x00'
                + b'\x01\x00\x00\x00' + b'\x00\x00\x00\x00' + b'\x00\x00'
                + opnum.to_bytes(2, 'little'))

    def ntlm_challenge(ch):
        return (b'NTLMSSP\x00' + (2).to_bytes(4, 'little') + b'\x00' * 12 + ch
                + b'\x00' * 8)

    def smb2_negotiate_resp(secmode):
        hdr = b'\xfeSMB' + b'\x00' * 8 + (0).to_bytes(2, 'little') + b'\x00' * 50
        body = (65).to_bytes(2, 'little') + secmode.to_bytes(2, 'little') + b'\x00' * 32
        return b'\x00\x00\x00\x00' + hdr + body

    def run(name, pkts, baseline, expect):
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
            path = tf.name
        wrpcap(path, pkts)
        try:
            co, ch, sg = _parse_relay_packets(rdpcap(path))
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
        res = _relay_analyze(co, ch, sg, 20, dict(baseline or {}), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'pass': ok})
        return res

    base = {'unsigned_servers': ['10.0.0.7']}

    # 1. clean: an SMB2 negotiate with signing required.
    run('clean', [pkt('10.0.0.5', '10.0.0.9', smb2_negotiate_resp(0x03),
                      sport=445, dport=50000)], base, 'clean')
    # 2. coercion (PetitPotam): EFSRPC interface bind.
    run('coercion-petitpotam',
        [pkt('10.0.0.66', '10.0.0.5', rpc_bind('88d481c650d8d0118c5200c04fd90f7e'))],
        base, 'coercion-attempt')
    # 3. coercion (DFSCoerce): DFSNM interface bind.
    run('coercion-dfscoerce',
        [pkt('10.0.0.66', '10.0.0.5', rpc_bind('e042c74f104acf11827300aa004ae673'))],
        base, 'coercion-attempt')
    # 4. coercion (PrinterBug): RPRN bind + opnum-65 request in the same stream.
    run('coercion-printerbug',
        [pkt('10.0.0.66', '10.0.0.5', rpc_bind('785634123412cdabef000123456789ab')),
         pkt('10.0.0.66', '10.0.0.5', rpc_request(65))], base, 'coercion-attempt')
    # 4b. RPRN bind WITHOUT the coercion opnum must NOT trigger (legit printing).
    r = run('printer-legit',
            [pkt('10.0.0.9', '10.0.0.5', rpc_bind('785634123412cdabef000123456789ab'))],
            base, 'clean')
    # 5. relay-suspected: same NTLM challenge from two servers.
    ch = b'\x11\x22\x33\x44\x55\x66\x77\x88'
    run('relay-suspected',
        [pkt('10.0.0.5', '10.0.0.9', ntlm_challenge(ch), sport=445, dport=50000),
         pkt('10.0.0.66', '10.0.0.9', ntlm_challenge(ch), sport=445, dport=50001)],
        base, 'relay-suspected')
    # 6. signing-not-required: a server negotiating signing enabled-only.
    run('signing-not-required',
        [pkt('10.0.0.8', '10.0.0.9', smb2_negotiate_resp(0x01), sport=445, dport=50000)],
        base, 'signing-not-required')

    # 7. parse: fields land.
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
        path = tf.name
    wrpcap(path, [pkt('10.0.0.66', '10.0.0.5',
                      rpc_bind('88d481c650d8d0118c5200c04fd90f7e')),
                  pkt('10.0.0.8', '10.0.0.9', smb2_negotiate_resp(0x01),
                      sport=445, dport=50000)])
    co, ch2, sg = _parse_relay_packets(rdpcap(path))
    try:
        os.remove(path)
    except OSError:
        pass
    p_ok = (any(c['technique'] == 'PetitPotam' for c in co)
            and sg.get('10.0.0.8') is False)
    scenarios.append({'name': 'relay-parse', 'expect': 'petitpotam+unsigned',
                      'got': f"coercion={len(co)} unsigned={sg.get('10.0.0.8')}",
                      'pass': p_ok})

    passed = all(s['pass'] for s in scenarios)
    return {'success': passed, 'scenarios': scenarios,
            'scapy': {'ran': True, 'pass': passed, 'scenarios_run': len(scenarios)}}


# --------------------------------------------------------------------------
# SMB Watch: passive SMBv1 + LLMNR/NBT-NS/mDNS poisoning scanner (Windows attack surface)
# --------------------------------------------------------------------------
# Two related Windows-endpoint findings that share one kill chain (Responder → NTLM →
# SMB relay), detection-only, one passive capture:
#   Part 1 — SMBv1: the deprecated (2014) SMB dialect and the EternalBlue / WannaCry /
#     NotPetya (MS17-010) vector. Disabled by default on modern Windows but still
#     lurking on legacy NAS/printers/old hosts. SMBv1 frames carry the magic \xffSMB
#     (SMB2/3 use \xfeSMB), so we tell them apart on the wire and, from the SMB command
#     byte + response flag, separate a *real* SMBv1 session (tree-connect/session-setup,
#     or a server negotiate-response) from a harmless multi-dialect negotiate offer.
#   Part 2 — LLMNR / NBT-NS / mDNS poisoning: when DNS fails, Windows falls back to
#     these broadcast/multicast name-resolution protocols (LLMNR udp/5355, NBT-NS
#     udp/137, mDNS udp/5353). Responder / Inveigh answer those queries with the
#     attacker's IP; the victim then authenticates to the attacker and leaks NTLMv2
#     hashes (offline crack or relay). Nothing legitimate *answers* LLMNR/NBT-NS, so a
#     host that does is a poisoner. We flag: an active poisoner, a spoof-conflict (two
#     hosts answering one name differently), WPAD targeting, and mere exposure
#     (LLMNR/NBT-NS in use at all). Capture is done by tcpdump into a pcap; Scapy
#     dissects it (tcpdump no longer decodes SMB, and never decoded LLMNR/NBT-NS).
#   Part 3 — Kerberos downgrade / roasting (tcp+udp 88): the same capture also reads
#     Kerberos KDC traffic. Kerberos is ASN.1/DER, and the fields that matter for a
#     *passive* downgrade watch sit near the start of each message, so a small tolerant
#     DER walker (_krb_*) reads them straight off the wire without a full dissector —
#     and it keeps working on packets truncated by the capture snaplen. It flags:
#       * kerberoast    — a TGS-REQ for a service SPN (sname != krbtgt) that forces RC4
#         (etype 23) so the returned service ticket is offline-crackable (Rubeus /
#         GetUserSPNs signature); or a KDC that issues an RC4 service ticket.
#       * asrep-roast   — an AS-REQ with no PA-ENC-TIMESTAMP pre-auth (account has "do
#         not require preauth"), especially one answered by an AS-REP — the AS-REP is an
#         offline-crackable hash.
#       * krb-downgrade — the KDC actually issues a DES/RC4 ticket (weak encryption in
#         real use), or a client offers only weak etypes (AES stripped/disabled).
#       * krb-exposure  — RC4/DES still enabled alongside AES (legacy encryption).
#     Kerberos attack verdicts are never baselined away; the baseline only remembers
#     known KDC IPs + realms to annotate the output. See [[SMB Watch]] / [[relay watch]].
_SMB_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'data', 'smb_watch.json')
_smb_watch_lock = threading.Lock()
_SMB_EVENTS_CAP = 200
_SMB_SERVER_PORTS = {445, 139}
# High-value names an attacker loves to poison (proxy auto-config, ISATAP, etc.).
_SMB_HIGHVALUE = {'wpad', 'isatap'}
# Multicast/broadcast destinations that mark a name-resolution *query*.
_SMB_MCAST = {'224.0.0.252', 'ff02::1:3', '224.0.0.251', 'ff02::fb'}
# Kerberos KDC ports (AS/TGS exchange). Same passive capture, tcp + udp.
_KRB_PORTS = {88}
# Kerberos encryption types (RFC 3961/4120). AES is strong; RC4/DES are the
# downgrade/roasting-enabling weak ones; 3DES is deprecated legacy.
_KRB_ETYPE_NAMES = {1: 'des-cbc-crc', 2: 'des-cbc-md4', 3: 'des-cbc-md5',
                    5: 'des3-cbc-md5', 16: 'des3-cbc-sha1', 17: 'aes128',
                    18: 'aes256', 19: 'aes128-sha256', 20: 'aes256-sha384',
                    23: 'rc4-hmac', 24: 'rc4-hmac-exp', 25: 'camellia128',
                    26: 'camellia256'}
_KRB_RC4 = {23, 24}
_KRB_DES = {1, 2, 3, 5, 16}          # single-DES + 3DES, all deprecated/breakable
_KRB_AES = {17, 18, 19, 20}
_KRB_WEAK = _KRB_RC4 | _KRB_DES
# PA-ENC-TIMESTAMP pre-auth padata type; its absence == "do not require preauth".
_KRB_PA_ENC_TIMESTAMP = 2


def _smb_find_magic(raw):
    """Locate the SMB header in a TCP payload. Returns (version, command, response?)
    or None. version is 'v1' (\\xffSMB) or 'v2' (\\xfeSMB)."""
    i = raw.find(b'SMB')
    if i < 1:
        return None
    magic = raw[i - 1]
    if magic == 0xFF:
        cmd = raw[i + 3] if len(raw) > i + 3 else None
        flags = raw[i + 8] if len(raw) > i + 8 else 0
        return ('v1', cmd, bool(flags & 0x80))
    if magic == 0xFE:
        return ('v2', None, None)
    return None


def _nbns_parse(payload):
    """Force-parse a NetBIOS-NS (udp/137) payload -> (is_response, name, answer_ips).
    tcpdump/scapy don't auto-bind NBT-NS, so we read the header flag and layer by
    hand."""
    if len(payload) < 12:
        return None
    is_resp = bool(int.from_bytes(payload[2:4], 'big') & 0x8000)
    name, answers = None, []
    try:
        from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse
        nb = (NBNSQueryResponse if is_resp else NBNSQueryRequest)(payload)
        raw = getattr(nb, 'RR_NAME', None) or getattr(nb, 'QUESTION_NAME', None)
        if isinstance(raw, bytes):
            name = raw.decode('latin1', 'replace').strip().strip('\x00').strip()
        elif raw is not None:
            name = str(raw).strip()
        for ent in (getattr(nb, 'ADDR_ENTRY', None) or []):
            a = getattr(ent, 'NB_ADDRESS', None)
            if a:
                answers.append(a)
    except Exception:
        pass
    return is_resp, name, answers


def _smb_parse_packets(packets):
    """Classify a sequence of scapy packets into (smb_events, nameres_events).
    Shared by the live path (rdpcap of a tcpdump pcap) and the self-test."""
    from scapy.all import IP, IPv6, UDP, TCP, Raw, DNS
    try:
        from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
    except Exception:
        LLMNRQuery = LLMNRResponse = None

    smb_events, nameres = [], []
    for pk in packets:
        ipl = pk.getlayer(IP) or pk.getlayer(IPv6)
        if ipl is None:
            continue
        src, dst = ipl.src, ipl.dst

        if pk.haslayer(TCP) and pk.haslayer(Raw):
            t = pk.getlayer(TCP)
            if t.sport in _SMB_SERVER_PORTS or t.dport in _SMB_SERVER_PORTS:
                found = _smb_find_magic(bytes(pk.getlayer(Raw).load))
                if found:
                    ver, cmd, resp = found
                    from_server = t.sport in _SMB_SERVER_PORTS
                    server = src if from_server else dst
                    smb_events.append({'server': server, 'client': dst if from_server else src,
                                       'version': ver, 'command': cmd, 'response': resp,
                                       'from_server': from_server})
            continue

        if not pk.haslayer(UDP):
            continue
        u = pk.getlayer(UDP)
        to_mcast = dst in _SMB_MCAST or str(dst).endswith('.255')

        if u.dport == 5355 or u.sport == 5355:            # LLMNR
            if LLMNRResponse is not None and pk.haslayer(LLMNRResponse):
                r = pk.getlayer(LLMNRResponse)
                nm = _dns_qname(r)
                ans = _dns_answer_ip(r)
                nameres.append({'proto': 'llmnr', 'kind': 'response', 'src': src,
                                'dst': dst, 'name': nm, 'answer': ans})
            elif LLMNRQuery is not None and pk.haslayer(LLMNRQuery):
                nameres.append({'proto': 'llmnr', 'kind': 'query', 'src': src,
                                'dst': dst, 'name': _dns_qname(pk.getlayer(LLMNRQuery)),
                                'answer': None})
        elif u.dport == 5353 or u.sport == 5353:          # mDNS
            if pk.haslayer(DNS):
                d = pk.getlayer(DNS)
                is_resp = int(getattr(d, 'qr', 0)) == 1 or int(getattr(d, 'ancount', 0)) > 0
                nameres.append({'proto': 'mdns', 'kind': 'response' if is_resp else 'query',
                                'src': src, 'dst': dst, 'name': _dns_qname(d),
                                'answer': _dns_answer_ip(d) if is_resp else None})
        elif u.dport == 137 or u.sport == 137:            # NBT-NS
            parsed = _nbns_parse(bytes(u.payload))
            if parsed:
                is_resp, nm, answers = parsed
                # Queries are broadcast; a reply from :137 to a unicast host (not the
                # broadcast group) is a response even if the header flag is unset.
                if not is_resp and u.sport == 137 and not to_mcast:
                    is_resp = True
                nameres.append({'proto': 'nbtns', 'kind': 'response' if is_resp else 'query',
                                'src': src, 'dst': dst, 'name': nm,
                                'answer': answers[0] if answers else None})
    return smb_events, nameres


def _dns_qname(layer):
    try:
        qd = getattr(layer, 'qd', None)
        if qd and getattr(qd, 'qname', None):
            n = qd.qname
            return (n.decode('latin1', 'replace') if isinstance(n, bytes) else str(n)).rstrip('.')
    except Exception:
        pass
    return None


def _dns_answer_ip(layer):
    try:
        an = getattr(layer, 'an', None)
        if an and getattr(an, 'rdata', None):
            rd = an.rdata
            return rd.decode('latin1', 'replace') if isinstance(rd, bytes) else str(rd)
    except Exception:
        pass
    return None


def _smb_watch_load():
    try:
        with open(_SMB_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _smb_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_SMB_WATCH_PATH), exist_ok=True)
        tmp = _SMB_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _SMB_WATCH_PATH)
    except OSError:
        pass


def do_smb_baseline(action='get'):
    """Manage the learned SMB Watch baseline (accepted mDNS responders + known SMBv1
    hosts + known Kerberos KDCs/realms). LLMNR/NBT-NS responders and Kerberos attack
    verdicts are never baselined away — nothing should answer LLMNR/NBT-NS, and the
    KDC/realm baseline only annotates output, never suppresses a downgrade/roast."""
    with _smb_watch_lock:
        if action == 'reset':
            _smb_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _smb_watch_load()
        return {'success': True, 'baseline': {
            'mdns_responders': b.get('mdns_responders') or [],
            'smbv1_hosts': b.get('smbv1_hosts') or [],
            'kdcs': b.get('kdcs') or [],
            'krb_realms': b.get('krb_realms') or []}}


def _smb_analyze(smb_events, nameres, seconds, baseline, learn=True):
    """Pure classifier over parsed SMB + name-resolution events. Separated from
    capture for the self-test. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))

    # ---- Part 1: SMBv1 ----
    servers = {}
    v2_count = 0
    for e in smb_events:
        if e['version'] == 'v2':
            v2_count += 1
            continue
        s = servers.setdefault(e['server'], {
            'ip': e['server'], 'active': False, 'offered': False, 'count': 0})
        s['count'] += 1
        # A v1 command other than negotiate (0x72), or a server negotiate *response*,
        # means SMBv1 is really being spoken; a client's negotiate request only offers it.
        if (e['command'] not in (0x72, None)) or (e['command'] == 0x72 and e['response']):
            s['active'] = True
        else:
            s['offered'] = True

    # ---- Part 2: LLMNR/NBT-NS/mDNS poisoning ----
    responders = {}
    q_llmnr = q_nbtns = q_mdns = 0
    name_answers = {}
    for e in nameres:
        if e['kind'] == 'query':
            if e['proto'] == 'llmnr':
                q_llmnr += 1
            elif e['proto'] == 'nbtns':
                q_nbtns += 1
            else:
                q_mdns += 1
            continue
        r = responders.setdefault(e['src'], {
            'ip': e['src'], 'protos': set(), 'names': set(), 'highvalue': set(),
            'foreign': False, 'count': 0})
        r['count'] += 1
        r['protos'].add(e['proto'])
        if e['name']:
            r['names'].add(e['name'])
            base = e['name'].split('.')[0].lower()
            if base in _SMB_HIGHVALUE:
                r['highvalue'].add(e['name'])
            name_answers.setdefault(e['name'].lower(), set())
            if e['answer']:
                name_answers[e['name'].lower()].add(e['answer'])
        # mDNS is legit when a host announces *itself* (answer == its own IP); a reply
        # pointing elsewhere is a host claiming another identity.
        if e['answer'] and e['answer'] != e['src']:
            r['foreign'] = True

    known_mdns = set(baseline.get('mdns_responders') or [])
    known_v1 = set(baseline.get('smbv1_hosts') or [])
    had_baseline = bool(known_mdns) or bool(known_v1) or bool(baseline)

    learned = False
    if learn and not had_baseline and (servers or responders):
        baseline['mdns_responders'] = sorted(
            ip for ip, r in responders.items() if r['protos'] == {'mdns'} and not r['foreign'])
        baseline['smbv1_hosts'] = sorted(servers.keys())
        learned = True
        known_mdns = set(baseline['mdns_responders'])
        known_v1 = set(baseline['smbv1_hosts'])

    PRIORITY = ['poisoning', 'smbv1-active', 'spoof-conflict', 'smbv1-offered',
                'name-exposure', 'clean']
    verdict = 'clean'
    reasons = []

    def bump(v):
        nonlocal verdict
        if PRIORITY.index(v) < PRIORITY.index(verdict):
            verdict = v

    # Poisoning: any host answering LLMNR/NBT-NS, or an mDNS host claiming foreign
    # identities / high-value names.
    for ip in sorted(responders):
        r = responders[ip]
        poisons = r['protos'] & {'llmnr', 'nbtns'}
        mdns_bad = ('mdns' in r['protos']
                    and (r['highvalue'] or (r['foreign'] and len(r['names']) > 4)))
        if poisons or mdns_bad:
            bump('poisoning')
            protos = ', '.join(sorted(poisons or {'mdns'})).upper()
            names = ', '.join(sorted(r['names'])[:5]) or '(unnamed)'
            hv = ' incl. WPAD/ISATAP' if r['highvalue'] else ''
            reasons.append(
                f"POISONING: {ip} is answering {protos} name queries "
                f"(Responder/Inveigh) — replied for {names}{hv}. Victims that trust "
                f"the reply authenticate to it and leak NTLMv2 hashes. Disable "
                f"LLMNR/NBT-NS via GPO and enable SMB signing to block relay")

    # Spoof conflict: one name answered by 2+ different IPs.
    for name in sorted(name_answers):
        ips = name_answers[name]
        if len(ips) > 1:
            bump('spoof-conflict')
            reasons.append(
                f"Name '{name}' is answered with conflicting IPs ({', '.join(sorted(ips))}) "
                f"— a poisoner racing the real owner of the name")

    # SMBv1.
    for ip in sorted(servers):
        s = servers[ip]
        tag = ' (known legacy host)' if ip in known_v1 else ''
        if s['active']:
            bump('smbv1-active')
            reasons.append(
                f"SMBv1 in ACTIVE use by {ip}{tag} — SMBv1 is deprecated and the "
                f"EternalBlue/WannaCry (MS17-010) vector. Disable it "
                f"(Set-SmbServerConfiguration -EnableSMB1Protocol $false) and patch")
        elif s['offered']:
            bump('smbv1-offered')
            reasons.append(
                f"SMBv1 offered by {ip}{tag} in dialect negotiation (may still upgrade "
                f"to SMB2/3) — disable SMBv1 to remove the downgrade/fallback path")

    # Exposure: LLMNR/NBT-NS queries present but nobody (yet) answering.
    if (q_llmnr or q_nbtns) and verdict in ('clean', 'name-exposure'):
        bump('name-exposure')
        reasons.append(
            f"LLMNR/NBT-NS queries seen ({q_llmnr} LLMNR, {q_nbtns} NBT-NS) with no "
            f"responder — hosts fall back to these poisonable protocols; disable them "
            f"via GPO before a Responder shows up on the segment")

    advisories = []
    if servers or responders or q_llmnr or q_nbtns:
        advisories.append(
            "Windows hardening: disable SMBv1 everywhere, turn off LLMNR (GPO: Turn off "
            "multicast name resolution) and NBT-NS (per-adapter / DHCP option 001=2), "
            "and enforce SMB signing so captured NTLM can't be relayed.")

    if reasons:
        summary = reasons
    elif not (smb_events or nameres):
        summary = ['No SMB or LLMNR/NBT-NS/mDNS traffic seen on this segment']
    else:
        summary = ['No SMBv1 and no name-resolution poisoning detected '
                   '(SMB2/3 + legit mDNS only)']

    return {
        'success': True,
        'verdict': verdict,
        'reasons': summary,
        'learned': learned,
        'smb': {
            'v1_servers': [{'ip': s['ip'],
                            'mode': 'active' if s['active'] else 'offered',
                            'known': s['ip'] in known_v1} for s in
                           (servers[i] for i in sorted(servers))],
            'v1_count': sum(s['count'] for s in servers.values()),
            'v2_count': v2_count},
        'nameres': {
            'responders': [{'ip': r['ip'], 'protos': sorted(r['protos']),
                            'names': sorted(r['names'])[:12],
                            'highvalue': sorted(r['highvalue']),
                            'foreign': r['foreign'],
                            'known': r['ip'] in known_mdns} for r in
                           (responders[i] for i in sorted(responders))],
            'queries': {'llmnr': q_llmnr, 'nbtns': q_nbtns, 'mdns': q_mdns},
            'conflicts': [{'name': n, 'answers': sorted(name_answers[n])}
                          for n in sorted(name_answers) if len(name_answers[n]) > 1]},
        'advisories': advisories,
    }


# ---- Kerberos (Part 3): tolerant DER walker + passive downgrade/roasting parse ----
# Kerberos messages are ASN.1/DER. We don't need a full dissector — only a handful of
# early fields — so this walks the tag/length/value tree just far enough, and never
# raises on malformed or snaplen-truncated input (it returns what it managed to read).

def _der_len(buf, i):
    """DER length starting at byte i (tag already consumed). Returns (length, next_i);
    length is None on a malformed/indefinite/oversized encoding."""
    if i >= len(buf):
        return None, i
    b = buf[i]
    i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7f
    if n == 0 or n > 4 or i + n > len(buf):
        return None, i
    return int.from_bytes(buf[i:i + n], 'big'), i + n


def _der_children(buf):
    """Split a constructed value's content into a list of (tag_byte, content_bytes).
    Stops cleanly at a truncated tail rather than raising."""
    out, i = [], 0
    while i < len(buf):
        tag = buf[i]
        i += 1
        length, i = _der_len(buf, i)
        if length is None:
            break
        content = buf[i:i + length]
        out.append((tag, content))
        if len(content) < length:      # truncated by snaplen — keep the partial tail
            break
        i += length
    return out


def _der_int(b):
    """Decode a DER INTEGER's content bytes (two's-complement signed)."""
    if not b:
        return 0
    v = int.from_bytes(b, 'big')
    return v - (1 << (8 * len(b))) if (b[0] & 0x80) else v


def _der_first_int(content):
    """First INTEGER value inside a context tag's content, or None."""
    kids = _der_children(content)
    return _der_int(kids[0][1]) if kids else None


def _der_child(children, tag):
    for t, c in children:
        if t == tag:
            return c
    return None


def _der_unwrap(content):
    """Children of the SEQUENCE (or APPLICATION-tagged SEQUENCE) inside a context tag."""
    kids = _der_children(content)
    if kids and kids[0][0] in (0x30, 0x61, 0x6e):
        return _der_children(kids[0][1])
    return kids


def _krb_princ(content):
    """PrincipalName -> list of its name-string components (['MSSQLSvc','db01'] ...)."""
    ns = _der_child(_der_unwrap(content), 0xa1)          # [1] name-string
    if ns is None:
        return []
    seq = _der_children(ns)
    if not seq:
        return []
    return [c.decode('latin1', 'replace')
            for t, c in _der_children(seq[0][1]) if t == 0x1b]


def _krb_gstr(content):
    for t, c in _der_children(content):
        if t == 0x1b:                                    # GeneralString
            return c.decode('latin1', 'replace')
    return None


# Application tags of the Kerberos messages we read (class APPLICATION, constructed).
_KRB_APP_TAGS = {0x6a: 'as-req', 0x6b: 'as-rep', 0x6c: 'tgs-req', 0x6d: 'tgs-rep',
                 0x7e: 'krb-error'}


def _krb_parse_message(raw):
    """Parse one Kerberos message payload into a dict, or None if it isn't one. Over TCP
    the payload is preceded by a 4-byte length; over UDP it starts at the app tag."""
    if not raw:
        return None
    if raw[0] not in _KRB_APP_TAGS and len(raw) > 4 and raw[4] in _KRB_APP_TAGS:
        raw = raw[4:]                                    # skip TCP length prefix
    if not raw or raw[0] not in _KRB_APP_TAGS:
        return None
    kind = _KRB_APP_TAGS[raw[0]]
    length, hdr = _der_len(raw, 1)
    seq = _der_children(raw[hdr:hdr + (length if length else len(raw))])
    kids = _der_children(seq[0][1]) if (seq and seq[0][0] == 0x30) else seq
    ev = {'kind': kind, 'etypes': [], 'cname': [], 'sname': [], 'realm': None,
          'padata': [], 'rep_etype': None, 'error_code': None}

    def padata_types(tag_content):
        types = []
        for t, c in _der_unwrap(tag_content):            # each PA-DATA SEQUENCE
            if t == 0x30:
                pt = _der_child(_der_children(c), 0xa1)  # [1] padata-type
                if pt is not None:
                    types.append(_der_first_int(pt))
        return types

    if kind in ('as-req', 'tgs-req'):
        pc = _der_child(kids, 0xa3)                      # [3] padata
        if pc:
            ev['padata'] = padata_types(pc)
        rb = _der_child(kids, 0xa4)                      # [4] req-body
        if rb:
            body = _der_unwrap(rb)
            et = _der_child(body, 0xa8)                  # [8] etype (SEQUENCE OF Int32)
            if et:
                s = _der_children(et)
                if s:
                    ev['etypes'] = [_der_int(c) for t, c in _der_children(s[0][1])
                                    if t == 0x02]
            cn = _der_child(body, 0xa1)                  # [1] cname
            ev['cname'] = _krb_princ(cn) if cn else []
            rl = _der_child(body, 0xa2)                  # [2] realm
            ev['realm'] = _krb_gstr(rl) if rl else None
            sn = _der_child(body, 0xa3)                  # [3] sname
            ev['sname'] = _krb_princ(sn) if sn else []
    elif kind in ('as-rep', 'tgs-rep'):
        cn = _der_child(kids, 0xa4)                      # [4] cname
        ev['cname'] = _krb_princ(cn) if cn else []
        rl = _der_child(kids, 0xa3)                      # [3] crealm
        ev['realm'] = _krb_gstr(rl) if rl else None
        ep = _der_child(kids, 0xa6)                      # [6] enc-part (EncryptedData)
        if ep:
            e0 = _der_child(_der_unwrap(ep), 0xa0)       # [0] etype
            if e0 is not None:
                ev['rep_etype'] = _der_first_int(e0)
    elif kind == 'krb-error':
        ec = _der_child(kids, 0xa6)                      # [6] error-code
        if ec is not None:
            ev['error_code'] = _der_first_int(ec)
        cn = _der_child(kids, 0xa8)                      # [8] cname
        ev['cname'] = _krb_princ(cn) if cn else []
    return ev


def _krb_parse_packets(packets):
    """Extract Kerberos KDC events from scapy packets (tcp/udp port 88). Each event also
    records src/dst and which side is the KDC, for known-KDC baselining."""
    from scapy.all import IP, IPv6, UDP, TCP, Raw
    events = []
    for pk in packets:
        ipl = pk.getlayer(IP) or pk.getlayer(IPv6)
        if ipl is None or not pk.haslayer(Raw):
            continue
        l4 = pk.getlayer(TCP) or pk.getlayer(UDP)
        if l4 is None:
            continue
        if l4.sport not in _KRB_PORTS and l4.dport not in _KRB_PORTS:
            continue
        try:
            ev = _krb_parse_message(bytes(pk.getlayer(Raw).load))
        except Exception:
            ev = None
        if not ev:
            continue
        from_kdc = l4.sport in _KRB_PORTS
        ev['src'], ev['dst'] = ipl.src, ipl.dst
        ev['kdc'] = ipl.src if from_kdc else ipl.dst
        events.append(ev)
    return events


def _krb_etype_names(etypes):
    return [_KRB_ETYPE_NAMES.get(e, str(e)) for e in etypes]


def _krb_analyze(krb_events, baseline, learn=True):
    """Pure classifier over parsed Kerberos events (separated from capture for the
    self-test). Flags downgrade / kerberoast / AS-REP roast. May learn known KDC IPs +
    realms into `baseline`, but never suppresses an attack verdict with them."""
    PRIORITY = ['kerberoast', 'asrep-roast', 'krb-downgrade', 'krb-exposure', 'clean']
    verdict = 'clean'
    reasons, findings = [], []

    def bump(v):
        nonlocal verdict
        if PRIORITY.index(v) < PRIORITY.index(verdict):
            verdict = v

    kdcs, realms = set(), set()
    counts = {'as-req': 0, 'as-rep': 0, 'tgs-req': 0, 'tgs-rep': 0, 'krb-error': 0}
    nopreauth_clients = set()          # cnames that sent an AS-REQ without pre-auth
    etype_nosupp = 0

    for e in krb_events:
        counts[e['kind']] = counts.get(e['kind'], 0) + 1
        if e.get('kdc'):
            kdcs.add(e['kdc'])
        if e.get('realm'):
            realms.add(e['realm'])
        cname = '/'.join(e['cname']) if e['cname'] else ''
        sname = '/'.join(e['sname']) if e['sname'] else ''
        et = e['etypes']
        has_aes = any(x in _KRB_AES for x in et)
        weak = [x for x in et if x in _KRB_WEAK]

        # A request offering only weak etypes (no AES at all) is an AES-stripped
        # downgrade — client-side AES disabled or an on-path etype strip.
        only_weak = bool(et) and not has_aes and all(x in _KRB_WEAK for x in et)

        if e['kind'] == 'as-req':
            preauth = _KRB_PA_ENC_TIMESTAMP in e['padata']
            if not preauth and cname:
                nopreauth_clients.add(cname)
            # No pre-auth + RC4 requested is the AS-REP-roasting request signature.
            if not preauth and any(x in _KRB_RC4 for x in et):
                bump('asrep-roast')
                findings.append({'type': 'asrep-roast', 'principal': cname,
                                 'etypes': _krb_etype_names(et)})
                reasons.append(
                    f"AS-REP roast: AS-REQ for '{cname or '?'}' with no pre-auth "
                    f"requesting RC4 — the account likely has 'do not require "
                    f"Kerberos preauthentication'; its AS-REP is an offline-crackable "
                    f"hash (Rubeus/GetNPUsers). Require pre-auth on every account")
            elif only_weak:
                bump('krb-downgrade')
                findings.append({'type': 'downgrade', 'principal': cname,
                                 'etypes': _krb_etype_names(et)})
                reasons.append(
                    f"Downgrade: AS-REQ for '{cname or '?'}' offers only weak "
                    f"encryption ({', '.join(_krb_etype_names(et))}) with no AES — AES "
                    f"appears stripped/disabled on the client")
        elif e['kind'] == 'tgs-req':
            is_service = sname and not sname.lower().startswith('krbtgt')
            if is_service and et and any(x in _KRB_RC4 for x in et) and not has_aes:
                bump('kerberoast')
                findings.append({'type': 'kerberoast', 'principal': cname,
                                 'sname': sname, 'etypes': _krb_etype_names(et)})
                reasons.append(
                    f"Kerberoast: TGS-REQ for service '{sname}' forcing RC4 (etype 23, "
                    f"no AES offered) — the returned service ticket is encrypted with "
                    f"the service account's RC4 key and crackable offline "
                    f"(Rubeus/GetUserSPNs). Set AES-only + a long managed password on "
                    f"the account")
            elif is_service and weak:
                bump('krb-exposure')
                findings.append({'type': 'weak-etype', 'sname': sname,
                                 'etypes': _krb_etype_names(et)})
                reasons.append(
                    f"TGS-REQ for '{sname}' still offers weak encryption "
                    f"({', '.join(_krb_etype_names(weak))}) alongside AES — legacy "
                    f"etypes remain enabled and can be forced by a roaster")
            elif only_weak:                              # TGT (krbtgt) request, AES-less
                bump('krb-downgrade')
                findings.append({'type': 'downgrade', 'principal': cname,
                                 'sname': sname, 'etypes': _krb_etype_names(et)})
                reasons.append(
                    f"Downgrade: TGS-REQ for '{sname or '?'}' offers only weak "
                    f"encryption ({', '.join(_krb_etype_names(et))}) with no AES — AES "
                    f"appears stripped/disabled on the client")
        elif e['kind'] in ('as-rep', 'tgs-rep'):
            re_ = e['rep_etype']
            if e['kind'] == 'as-rep' and cname and cname in nopreauth_clients:
                bump('asrep-roast')
                findings.append({'type': 'asrep-roast', 'principal': cname,
                                 'etypes': _krb_etype_names([re_] if re_ else [])})
                reasons.append(
                    f"AS-REP roast: the KDC returned an AS-REP for '{cname}' whose "
                    f"AS-REQ carried no pre-auth — the encrypted part is an "
                    f"offline-crackable hash")
            if re_ in _KRB_RC4:
                bump('krb-downgrade')
                findings.append({'type': 'downgrade', 'principal': cname,
                                 'etypes': _krb_etype_names([re_])})
                reasons.append(
                    f"Downgrade: the KDC issued an RC4 ({_KRB_ETYPE_NAMES.get(re_)}) "
                    f"ticket to '{cname or '?'}' — weak encryption in real use; "
                    f"enable/enforce AES on the account and KDC")
            elif re_ in _KRB_DES:
                bump('krb-downgrade')
                findings.append({'type': 'downgrade', 'principal': cname,
                                 'etypes': _krb_etype_names([re_])})
                reasons.append(
                    f"Downgrade: the KDC issued a DES/3DES ({_KRB_ETYPE_NAMES.get(re_)})"
                    f" ticket to '{cname or '?'}' — broken encryption; disable DES and "
                    f"enforce AES")
        elif e['kind'] == 'krb-error':
            if e['error_code'] == 14:                    # KDC_ERR_ETYPE_NOSUPP
                etype_nosupp += 1

    if etype_nosupp:
        reasons.append(
            f"{etype_nosupp} KDC_ERR_ETYPE_NOSUPP error(s) — a client requested an "
            f"encryption type the KDC would not grant (possible etype probing)")

    known_kdcs = set(baseline.get('kdcs') or [])
    known_realms = set(baseline.get('krb_realms') or [])
    learned = False
    if learn and 'kdcs' not in baseline and (kdcs or realms):
        baseline['kdcs'] = sorted(kdcs)
        baseline['krb_realms'] = sorted(realms)
        known_kdcs, known_realms = set(kdcs), set(realms)
        learned = True

    advisories = []
    if krb_events:
        advisories.append(
            "Kerberos hardening: set msDS-SupportedEncryptionTypes to AES-only "
            "(remove RC4/DES) on accounts and DCs, require Kerberos pre-authentication "
            "on every account, and give service accounts (gMSA) long random passwords "
            "so a captured RC4 ticket can't be cracked.")

    return {
        'verdict': verdict,
        'reasons': reasons,
        'learned': learned,
        'advisories': advisories,
        'kerberos': {
            'verdict': verdict,
            'kdcs': [{'ip': ip, 'known': ip in known_kdcs} for ip in sorted(kdcs)],
            'realms': sorted(realms),
            'new_kdc': sorted(kdcs - known_kdcs) if known_kdcs else [],
            'counts': counts,
            'findings': findings[:24],
            'errors': counts.get('krb-error', 0),
        },
    }


# Unified severity across the SMB/name-res and Kerberos verdict vocabularies, so one
# combined banner can show the worst finding from either leg.
_SMB_SEVERITY = {
    'clean': 0, 'name-exposure': 2, 'smbv1-offered': 3, 'krb-exposure': 3,
    'krb-downgrade': 4, 'spoof-conflict': 5, 'smbv1-active': 6, 'poisoning': 7,
    'asrep-roast': 7, 'kerberoast': 8,
}


def _smb_worse_verdict(a, b):
    return a if _SMB_SEVERITY.get(a, 0) >= _SMB_SEVERITY.get(b, 0) else b


def _smb_capture(interface, seconds):
    """Capture SMB + name-resolution traffic to a temp pcap via tcpdump -w, and return
    (pcap_path, error). Scapy then dissects it (tcpdump can't decode these)."""
    if not _have('tcpdump'):
        return None, 'tcpdump is not installed. Click Install to add it.'
    if not _have_scapy():
        return None, ('python3-scapy is required to parse SMB / name-resolution '
                      'traffic — install Scapy (Detector Self-Test → Install Scapy).')
    bpf = ('(tcp port 445 or tcp port 139) or (udp port 5355 or udp port 5353 or '
           'udp port 137) or (tcp port 88 or udp port 88)')
    import tempfile
    fd, path = tempfile.mkstemp(suffix='.pcap')
    os.close(fd)
    # 2048-byte snaplen: SMB magic + name-res fit easily, and it captures the Kerberos
    # KDC-REQ-BODY (etype list / SPN) even in a TGS-REQ, whose embedded TGT would push
    # those fields past a 512 snaplen. The tolerant DER walker still copes if truncated.
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface, '-nn', '-p',
                '-s', '2048', '-c', '20000', '-w', path, bpf], timeout=seconds + 8)
    if (os.path.getsize(path) <= 24 and res['err']
            and ('permission' in res['err'].lower() or "couldn't" in res['err'].lower()
                 or 'no such device' in res['err'].lower()
                 or 'syntax error' in res['err'].lower())):
        try:
            os.remove(path)
        except OSError:
            pass
        return None, res['err'].strip()[:200]
    return path, None


def do_smb_watch(interface=None, seconds=20, learn=True):
    """Passive SMBv1 + LLMNR/NBT-NS/mDNS-poisoning + Kerberos-downgrade scanner
    (detection-only). One capture; classifies SMBv1 use, Responder-style name-resolution
    poisoning, and Kerberos downgrade / kerberoasting / AS-REP roasting. Learns accepted
    mDNS responders, known SMBv1 hosts, and known KDCs/realms on first run."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 20, 5, 50)

    path, err = _smb_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    try:
        from scapy.all import rdpcap
        packets = rdpcap(path)
    except Exception as e:
        return {'success': False, 'interface': iface,
                'error': f'could not read capture: {type(e).__name__}'}
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    smb_events, nameres = _smb_parse_packets(packets)
    krb_events = _krb_parse_packets(packets)

    with _smb_watch_lock:
        baseline = _smb_watch_load()
        result = _smb_analyze(smb_events, nameres, seconds, baseline, learn=learn)
        krb = _krb_analyze(krb_events, baseline, learn=learn)
        if result.get('learned') or krb.get('learned'):
            _smb_watch_save(baseline)
            result['learned'] = bool(result.get('learned') or krb.get('learned'))

        # Fold the Kerberos leg into the combined result. Overall verdict is the more
        # severe of the SMB/name-res verdict and the Kerberos verdict.
        result['smb_verdict'] = result['verdict']
        result['kerberos'] = krb['kerberos']
        result['verdict'] = _smb_worse_verdict(result['verdict'], krb['verdict'])
        if krb['reasons']:
            base = result['reasons']
            if base == ['No SMB or LLMNR/NBT-NS/mDNS traffic seen on this segment'] or \
               base == ['No SMBv1 and no name-resolution poisoning detected '
                        '(SMB2/3 + legit mDNS only)']:
                base = []
            result['reasons'] = base + krb['reasons']
        result['advisories'] = (result.get('advisories') or []) + krb['advisories']

        if result['verdict'] != 'clean':
            b = _smb_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_SMB_EVENTS_CAP:]
            _smb_watch_save(b)

    result['interface'] = iface
    result['seconds'] = seconds
    result['packet_count'] = len(smb_events) + len(nameres) + len(krb_events)
    result['krb_count'] = len(krb_events)
    return result


def _smb_selftest():
    """Self-test SMB Watch by building real attack packets into a pcap, reading them
    back through the same Scapy parser, and asserting the verdicts (this is the
    end-to-end leg — the tool is Scapy-parsed by construction)."""
    scenarios = []
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import (Ether, IP, UDP, TCP, Raw, wrpcap, rdpcap, DNS, DNSQR,
                               DNSRR)
        from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
        from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse
    except Exception as e:
        return {'success': True, 'scenarios': [],
                'scapy': {'ran': False, 'reason': f'{type(e).__name__}: {e}'}}

    def smb1(cmd, response, server='10.0.0.5'):
        flags = 0x80 if response else 0x00
        body = b'\xffSMB' + bytes([cmd]) + b'\x00\x00\x00\x00' + bytes([flags]) + b'\x00' * 20
        sport, dport = (445, 50000) if response or cmd != 0x72 else (50000, 445)
        # server side uses port 445; client request uses dport 445
        if response:
            ip = IP(src=server, dst='10.0.0.9'); tcp = TCP(sport=445, dport=50000, flags='PA')
        elif cmd == 0x72:
            ip = IP(src='10.0.0.9', dst=server); tcp = TCP(sport=50000, dport=445, flags='PA')
        else:
            ip = IP(src=server, dst='10.0.0.9'); tcp = TCP(sport=445, dport=50000, flags='PA')
        return Ether() / ip / tcp / Raw(b'\x00\x00\x00' + bytes([len(body)]) + body)

    def llmnr_resp(src, name, ip):
        return (Ether() / IP(src=src, dst='10.0.0.9') / UDP(sport=5355, dport=50000)
                / LLMNRResponse(qd=DNSQR(qname=name),
                                an=DNSRR(rrname=name, rdata=ip)))

    def llmnr_query(name):
        return (Ether() / IP(src='10.0.0.9', dst='224.0.0.252')
                / UDP(sport=50000, dport=5355) / LLMNRQuery(qd=DNSQR(qname=name)))

    def nbns_resp(src, name):
        return (Ether() / IP(src=src, dst='10.0.0.9') / UDP(sport=137, dport=137)
                / NBNSQueryResponse(RR_NAME=name))

    def mdns_self(src, name):
        return (Ether() / IP(src=src, dst='224.0.0.251') / UDP(sport=5353, dport=5353)
                / DNS(qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata=src)))

    def run(name, pkts, baseline, expect):
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
            path = tf.name
        wrpcap(path, pkts)
        try:
            smb_e, nr = _smb_parse_packets(rdpcap(path))
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
        res = _smb_analyze(smb_e, nr, 20, dict(baseline or {}), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'events': len(smb_e) + len(nr), 'pass': ok})
        return res

    base = {'mdns_responders': ['10.0.0.20'], 'smbv1_hosts': []}

    # 1. clean: legit mDNS host announcing itself + SMB2 traffic.
    run('clean', [mdns_self('10.0.0.20', 'printer.local'),
                  Ether() / IP(src='10.0.0.5', dst='10.0.0.9')
                  / TCP(sport=445, dport=50000, flags='PA')
                  / Raw(b'\x00\x00\x00\x20\xfeSMB' + b'\x00' * 20)], base, 'clean')
    # 2. poisoning: a host answering LLMNR (Responder) incl. WPAD.
    run('poisoning', [llmnr_resp('10.0.0.66', 'fileserver', '10.0.0.66'),
                      llmnr_resp('10.0.0.66', 'wpad', '10.0.0.66')], base, 'poisoning')
    # 3. poisoning via NBT-NS response.
    run('poisoning-nbtns', [nbns_resp('10.0.0.66', 'FILESERVER')], base, 'poisoning')
    # 4. spoof-conflict: two hosts answer the same LLMNR name differently.
    run('spoof-conflict', [llmnr_resp('10.0.0.5', 'app01', '10.0.0.5'),
                           llmnr_resp('10.0.0.66', 'app01', '10.0.0.66')], base,
        'poisoning')  # both are LLMNR responders -> poisoning outranks conflict
    # 5. smbv1-active: a real SMBv1 tree-connect (cmd 0x75).
    run('smbv1-active', [smb1(0x75, False)], base, 'smbv1-active')
    # 6. smbv1-offered: only a client SMBv1 negotiate request (cmd 0x72, no response).
    run('smbv1-offered', [smb1(0x72, False)], base, 'smbv1-offered')
    # 7. name-exposure: LLMNR queries only, nobody answering.
    run('name-exposure', [llmnr_query('fileserver'), llmnr_query('wpad')], base,
        'name-exposure')

    # 8. parse: fields land correctly.
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
        path = tf.name
    wrpcap(path, [llmnr_resp('10.0.0.66', 'wpad', '10.0.0.66'), smb1(0x72, True)])
    smb_e, nr = _smb_parse_packets(rdpcap(path))
    try:
        os.remove(path)
    except OSError:
        pass
    llmnr_ev = next((e for e in nr if e['proto'] == 'llmnr'), {})
    smb_ev = smb_e[0] if smb_e else {}
    p_ok = (llmnr_ev.get('kind') == 'response' and llmnr_ev.get('name') == 'wpad'
            and llmnr_ev.get('answer') == '10.0.0.66'
            and smb_ev.get('version') == 'v1' and smb_ev.get('response') is True)
    scenarios.append({'name': 'smb-parse', 'expect': 'llmnr-wpad/smbv1-resp',
                      'got': f"name={llmnr_ev.get('name')} v={smb_ev.get('version')}",
                      'pass': p_ok})

    # ---- Kerberos (Part 3): hand-crafted DER through the byte walker + analyzer ----
    # Minimal DER encoders — no scapy Kerberos layer needed, which also lets us build a
    # deliberately truncated TGS-REQ to prove the walker tolerates snaplen cut-offs.
    def _el(n):
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(b)]) + b

    def _tlv(tag, c):
        return bytes([tag]) + _el(len(c)) + c

    def _int(v):
        b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big', signed=v < 0)
        return _tlv(0x02, b)

    def _gs(s):
        return _tlv(0x1b, s.encode())

    def _ctx(n, c):
        return _tlv(0xa0 | n, c)

    def _princ(parts):
        ns = _tlv(0x30, b''.join(_gs(p) for p in parts))
        return _tlv(0x30, _ctx(0, _int(1)) + _ctx(1, ns))

    def _etypes(lst):
        return _tlv(0x30, b''.join(_int(e) for e in lst))

    def as_req(cname, sname, realm, etypes, pa):
        pad = b''.join(_tlv(0x30, _ctx(1, _int(t)) + _ctx(2, _tlv(0x04, b'\x00')))
                       for t in pa)
        body = _tlv(0x30, _ctx(0, _tlv(0x03, b'\x00' * 5)) + _ctx(1, _princ(cname))
                    + _ctx(2, _gs(realm)) + _ctx(3, _princ(sname)) + _ctx(7, _int(9))
                    + _ctx(8, _etypes(etypes)))
        inner = _ctx(1, _int(5)) + _ctx(2, _int(10)) \
            + (_ctx(3, _tlv(0x30, pad)) if pad else b'') + _ctx(4, body)
        return _tlv(0x6a, _tlv(0x30, inner))

    def tgs_req(sname, realm, etypes, tgt=800):
        body = _tlv(0x30, _ctx(0, _tlv(0x03, b'\x00' * 5)) + _ctx(2, _gs(realm))
                    + _ctx(3, _princ(sname)) + _ctx(7, _int(9))
                    + _ctx(8, _etypes(etypes)))
        pad = _tlv(0x30, _tlv(0x30, _ctx(1, _int(1))          # big PA-TGS-REQ (a TGT)
                    + _ctx(2, _tlv(0x04, b'\x00' * tgt))))
        inner = _ctx(1, _int(5)) + _ctx(2, _int(12)) + _ctx(3, pad) + _ctx(4, body)
        return _tlv(0x6c, _tlv(0x30, inner))

    def as_rep(cname, realm, etype):
        ep = _ctx(6, _tlv(0x30, _ctx(0, _int(etype)) + _ctx(2, _tlv(0x04, b'\x00' * 8))))
        inner = _ctx(0, _int(5)) + _ctx(1, _int(11)) + _ctx(3, _gs(realm)) \
            + _ctx(4, _princ(cname)) + _ctx(5, _tlv(0x61, _tlv(0x30, b''))) + ep
        return _tlv(0x6b, _tlv(0x30, inner))

    def krun(name, raws, expect):
        evs = [e for e in (_krb_parse_message(r) for r in raws) if e]
        for e in evs:                                    # attach a KDC for realism
            e.setdefault('kdc', '10.0.0.1')
        res = _krb_analyze(evs, {}, learn=False)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'events': len(evs), 'pass': ok})
        return res

    # clean: AES request with pre-auth, AES ticket back.
    krun('krb-clean', [as_req(['alice'], ['krbtgt', 'CORP'], 'CORP', [18, 17], [2]),
                       as_rep(['alice'], 'CORP', 18)], 'clean')
    # kerberoast: TGS-REQ for a service SPN forcing RC4-only.
    krun('krb-kerberoast', [tgs_req(['MSSQLSvc', 'db01.corp'], 'CORP', [23])],
         'kerberoast')
    # asrep-roast: no-preauth AS-REQ requesting RC4.
    krun('krb-asrep-roast', [as_req(['svc_web'], ['krbtgt', 'CORP'], 'CORP', [23], [])],
         'asrep-roast')
    # downgrade: KDC hands back an RC4 ticket for a normally-pre-authing client.
    krun('krb-downgrade', [as_req(['bob'], ['krbtgt', 'CORP'], 'CORP', [18], [2]),
                           as_rep(['bob'], 'CORP', 23)], 'krb-downgrade')
    # exposure: service TGS-REQ still offering RC4 alongside AES.
    krun('krb-exposure', [tgs_req(['HTTP', 'web01.corp'], 'CORP', [18, 23])],
         'krb-exposure')

    # krb-parse: a TGS-REQ whose etype/SPN sit past a 400-byte truncation still yields
    # the message kind, and the full packet yields the SPN + RC4 etype.
    full = tgs_req(['MSSQLSvc', 'db01.corp'], 'CORP', [23], tgt=900)
    tev, fev = _krb_parse_message(full[:400]), _krb_parse_message(full)
    kp_ok = (tev and tev['kind'] == 'tgs-req' and fev
             and fev['sname'] == ['MSSQLSvc', 'db01.corp'] and fev['etypes'] == [23])
    scenarios.append({'name': 'krb-parse', 'expect': 'tgs-req/MSSQLSvc/rc4',
                      'got': f"trunc={tev and tev['kind']} sname={fev and fev['sname']}",
                      'pass': bool(kp_ok)})

    passed = all(s['pass'] for s in scenarios)
    scapy_result = {'ran': True, 'pass': passed,
                    'scenarios_run': len(scenarios)}
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# IS-IS Watch: passive IS-IS routing-security scanner (detection-only)
# --------------------------------------------------------------------------
# IS-IS (ISO/IEC 10589) is the third interior gateway protocol alongside OSPF and
# EIGRP, and the one that dominates ISP / service-provider and data-center cores. It
# is architecturally unusual: it runs *directly on L2* (ISO CLNS, LLC DSAP 0xFE) — not
# over IP — so IP ACLs don't touch it, and its only real protection is the TLV-10
# authentication (cleartext password or HMAC-MD5). On a broadcast LAN its PDUs go to
# the AllL1ISs (01:80:c2:00:00:14) and AllL2ISs (01:80:c2:00:00:15) multicast MACs:
#   IIH  (Hello, PDU 15/16/17)  — forms adjacencies
#   LSP  (Link State PDU 18/20) — carries the topology + reachable prefixes
#   CSNP/PSNP (24-27)           — database sync
# Without authentication any host on the segment can form an adjacency and inject LSPs
# with attractive metrics to blackhole or MITM traffic (the IS-IS analogue of OSPF LSA
# injection). tcpdump fully decodes IS-IS — system-ids, areas, the Authentication TLV,
# the reachable prefixes in LSPs, and the dynamic-hostname TLV (#137) that maps a
# system-id to a router name — so this passive scanner sees injection directly and can
# name the routers. It never sends an IS-IS PDU. What it flags:
#   * injection    — an LSP from a system-id not in the baseline, or a new / re-homed
#     reachable prefix (topology poisoning).
#   * rogue-router — a new IS-IS speaker (system-id) sending hellos, not in baseline.
#   * storm        — an IIH/LSP flood by rate.
#   * anomaly      — a duplicate system-id from two MACs (spoof), or a new area address.
#   * weak-auth    — a PDU with no Authentication TLV, or a cleartext password.
_ISIS_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'data', 'isis_watch.json')
_isis_watch_lock = threading.Lock()
_ISIS_EVENTS_CAP = 200
_ISIS_STORM_RATE = 25           # IS-IS PDUs/s above this (with volume) == flood
# LSP sequence number this close to the 0xFFFFFFFF wrap is the classic seq-number
# attack: force the real owner to purge + re-originate from seq 1.
_ISIS_SEQ_HIGH = 0xFFFFFF00
_ISIS_SRC_RE = re.compile(r'^([0-9a-fA-F:]{17})\s*>\s*'
                          r'(01:80:c2:00:00:1[45])')
_ISIS_PDU_RE = re.compile(r'\b(L1|L2|p2p)\s+(Lan IIH|IIH|LSP|CSNP|PSNP)')
_ISIS_SRCID_RE = re.compile(r'source-id:\s*([0-9a-fA-F.]+)')
_ISIS_LSPID_RE = re.compile(r'lsp-id:\s*([0-9a-fA-F.\-]+),\s*seq:\s*(0x[0-9a-fA-F]+)')
# Remaining Lifetime on the lsp-id line; 0 == a purge (LSP deletion / blackhole).
_ISIS_LIFETIME_RE = re.compile(r'lifetime:?\s*(\d+)\s*s')
_ISIS_AREA_RE = re.compile(r'Area address \(length: \d+\):\s*([0-9a-fA-F.]+)')
_ISIS_HOST_RE = re.compile(r'Hostname:\s*(\S+)')
_ISIS_PFX_RE = re.compile(r'IP(?:v4|v6) prefix:\s*([0-9a-fA-F:.]+/\d+),.*?Metric:\s*(\d+)')


def _isis_sysid_of_lsp(lspid):
    """System-id (first three dotted groups) of an LSP-ID like 0000.0000.0001.00-00."""
    return '.'.join((lspid or '').split('.')[:3]) or None


def _parse_isis_capture(output):
    """Parse `tcpdump -e -t -v` text over IS-IS into per-PDU events. Block-structured:
    a header line (`<src> > <AllISs-mac>, 802.3, ... IS-IS (0x83)`) starts a PDU whose
    type line (`L1 Lan IIH` / `L2 LSP` / ...) and TLVs (area/auth/hostname/prefix)
    follow indented."""
    events = []
    cur = None
    for raw in output.splitlines():
        line = raw.strip()
        m = _ISIS_SRC_RE.match(line)
        if m and 'IS-IS' in line:
            if cur:
                events.append(cur)
            cur = {'src_mac': m.group(1).lower(), 'dst': m.group(2),
                   'level': None, 'kind': None, 'source_id': None, 'lsp_id': None,
                   'seq': None, 'areas': [], 'auth_present': False, 'auth': None,
                   'hostname': None, 'prefixes': [], 'lifetime': None,
                   'overload': False}
            continue
        if cur is None:
            continue
        p = _ISIS_PDU_RE.search(line)
        if p and cur['kind'] is None:
            lvl = p.group(1)
            cur['level'] = 1 if lvl == 'L1' else (2 if lvl == 'L2' else None)
            t = p.group(2)
            cur['kind'] = ('iih' if 'IIH' in t else 'lsp' if t == 'LSP'
                           else 'csnp' if t == 'CSNP' else 'psnp' if t == 'PSNP'
                           else 'unknown')
        sid = _ISIS_SRCID_RE.search(line)
        if sid:
            cur['source_id'] = sid.group(1)
        lsp = _ISIS_LSPID_RE.search(line)
        if lsp:
            cur['lsp_id'] = lsp.group(1)
            cur['seq'] = lsp.group(2)
        lt = _ISIS_LIFETIME_RE.search(line)
        if lt and cur['lifetime'] is None:
            cur['lifetime'] = int(lt.group(1))
        # tcpdump renders the LSP overload (OL) bit in the type block, e.g.
        # "Flags: [ L2 IS, Overload bit set ]".
        if 'overload' in line.lower():
            cur['overload'] = True
        ar = _ISIS_AREA_RE.search(line)
        if ar and ar.group(1) not in cur['areas']:
            cur['areas'].append(ar.group(1))
        if 'Authentication TLV' in line:
            cur['auth_present'] = True
        elif 'simple text password' in line:
            cur['auth'] = 'cleartext'
        elif 'HMAC' in line:
            cur['auth'] = 'hmac'
        hn = _ISIS_HOST_RE.search(line)
        if hn:
            cur['hostname'] = hn.group(1)
        pf = _ISIS_PFX_RE.search(line)
        if pf:
            cur['prefixes'].append({'pfx': pf.group(1), 'metric': int(pf.group(2))})
    if cur:
        events.append(cur)
    # Attribute a stable system-id to every event (LSPs carry it in the lsp-id).
    for e in events:
        e['system_id'] = e['source_id'] or _isis_sysid_of_lsp(e['lsp_id'])
    return [e for e in events if e['system_id']]


def _isis_watch_load():
    try:
        with open(_ISIS_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _isis_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_ISIS_WATCH_PATH), exist_ok=True)
        tmp = _ISIS_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _ISIS_WATCH_PATH)
    except OSError:
        pass


def do_isis_baseline(action='get'):
    """Manage the learned IS-IS baseline (trusted routers + advertised prefixes)."""
    with _isis_watch_lock:
        if action == 'reset':
            _isis_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _isis_watch_load()
        return {'success': True, 'baseline': {
            'routers': sorted((b.get('routers') or {}).keys()),
            'prefixes': sorted((b.get('prefixes') or {}).keys())}}


def _isis_analyze(events, seconds, baseline, learn=True):
    """Pure classifier over parsed IS-IS events. Separated from capture for the
    self-test. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))

    routers = {}
    prefixes = {}
    noauth_any = False
    for e in events:
        sid = e['system_id']
        r = routers.setdefault(sid, {
            'system_id': sid, 'hostname': None, 'areas': set(), 'levels': set(),
            'macs': set(), 'kinds': set(), 'auth': set(), 'count': 0})
        r['count'] += 1
        if e['hostname']:
            r['hostname'] = e['hostname']
        for a in e['areas']:
            r['areas'].add(a)
        if e['level']:
            r['levels'].add(e['level'])
        if e['src_mac']:
            r['macs'].add(e['src_mac'])
        if e['kind']:
            r['kinds'].add(e['kind'])
        # An IIH/LSP with no Authentication TLV, or a cleartext password, is weak.
        if e['kind'] in ('iih', 'lsp'):
            if not e['auth_present'] or e['auth'] == 'cleartext':
                r['auth'].add(e['auth'] or 'none')
                noauth_any = True
            else:
                r['auth'].add(e['auth'])
        if e['kind'] == 'lsp':
            for p in e['prefixes']:
                prefixes.setdefault(p['pfx'], {
                    'pfx': p['pfx'], 'origin': sid, 'metric': p['metric']})

    known = dict(baseline.get('routers') or {})
    base_prefixes = dict(baseline.get('prefixes') or {})
    had_baseline = bool(known) or bool(base_prefixes)

    def _name(sid):
        r = routers.get(sid)
        hn = (r['hostname'] if r else None) or (known.get(sid) or {}).get('hostname')
        return f"{hn} ({sid})" if hn else sid

    learned = False
    if learn and not had_baseline and routers:
        baseline['routers'] = {
            s: {'areas': sorted(r['areas']), 'hostname': r['hostname'],
                'levels': sorted(r['levels'])}
            for s, r in routers.items()}
        baseline['prefixes'] = {
            p: {'origin': d['origin']} for p, d in prefixes.items()}
        learned = True
        known = dict(baseline['routers'])
        base_prefixes = dict(baseline['prefixes'])
        had_baseline = True

    PRIORITY = ['injection', 'rogue-router', 'storm', 'anomaly', 'weak-auth', 'clean']
    verdict = 'clean'
    reasons = []

    def bump(v):
        nonlocal verdict
        if PRIORITY.index(v) < PRIORITY.index(verdict):
            verdict = v

    # LSP injection: new prefix, or a known prefix re-homed to a different originator.
    if had_baseline:
        for p in sorted(prefixes):
            d = prefixes[p]
            base = base_prefixes.get(p)
            if base is None:
                bump('injection')
                reasons.append(
                    f"IS-IS LSP INJECTION: prefix {p} advertised by {_name(d['origin'])} "
                    f"is not in the baseline — a forged LSP that can blackhole or MITM "
                    f"traffic to it")
            elif base.get('origin') and d['origin'] != base['origin']:
                bump('injection')
                reasons.append(
                    f"IS-IS PREFIX RE-HOMED: {p} is now originated by "
                    f"{_name(d['origin'])} (was {_name(base['origin'])}) — an LSP "
                    f"hijack steering traffic to {p}")

    # Rogue routers (new system-ids sending hellos/LSPs).
    for sid in sorted(routers):
        if had_baseline and sid not in known:
            bump('rogue-router')
            r = routers[sid]
            area = ', '.join(sorted(r['areas'])) or '?'
            reasons.append(
                f"Rogue IS-IS speaker {_name(sid)} (area {area}, "
                f"L{'/'.join(str(x) for x in sorted(r['levels'])) or '?'}) — not in "
                f"the baseline; a new router forming adjacencies on this segment")

    # Anomalies: duplicate system-id across MACs (spoof), or a new area on a known router.
    for sid in sorted(routers):
        r = routers[sid]
        if len(r['macs']) > 1:
            bump('anomaly')
            reasons.append(
                f"IS-IS system-id {_name(sid)} seen from {len(r['macs'])} different "
                f"MACs ({', '.join(sorted(r['macs']))}) — a duplicate system-id / "
                f"adjacency spoof")
        base = known.get(sid)
        if base:
            new_areas = [a for a in r['areas'] if a not in (base.get('areas') or [])]
            if new_areas:
                bump('anomaly')
                reasons.append(
                    f"IS-IS router {_name(sid)} is advertising a new area address "
                    f"{', '.join(new_areas)} (baseline: "
                    f"{', '.join(base.get('areas') or []) or 'none'}) — area/topology "
                    f"change or a crafted hello")

    # LSP-level attacks: purge (lifetime 0), overload bit, sequence-number wrap.
    # Dedupe reasons per system so a re-flood doesn't spam the snapshot.
    _purged, _overloaded, _seqhi = set(), set(), set()
    for e in events:
        if e['kind'] != 'lsp':
            continue
        sid = e['system_id']
        if e.get('lifetime') == 0 and sid not in _purged:
            _purged.add(sid)
            bump('injection')
            reasons.append(
                f"IS-IS LSP PURGE: {_name(sid)} LSP {e.get('lsp_id') or ''} has "
                f"Remaining Lifetime 0 — an LSP deletion/blackhole (a forged purge "
                f"wipes a router's LSP from every database in the area)")
        if e.get('overload') and sid not in _overloaded:
            _overloaded.add(sid)
            bump('anomaly')
            reasons.append(
                f"IS-IS OVERLOAD bit set by {_name(sid)} — signals 'do not transit "
                f"through me'; a forged OL bit steers traffic off the router (or is an "
                f"unplanned overload/maintenance state)")
        try:
            seqv = int(e['seq'], 16) if e.get('seq') else 0
        except (TypeError, ValueError):
            seqv = 0
        if seqv >= _ISIS_SEQ_HIGH and sid not in _seqhi:
            _seqhi.add(sid)
            bump('anomaly')
            reasons.append(
                f"IS-IS LSP sequence number {e.get('seq')} from {_name(sid)} is near "
                f"the 0xFFFFFFFF wrap — a sequence-number attack forcing the real owner "
                f"to purge and re-originate")

    # Mixed authentication: a system seen both authenticated and unauthenticated —
    # an attacker's un-keyed PDUs racing the real router's keyed ones (or a
    # mid-rollout key mismatch).
    for sid in sorted(routers):
        a = routers[sid]['auth']
        if ('hmac' in a) and (a & {'none', 'cleartext'}):
            bump('anomaly')
            reasons.append(
                f"IS-IS system {_name(sid)} seen BOTH authenticated and "
                f"unauthenticated (mixed-auth) — a spoofed/un-keyed PDU alongside the "
                f"real router's keyed ones")

    # Weak / no authentication.
    if noauth_any:
        bump('weak-auth')
        reasons.append(
            "IS-IS PDUs seen with no Authentication TLV or a cleartext password — no "
            "HMAC protection. This is what lets a forged LSP win; configure IS-IS "
            "authentication (key-chain / hmac-md5) at both levels on every interface")

    # Flooding.
    rate = round(len(events) / seconds, 2)
    if len(events) > 100 and rate > _ISIS_STORM_RATE:
        bump('storm')
        reasons.append(
            f"IS-IS flood: {rate} PDUs/s — a hello/LSP storm (churn or a DoS against "
            f"the routing process)")

    advisories = []
    if routers:
        advisories.append(
            "Authenticate IS-IS (hmac-md5 key-chain at both L1 and L2), set edge "
            "interfaces passive, and — because IS-IS rides directly on L2 — restrict "
            "which access ports may carry it. Alert on any new system-id, new area, or "
            "new/re-homed prefix.")

    def _pub_router(r):
        return {'system_id': r['system_id'], 'hostname': r['hostname'],
                'areas': sorted(r['areas']),
                'levels': sorted(r['levels']), 'kinds': sorted(r['kinds']),
                'macs': sorted(r['macs']),
                'auth': ('hmac' if r['auth'] == {'hmac'} else
                         ('none/cleartext' if (r['auth'] & {'none', 'cleartext'})
                          else (sorted(r['auth'])[0] if r['auth'] else 'n/a'))),
                'count': r['count'], 'baseline': r['system_id'] in known}

    def _pub_prefix(p, d):
        base = base_prefixes.get(p)
        status = 'known' if base else ('new' if had_baseline else 'learned')
        if base and base.get('origin') and d['origin'] != base['origin']:
            status = 're-homed'
        return {'pfx': p, 'origin': d['origin'], 'origin_name': _name(d['origin']),
                'metric': d['metric'], 'status': status}

    if reasons:
        summary = reasons
    elif not routers:
        summary = ['No IS-IS traffic seen — no IS-IS on this segment']
    else:
        summary = ['All IS-IS routers and advertised prefixes match the trusted baseline']

    return {
        'success': True,
        'verdict': verdict,
        'reasons': summary,
        'learned': learned,
        'router_count': len(routers),
        'prefix_count': len(prefixes),
        'packet_count': len(events),
        'rate': rate,
        'routers': [_pub_router(routers[s]) for s in sorted(routers)],
        'prefixes': [_pub_prefix(p, prefixes[p]) for p in sorted(prefixes)],
        'advisories': advisories,
    }


def _isis_capture(interface, seconds):
    """One passive tcpdump window over IS-IS PDUs -> (raw, error). Uses -e for the
    sender MAC; the BPF covers the AllL1ISs + AllL2ISs multicast MACs."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    bpf = 'ether dst 01:80:c2:00:00:14 or ether dst 01:80:c2:00:00:15'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface, '-e',
                '-nn', '-t', '-v', '-s', '512', '-c', '20000', bpf],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()
                                   or 'syntax error' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_isis_watch(interface=None, seconds=20, learn=True):
    """Passive IS-IS routing-security scanner (detection-only). Captures IS-IS for a
    few seconds and classifies: injection / rogue-router / storm / anomaly / weak-auth
    / clean. Learns the trusted routers + advertised prefixes on first run."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 20, 5, 50)

    text, err = _isis_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    events = _parse_isis_capture(text)

    with _isis_watch_lock:
        baseline = _isis_watch_load()
        result = _isis_analyze(events, seconds, baseline, learn=learn)
        if result.get('learned'):
            _isis_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _isis_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_ISIS_EVENTS_CAP:]
            _isis_watch_save(b)

    result['interface'] = iface
    result['seconds'] = seconds
    return result


def _isis_selftest():
    """Self-test the IS-IS detectors with synthetic captures, plus a Scapy end-to-end
    leg (craft a real IIH + LSP-with-prefix -> pcap -> tcpdump -e -> parse)."""
    scenarios = []

    def _hdr(srcmac, level, length=54):
        mac = '14' if level == 1 else '15'
        return (f"{srcmac} > 01:80:c2:00:00:{mac}, 802.3, length {length + 3}: LLC, "
                f"dsap OSI (0xfe) Individual, ssap OSI (0xfe) Command, ctrl 0x03: "
                f"OSI NLPID IS-IS (0x83): length {length}")

    def _auth(kind):
        if kind == 'hmac':
            return ["\t    Authentication TLV #10, length: 17",
                    "\t      HMAC-MD5 password: <redacted>"]
        if kind == 'cleartext':
            return ["\t    Authentication TLV #10, length: 7",
                    "\t      simple text password: secret"]
        return []

    def iih(srcmac, sysid, level=2, area='49.0001', auth='hmac', hostname=None):
        lines = [_hdr(srcmac, level),
                 f"\tL{level} Lan IIH, hlen: 27, v: 1, pdu-v: 1, sys-id-len: 6 (0), "
                 f"max-area: 3 (0)",
                 f"\t  source-id: {sysid},  holding time: 30s, Flags: [Level {level}]",
                 f"\t  lan-id:    {sysid}.01, Priority: 64, PDU length: 54",
                 f"\t    Area address(es) TLV #1, length: 4",
                 f"\t      Area address (length: 3): {area}"]
        lines += _auth(auth)
        if hostname:
            lines += [f"\t    Hostname TLV #137, length: {len(hostname)}",
                      f"\t      Hostname: {hostname}"]
        return "\n".join(lines)

    def lsp(srcmac, sysid, level=2, prefixes=(), auth='hmac', hostname=None, seq=0x10,
            lifetime=1199, overload=False):
        flags = f"L{level} IS" + (", Overload bit set" if overload else "")
        lines = [_hdr(srcmac, level),
                 f"\tL{level} LSP, hlen: 27, v: 1, pdu-v: 1, sys-id-len: 6 (0), "
                 f"max-area: 3 (0)",
                 f"\t  lsp-id: {sysid}.00-00, seq: {seq:#010x}, lifetime:  {lifetime}s",
                 f"\t  chksum: 0x1771 (correct), PDU length: 49, Flags: [ {flags} ]"]
        lines += _auth(auth)
        for (pfx, metric) in prefixes:
            lines += [f"\t    Extended IPv4 Reachability TLV #135, length: 8",
                      f"\t      IPv4 prefix:      {pfx}, Distribution: up, "
                      f"Metric: {metric}"]
        if hostname:
            lines += [f"\t    Hostname TLV #137, length: {len(hostname)}",
                      f"\t      Hostname: {hostname}"]
        return "\n".join(lines)

    def run(name, text, seconds, baseline, expect):
        events = _parse_isis_capture(text)
        res = _isis_analyze(events, seconds, dict(baseline or {}), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'events': len(events), 'pass': ok})
        return res

    base = {'routers': {'0000.0000.0001': {'areas': ['49.0001'],
                                           'hostname': 'core-rtr-1', 'levels': [2]}},
            'prefixes': {'10.1.0.0/24': {'origin': '0000.0000.0001'}}}

    # 1. clean: known router (hmac) re-advertising the known prefix.
    run('clean', iih('00:11:22:33:44:55', '0000.0000.0001', auth='hmac',
                     hostname='core-rtr-1') + "\n"
        + lsp('00:11:22:33:44:55', '0000.0000.0001', auth='hmac',
              prefixes=[('10.1.0.0/24', 10)]), 20, base, 'clean')
    # 2. injection: known router advertises a NEW prefix.
    run('injection', lsp('00:11:22:33:44:55', '0000.0000.0001', auth='hmac',
                         prefixes=[('10.66.66.0/24', 10)]), 20, base, 'injection')
    # 3. injection via re-home: known prefix now from a different originator.
    run('re-home', iih('de:ad:be:ef:00:01', '0000.0000.0009', auth='hmac') + "\n"
        + lsp('de:ad:be:ef:00:01', '0000.0000.0009', auth='hmac',
              prefixes=[('10.1.0.0/24', 5)]), 20, base, 'injection')
    # 4. rogue-router: a brand-new system-id speaking IS-IS (authed, no LSP).
    run('rogue-router', iih('de:ad:be:ef:00:02', '0000.0000.0666', auth='hmac'), 20,
        base, 'rogue-router')
    # 5. anomaly: duplicate system-id from two different MACs.
    run('anomaly-dup', iih('00:11:22:33:44:55', '0000.0000.0001', auth='hmac') + "\n"
        + iih('de:ad:be:ef:00:03', '0000.0000.0001', auth='hmac'), 20, base, 'anomaly')
    # 6. weak-auth: known router + prefix, but no Authentication TLV.
    run('weak-auth', lsp('00:11:22:33:44:55', '0000.0000.0001', auth='none',
                         prefixes=[('10.1.0.0/24', 10)]), 20, base, 'weak-auth')
    # 6b. lsp-purge: known router LSP with Remaining Lifetime 0 (blackhole).
    run('lsp-purge', lsp('00:11:22:33:44:55', '0000.0000.0001', auth='hmac',
                         prefixes=[('10.1.0.0/24', 10)], lifetime=0), 20, base, 'injection')
    # 6c. lsp-overload: known router sets the OL bit (traffic steering/denial).
    run('lsp-overload', lsp('00:11:22:33:44:55', '0000.0000.0001', auth='hmac',
                            prefixes=[('10.1.0.0/24', 10)], overload=True), 20, base,
        'anomaly')
    # 6d. seq-anomaly: LSP sequence number near the 0xFFFFFFFF wrap.
    run('seq-anomaly', lsp('00:11:22:33:44:55', '0000.0000.0001', auth='hmac',
                           prefixes=[('10.1.0.0/24', 10)], seq=0xFFFFFFF0), 20, base,
        'anomaly')
    # 6e. auth-mixed: same system authed (IIH hmac) and unauthed (LSP none).
    run('auth-mixed', iih('00:11:22:33:44:55', '0000.0000.0001', auth='hmac') + "\n"
        + lsp('00:11:22:33:44:55', '0000.0000.0001', auth='none',
              prefixes=[('10.1.0.0/24', 10)]), 20, base, 'anomaly')
    # 7. parse: source-id, area, cleartext auth, hostname, LSP prefix.
    pev = _parse_isis_capture(
        iih('00:11:22:33:44:55', '0000.0000.0001', area='49.0001', auth='cleartext',
            hostname='core-rtr-1') + "\n"
        + lsp('00:11:22:33:44:55', '0000.0000.0001', prefixes=[('10.66.66.0/24', 10)]))
    iih_ev = next((e for e in pev if e['kind'] == 'iih'), {})
    lsp_ev = next((e for e in pev if e['kind'] == 'lsp'), {})
    p_ok = (iih_ev.get('system_id') == '0000.0000.0001'
            and iih_ev.get('areas') == ['49.0001']
            and iih_ev.get('auth') == 'cleartext'
            and iih_ev.get('hostname') == 'core-rtr-1'
            and lsp_ev.get('prefixes') == [{'pfx': '10.66.66.0/24', 'metric': 10}])
    scenarios.append({'name': 'isis-parse', 'expect': 'sysid/area/cleartext/host/pfx',
                      'got': f"auth={iih_ev.get('auth')} host={iih_ev.get('hostname')}",
                      'pass': p_ok})
    # parse: Remaining Lifetime + overload flag off the LSP.
    pev2 = _parse_isis_capture(lsp('00:11:22:33:44:55', '0000.0000.0001',
                                   prefixes=[('10.1.0.0/24', 10)], lifetime=0,
                                   overload=True))
    lsp2 = next((e for e in pev2 if e['kind'] == 'lsp'), {})
    p2_ok = lsp2.get('lifetime') == 0 and lsp2.get('overload') is True
    scenarios.append({'name': 'isis-parse-lsp-flags',
                      'expect': 'lifetime=0/overload=True',
                      'got': f"lifetime={lsp2.get('lifetime')} overload={lsp2.get('overload')}",
                      'pass': p2_ok})

    # Scapy end-to-end: real IIH (no auth) + LSP with a prefix -> tcpdump -> parse.
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import Dot3, LLC, wrpcap
        import scapy.contrib.isis as ISIS
        if _have('tcpdump'):
            pkts = [
                (Dot3(dst='01:80:c2:00:00:15', src='de:ad:be:ef:00:01')
                 / LLC(dsap=0xfe, ssap=0xfe, ctrl=3) / ISIS.ISIS_CommonHdr()
                 / ISIS.ISIS_L2_LAN_Hello(
                     sourceid='0000.0000.0009', lanid='0000.0000.0009.01',
                     tlvs=[ISIS.ISIS_AreaTlv(
                         areas=[ISIS.ISIS_AreaEntry(areaid='49.0009')])])),
                (Dot3(dst='01:80:c2:00:00:15', src='de:ad:be:ef:00:01')
                 / LLC(dsap=0xfe, ssap=0xfe, ctrl=3) / ISIS.ISIS_CommonHdr()
                 / ISIS.ISIS_L2_LSP(
                     lspid='0000.0000.0009.00-00', seqnum=0x10,
                     tlvs=[ISIS.ISIS_ExtendedIpReachabilityTlv(
                         pfxs=[ISIS.ISIS_ExtendedIpPrefix(pfx='10.66.66.0/24',
                                                          metric=10)])]))]
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, pkts)
            res = _run(['tcpdump', '-e', '-nn', '-t', '-v', '-r', pcap_path], timeout=10)
            evs = _parse_isis_capture(res['out'])
            base2 = {'routers': {'0000.0000.0001': {'areas': ['49.0001'],
                                                    'hostname': None, 'levels': [2]}},
                     'prefixes': {'10.1.0.0/24': {'origin': '0000.0000.0001'}}}
            cls = _isis_analyze(evs, 20, dict(base2), learn=False)
            hostm = next((e for e in evs if e['kind'] == 'iih'), {})
            lspm = next((e for e in evs if e['kind'] == 'lsp'), {})
            ok = (hostm.get('system_id') == '0000.0000.0009'
                  and lspm.get('prefixes') == [{'pfx': '10.66.66.0/24', 'metric': 10}]
                  and cls['verdict'] == 'injection')
            scapy_result = {'ran': True, 'sysid': hostm.get('system_id'),
                            'prefix': (lspm.get('prefixes') or [{}])[0].get('pfx'),
                            'verdict': cls['verdict'], 'pass': ok,
                            'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and (not scapy_result.get('ran')
                                                    or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# STP/BPDU Watch: passive spanning-tree security scanner (detection-only)
# --------------------------------------------------------------------------
# Spanning Tree (802.1D STP / 802.1w RSTP / 802.1s MSTP, and Cisco PVST+/Rapid-PVST+)
# prevents L2 loops by electing a *root bridge* — the switch with the numerically
# lowest Bridge ID (priority + MAC) — and blocking redundant links back toward it.
# BPDUs (Bridge Protocol Data Units) carry the election; they are multicast in the
# clear (IEEE 01:80:c2:00:00:00 / PVST+ 01:00:0c:cc:cc:cd) with no authentication. So
# an attacker who sends a BPDU claiming a *superior* root (priority 0 — the Yersinia
# "claim root role" attack) wins the election, becomes the root bridge, and the tree
# reconverges to pull traffic through them (subnet-wide MITM). BPDU/TCN floods force
# constant reconvergence (DoS) and MAC-table flushing (which aids sniffing). The
# defenses are BPDU Guard (kill the port on any BPDU) on edge ports and Root Guard
# toward downstream switches. This scanner is PASSIVE: one short capture of the BPDUs,
# classified against a learned baseline of the root(s) and legitimate bridges. It
# never sends a BPDU. What it flags:
#   * root-hijack      — a BPDU advertising a root superior to the baseline root
#     (lower priority, or equal priority + lower MAC): a root-bridge takeover.
#   * rogue-bridge     — a new bridge (Bridge-ID MAC) speaking STP, not in the baseline.
#   * bpdu-flood       — an elevated BPDU rate: a reconvergence-storm DoS.
#   * topology-change  — TCN / TC-flag churn: forced MAC-table flushing / instability.
_STP_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'data', 'stp_watch.json')
_stp_watch_lock = threading.Lock()
_STP_EVENTS_CAP = 200
_STP_FLOOD_RATE = 30            # BPDUs/s above this (with volume) == flood
_STP_TCN_CHURN = 3              # TCN/TC events in a window above this == instability
_STP_SRC_RE = re.compile(r'^([0-9a-fA-F:]{17})\s*>\s*'
                         r'(01:80:c2:00:00:00|01:00:0c:cc:cc:cd)')
_STP_TYPE_RE = re.compile(r'STP 802\.1(\w)')
_STP_BRIDGE_RE = re.compile(r'bridge-id ([0-9a-fA-F]{4})\.([0-9a-fA-F:]{17})')
_STP_ROOT_RE = re.compile(r'root-id ([0-9a-fA-F]{4})\.([0-9a-fA-F:]{17}),'
                          r'\s*root-pathcost (\d+)')
_STP_FLAGS_RE = re.compile(r'Flags \[([^\]]*)\]')


def _mac_int(mac):
    try:
        return int(mac.replace(':', ''), 16)
    except (ValueError, AttributeError):
        return 0


def _parse_stp_capture(output):
    """Parse `tcpdump -e -t -v` text over BPDUs into events. Each BPDU is a header
    line (`<src> > <group-mac>, 802.3, ... STP 802.1d, Config, Flags [...], bridge-id
    PRIO.MAC.PORT`) optionally followed by a `root-id PRIO.MAC, root-pathcost N` line.
    TCN BPDUs are a single `STP 802.1d, Topology Change` line."""
    events = []
    cur = None
    for raw in output.splitlines():
        line = raw.strip()
        if 'STP 802.1' in line:
            if cur:
                events.append(cur)
            src = _STP_SRC_RE.match(line)
            t = _STP_TYPE_RE.search(line)
            tletter = t.group(1).lower() if t else 'd'
            is_pvst = ('pid PVST' in line
                       or (src and src.group(2) == '01:00:0c:cc:cc:cd'))
            if is_pvst:
                proto = 'pvst+'
            elif tletter == 'w':
                proto = 'rstp'
            elif tletter == 's':
                proto = 'mstp'
            else:
                proto = 'stp'
            is_tcn = 'Topology Change' in line and 'Config' not in line
            fl = _STP_FLAGS_RE.search(line)
            flagset = ([f.strip() for f in fl.group(1).split(',') if f.strip()]
                       if fl else [])
            br = _STP_BRIDGE_RE.search(line)
            cur = {'src': src.group(1).lower() if src else None,
                   'dst': src.group(2) if src else None,
                   'proto': proto, 'kind': 'tcn' if is_tcn else 'config',
                   'tc': 'Topology change' in flagset, 'flags': flagset,
                   'bridge_prio': int(br.group(1), 16) if br else None,
                   'bridge_mac': br.group(2).lower() if br else None,
                   'root_prio': None, 'root_mac': None, 'pathcost': None,
                   'port_role': None, 'vlan': None}
            continue
        if cur is None:
            continue
        rm = _STP_ROOT_RE.search(line)
        if rm:
            cur['root_prio'] = int(rm.group(1), 16)
            cur['root_mac'] = rm.group(2).lower()
            cur['pathcost'] = int(rm.group(3))
            cur['vlan'] = cur['root_prio'] & 0x0FFF
            pr = re.search(r'port-role (\w+)', line)
            if pr:
                cur['port_role'] = pr.group(1)
    if cur:
        events.append(cur)
    return [e for e in events if e['src']]


def _stp_watch_load():
    try:
        with open(_STP_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _stp_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_STP_WATCH_PATH), exist_ok=True)
        tmp = _STP_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _STP_WATCH_PATH)
    except OSError:
        pass


def do_stp_baseline(action='get'):
    """Manage the learned STP baseline (per-instance root bridge + legitimate bridges)."""
    with _stp_watch_lock:
        if action == 'reset':
            _stp_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _stp_watch_load()
        return {'success': True, 'baseline': {
            'roots': b.get('roots') or {}, 'bridges': b.get('bridges') or []}}


def _stp_analyze(events, seconds, baseline, learn=True):
    """Pure classifier over parsed BPDU events. Separated from capture for the
    self-test. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))

    instances = {}
    bridges = {}
    tcn_count = 0
    tc_count = 0
    for e in events:
        if e['bridge_mac']:
            b = bridges.setdefault(e['bridge_mac'], {
                'mac': e['bridge_mac'], 'proto': e['proto'], 'count': 0,
                'roles': set()})
            b['count'] += 1
            if e['port_role']:
                b['roles'].add(e['port_role'])
        if e['kind'] == 'tcn':
            tcn_count += 1
        if e['tc']:
            tc_count += 1
        if e['root_prio'] is not None:
            key = str(e['vlan'] if e['vlan'] is not None else 0)
            inst = instances.setdefault(key, {
                'vlan': int(key), 'proto': e['proto'], 'best': None,
                'claimer': None, 'root_macs': set()})
            inst['root_macs'].add(e['root_mac'])
            cand = (e['root_prio'], _mac_int(e['root_mac']))
            if inst['best'] is None or cand < inst['best']:
                inst['best'] = cand
                inst['claimer'] = {'prio': e['root_prio'], 'mac': e['root_mac'],
                                   'by': e['bridge_mac'] or e['src']}

    known_roots = dict(baseline.get('roots') or {})
    known_bridges = set(baseline.get('bridges') or [])
    had_baseline = bool(known_roots) or bool(known_bridges)

    learned = False
    if learn and not had_baseline and (instances or bridges):
        baseline['roots'] = {
            k: {'prio': inst['claimer']['prio'], 'mac': inst['claimer']['mac']}
            for k, inst in instances.items() if inst['claimer']}
        baseline['bridges'] = sorted(bridges.keys())
        learned = True
        known_roots = dict(baseline['roots'])
        known_bridges = set(baseline['bridges'])
        had_baseline = True

    PRIORITY = ['root-hijack', 'rogue-bridge', 'bpdu-flood', 'topology-change', 'clean']
    verdict = 'clean'
    reasons = []

    def bump(v):
        nonlocal verdict
        if PRIORITY.index(v) < PRIORITY.index(verdict):
            verdict = v

    # Root hijack: an advertised root superior to (or displacing) the baseline root.
    if had_baseline:
        for k in sorted(instances, key=lambda x: int(x)):
            inst = instances[k]
            base = known_roots.get(k)
            if not base or not inst['claimer']:
                continue
            cand = inst['best']
            base_t = (base['prio'], _mac_int(base['mac']))
            if cand < base_t:
                bump('root-hijack')
                c = inst['claimer']
                where = f"VLAN {inst['vlan']}" if inst['proto'] == 'pvst+' else \
                    (f"instance {inst['vlan']}" if inst['vlan'] else "the CIST")
                reasons.append(
                    f"ROOT HIJACK on {where}: {c['by']} is advertising root "
                    f"{c['prio']}.{c['mac']} — superior to the baseline root "
                    f"{base['prio']}.{base['mac']}. It wins the election and becomes "
                    f"the root bridge, pulling traffic through it (L2 MITM). Enable "
                    f"Root Guard / BPDU Guard")

    # Rogue bridges (new senders).
    if had_baseline:
        for mac in sorted(bridges):
            if mac not in known_bridges:
                bump('rogue-bridge')
                reasons.append(
                    f"New STP bridge {mac} ({bridges[mac]['proto'].upper()}) — not in "
                    f"the baseline; an unexpected switch (or a spoofed bridge) is "
                    f"participating in spanning tree on this segment")

    # BPDU flood (reconvergence-storm DoS).
    rate = round(len(events) / seconds, 2)
    if len(events) > 100 and rate > _STP_FLOOD_RATE:
        bump('bpdu-flood')
        reasons.append(
            f"BPDU flood: {rate} BPDUs/s (normal is ~1 per bridge every 2s) — a "
            f"spanning-tree storm forcing constant reconvergence (DoS)")

    # Topology-change churn (MAC-table flushing).
    if (tcn_count + tc_count) > _STP_TCN_CHURN:
        bump('topology-change')
        reasons.append(
            f"Topology-change churn: {tcn_count} TCN + {tc_count} TC-flagged BPDUs in "
            f"{seconds}s — repeated topology changes flush the MAC tables (traffic "
            f"floods, which aids sniffing) and can be a TCN-flood attack")

    advisories = []
    if instances or bridges:
        advisories.append(
            "Harden spanning tree: BPDU Guard + PortFast on every edge/access port "
            "(any BPDU there err-disables the port), Root Guard on ports toward "
            "downstream switches (rejects superior BPDUs), and set your real root/backup "
            "root to a low priority (0/4096) so a rogue can't outbid them.")

    def _pub_inst(k, inst):
        base = known_roots.get(k)
        c = inst['claimer'] or {}
        status = 'known'
        if base:
            if (c.get('prio'), _mac_int(c.get('mac', ''))) < (base['prio'],
                                                              _mac_int(base['mac'])):
                status = 'hijacked'
        elif had_baseline:
            status = 'new'
        else:
            status = 'learned'
        return {'vlan': inst['vlan'], 'proto': inst['proto'],
                'root_prio': c.get('prio'), 'root_mac': c.get('mac'),
                'advertised_by': c.get('by'),
                'baseline_root': (f"{base['prio']}.{base['mac']}" if base else None),
                'status': status}

    if reasons:
        summary = reasons
    elif not (instances or bridges):
        summary = ['No BPDUs seen — no spanning tree on this segment (an access port '
                   'with BPDU Guard, or an isolated link)']
    else:
        summary = ['Spanning-tree root(s) and bridges match the trusted baseline']

    return {
        'success': True,
        'verdict': verdict,
        'reasons': summary,
        'learned': learned,
        'bridge_count': len(bridges),
        'instance_count': len(instances),
        'packet_count': len(events),
        'rate': rate,
        'tcn_count': tcn_count,
        'tc_count': tc_count,
        'instances': [_pub_inst(k, instances[k])
                      for k in sorted(instances, key=lambda x: int(x))],
        'bridges': [{'mac': m, 'proto': bridges[m]['proto'],
                     'roles': sorted(bridges[m]['roles']), 'count': bridges[m]['count'],
                     'baseline': m in known_bridges} for m in sorted(bridges)],
        'advisories': advisories,
    }


def _stp_capture(interface, seconds):
    """One passive tcpdump window over BPDUs -> (raw, error). Uses -e for the sender
    MAC; the BPF covers IEEE (01:80:c2:00:00:00) and Cisco PVST+ (01:00:0c:cc:cc:cd)."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    bpf = '(ether dst 01:80:c2:00:00:00) or (ether dst 01:00:0c:cc:cc:cd)'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface, '-e',
                '-nn', '-t', '-v', '-s', '128', '-c', '20000', bpf],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()
                                   or 'syntax error' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_stp_watch(interface=None, seconds=20, learn=True):
    """Passive spanning-tree / BPDU security scanner (detection-only). BPDUs are ~2s
    apart, so a slightly longer window. Learns the root(s) + legitimate bridges on
    first run."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 20, 5, 50)

    text, err = _stp_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    events = _parse_stp_capture(text)

    with _stp_watch_lock:
        baseline = _stp_watch_load()
        result = _stp_analyze(events, seconds, baseline, learn=learn)
        if result.get('learned'):
            _stp_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _stp_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_STP_EVENTS_CAP:]
            _stp_watch_save(b)

    result['interface'] = iface
    result['seconds'] = seconds
    return result


def _stp_selftest():
    """Self-test the STP/BPDU detectors with synthetic captures, plus a Scapy
    end-to-end leg (craft a real superior-root BPDU -> pcap -> tcpdump -e -> parse)."""
    scenarios = []

    def cfg(src, root_prio, root_mac, bridge_prio=None, bridge_mac=None, flags='none',
            pathcost=0, pvst=False):
        bridge_prio = bridge_prio if bridge_prio is not None else root_prio
        bridge_mac = bridge_mac or src
        dst = '01:00:0c:cc:cc:cd' if pvst else '01:80:c2:00:00:00'
        pid = 'oui Cisco (0x00000c), pid PVST (0x010b), length 41: ' if pvst else ''
        return (f"{src} > {dst}, 802.3, length 49: LLC, dsap STP (0x42) Individual, "
                f"ssap STP (0x42) Command, ctrl 0x03: {pid}STP 802.1d, Config, "
                f"Flags [{flags}], bridge-id {bridge_prio:04x}.{bridge_mac}.0000, "
                f"length 35\n"
                f"\tmessage-age 1.00s, max-age 20.00s, hello-time 2.00s, "
                f"forwarding-delay 15.00s\n"
                f"\troot-id {root_prio:04x}.{root_mac}, root-pathcost {pathcost}")

    def tcn(src):
        return (f"{src} > 01:80:c2:00:00:00, 802.3, length 7: LLC, dsap STP (0x42) "
                f"Individual, ssap STP (0x42) Command, ctrl 0x03: STP 802.1d, "
                f"Topology Change")

    def run(name, text, seconds, baseline, expect):
        events = _parse_stp_capture(text)
        res = _stp_analyze(events, seconds, dict(baseline or {}), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'events': len(events), 'pass': ok})
        return res

    # Baseline: root of the CIST is 8000.00:11:22:33:44:55 (priority 32768), one bridge.
    base = {'roots': {'0': {'prio': 0x8000, 'mac': '00:11:22:33:44:55'}},
            'bridges': ['00:11:22:33:44:55']}

    # 1. clean: the known root re-advertising itself.
    run('clean', cfg('00:11:22:33:44:55', 0x8000, '00:11:22:33:44:55'), 20, base,
        'clean')
    # 2. root-hijack: a new bridge claims root with priority 0 (superior).
    run('root-hijack', cfg('de:ad:be:ef:00:01', 0x0000, 'de:ad:be:ef:00:01'), 20, base,
        'root-hijack')
    # 3. rogue-bridge: a new bridge advertising the *existing* root (not superior).
    run('rogue-bridge', cfg('de:ad:be:ef:00:02', 0x8000, '00:11:22:33:44:55',
                            bridge_mac='de:ad:be:ef:00:02'), 20, base, 'rogue-bridge')
    # 4. topology-change: known bridge + several TCNs (MAC-flush churn).
    run('topology-change',
        cfg('00:11:22:33:44:55', 0x8000, '00:11:22:33:44:55') + "\n"
        + "\n".join(tcn('00:11:22:33:44:55') for _ in range(4)), 20, base,
        'topology-change')
    # 5. bpdu-flood: a burst of BPDUs from the known root.
    run('bpdu-flood',
        "\n".join(cfg('00:11:22:33:44:55', 0x8000, '00:11:22:33:44:55')
                  for _ in range(200)), 3, base, 'bpdu-flood')
    # 6. pvst+ parse: per-VLAN BPDU, VLAN encoded in the priority low bits.
    pev = _parse_stp_capture(cfg('00:11:22:33:44:55', 0x8064, '00:11:22:33:44:55',
                                 bridge_prio=0x8064, pvst=True))
    p_ok = (len(pev) == 1 and pev[0]['proto'] == 'pvst+' and pev[0]['vlan'] == 100
            and pev[0]['root_prio'] == 0x8064)
    scenarios.append({'name': 'pvst-parse', 'expect': 'pvst+/vlan100',
                      'got': f"{pev[0]['proto'] if pev else '-'}/vlan"
                             f"{pev[0]['vlan'] if pev else '?'}", 'pass': p_ok})
    # 7. parse: TC flag + fields.
    fev = _parse_stp_capture(cfg('00:11:22:33:44:55', 0x8000, '00:11:22:33:44:55',
                                 flags='Topology change, Topology change ACK'))
    f_ok = (len(fev) == 1 and fev[0]['tc'] is True
            and fev[0]['root_mac'] == '00:11:22:33:44:55'
            and fev[0]['bridge_prio'] == 0x8000)
    scenarios.append({'name': 'flags-parse', 'expect': 'tc=True',
                      'got': f"tc={fev[0]['tc'] if fev else '?'}", 'pass': f_ok})

    # Scapy end-to-end: craft a real superior-root (priority 0) BPDU.
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import Dot3, LLC, STP, wrpcap
        if _have('tcpdump'):
            pkt = (Dot3(dst='01:80:c2:00:00:00', src='de:ad:be:ef:00:01')
                   / LLC(dsap=0x42, ssap=0x42, ctrl=3)
                   / STP(rootid=0, rootmac='de:ad:be:ef:00:01', bridgeid=0,
                         bridgemac='de:ad:be:ef:00:01', pathcost=0))
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, [pkt])
            res = _run(['tcpdump', '-e', '-nn', '-t', '-v', '-r', pcap_path], timeout=10)
            evs = _parse_stp_capture(res['out'])
            e = evs[0] if evs else {}
            base2 = {'roots': {'0': {'prio': 0x8000, 'mac': '00:11:22:33:44:55'}},
                     'bridges': ['00:11:22:33:44:55']}
            cls = _stp_analyze(evs, 20, dict(base2), learn=False)
            ok = (e.get('root_prio') == 0 and e.get('src') == 'de:ad:be:ef:00:01'
                  and cls['verdict'] == 'root-hijack')
            scapy_result = {'ran': True, 'root_prio': e.get('root_prio'),
                            'src': e.get('src'), 'verdict': cls['verdict'], 'pass': ok,
                            'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and (not scapy_result.get('ran')
                                                    or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# DTP Watch: passive Dynamic Trunking Protocol / VLAN-hopping scanner (Cisco)
# --------------------------------------------------------------------------
# DTP (Cisco proprietary, group MAC 01:00:0c:cc:cc:cc, SNAP OUI 0x00000c PID 0x2004)
# auto-negotiates whether a switch port becomes an 802.1Q/ISL *trunk*. A port left in
# the default `dynamic auto`/`dynamic desirable` mode will happily form a trunk with
# anything that sends DTP "desirable" frames — so an attacker plugs in, forges DTP
# desirable (Yersinia "enable trunking"), the access port trunks to them, and they now
# see and inject into *every VLAN* (the classic switch-spoofing VLAN hop). The fix is
# `switchport nonegotiate` + hard `access`/`trunk` on every port; DTP should never be
# seen on an access segment. This scanner is PASSIVE: one short capture of the DTP
# frames, no DTP is ever transmitted. It flags:
#   * vlan-hop           — trunk-forming DTP (on/desirable/auto) from a NEW speaker:
#     an active switch-spoofing / VLAN-hop attempt.
#   * trunk-negotiation  — trunk-forming DTP present (port isn't `nonegotiate`, so it
#     is exploitable) even from a known speaker.
#   * dtp-enabled        — DTP frames present at all (DTP not disabled). Advisory.
_DTP_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'data', 'dtp_watch.json')
_dtp_watch_lock = threading.Lock()
_DTP_EVENTS_CAP = 200
# DTP Trunk Administrative Status (low 3 bits of the Status octet). on/desirable/auto
# all mean the port will form (or force) a trunk; off means it won't.
_DTP_TAS = {1: 'on', 2: 'off', 3: 'desirable', 4: 'auto'}
_DTP_FORMING = {1, 3, 4}
_DTP_HDR_RE = re.compile(r'^([0-9a-fA-F:]{17})\s*>\s*01:00:0c:cc:cc:cc')


def _dtp_status(byte):
    """(label, forming?) for a DTP Status octet."""
    if byte is None:
        return ('unknown', False)
    tas = byte & 0x07
    return (_DTP_TAS.get(tas, f'0x{byte:02x}'), tas in _DTP_FORMING)


def _parse_dtp_capture(output):
    """Parse `tcpdump -e -t -v` text over DTP frames into events. Each DTP frame is a
    header line (`<src-mac> > 01:00:0c:cc:cc:cc, 802.3, ... DTPv1`) followed by
    indented Domain/Status/DTP type/Neighbor TLV lines."""
    events = []
    cur = None
    for raw in output.splitlines():
        line = raw.strip()
        m = _DTP_HDR_RE.match(line)
        if m and 'DTPv' in line:
            if cur:
                events.append(cur)
            ver = re.search(r'DTPv(\d+)', line)
            cur = {'src': m.group(1).lower(),
                   'version': int(ver.group(1)) if ver else None,
                   'domain': None, 'status': None, 'dtptype': None, 'neighbor': None}
            continue
        if cur is None:
            continue
        if line.startswith('Domain'):
            d = re.search(r'length \d+,\s*(.*)$', line)
            cur['domain'] = (d.group(1).strip() or None) if d else None
        elif line.startswith('Status'):
            s = re.search(r'0x([0-9a-fA-F]+)\s*$', line)
            cur['status'] = int(s.group(1), 16) if s else None
        elif line.startswith('DTP type'):
            s = re.search(r'0x([0-9a-fA-F]+)\s*$', line)
            cur['dtptype'] = int(s.group(1), 16) if s else None
        elif line.startswith('Neighbor'):
            s = re.search(r'([0-9a-fA-F:]{17})\s*$', line)
            cur['neighbor'] = s.group(1).lower() if s else None
    if cur:
        events.append(cur)
    return [e for e in events if e['src']]


def _dtp_watch_load():
    try:
        with open(_DTP_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _dtp_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_DTP_WATCH_PATH), exist_ok=True)
        tmp = _DTP_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _DTP_WATCH_PATH)
    except OSError:
        pass


def do_dtp_baseline(action='get'):
    """Manage the learned DTP baseline (trusted DTP speaker MACs — the real switches)."""
    with _dtp_watch_lock:
        if action == 'reset':
            _dtp_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _dtp_watch_load()
        return {'success': True, 'baseline': {'speakers': b.get('speakers') or []}}


def _dtp_analyze(events, seconds, baseline, learn=True):
    """Pure classifier over parsed DTP events. Separated from capture for the
    self-test. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))

    speakers = {}
    for e in events:
        sp = speakers.setdefault(e['src'], {
            'src': e['src'], 'count': 0, 'status': 'unknown', 'forming': False,
            'domain': None, 'neighbor': None})
        sp['count'] += 1
        label, forming = _dtp_status(e['status'])
        sp['status'] = label
        if forming:
            sp['forming'] = True
        if e.get('domain'):
            sp['domain'] = e['domain']
        if e.get('neighbor'):
            sp['neighbor'] = e['neighbor']

    known = set(baseline.get('speakers') or [])
    had_baseline = bool(known)

    learned = False
    if learn and not had_baseline and speakers:
        baseline['speakers'] = sorted(speakers.keys())
        learned = True
        known = set(speakers.keys())
        had_baseline = True

    PRIORITY = ['vlan-hop', 'trunk-negotiation', 'dtp-enabled', 'clean']
    verdict = 'clean'
    reasons = []

    def bump(v):
        nonlocal verdict
        if PRIORITY.index(v) < PRIORITY.index(verdict):
            verdict = v

    # First (learning) run: surface that DTP exists here so the user knows, but a
    # known non-forming switch on later runs is clean (legit trunk infrastructure).
    if learned and speakers:
        bump('dtp-enabled')
    for src in sorted(speakers):
        sp = speakers[src]
        is_new = had_baseline and src not in known
        if sp['forming'] and is_new:
            bump('vlan-hop')
            reasons.append(
                f"VLAN HOP: DTP '{sp['status']}' (trunk-forming) from a NEW speaker "
                f"{src} — a switch-spoofing attempt; if an access port answers this it "
                f"trunks and exposes every VLAN. Set `switchport nonegotiate` + hard "
                f"access mode on that port")
        elif sp['forming']:
            bump('trunk-negotiation')
            reasons.append(
                f"DTP '{sp['status']}' (trunk-forming) from {src} — this segment is "
                f"negotiating trunks; a rogue host could VLAN-hop. Disable DTP with "
                f"`switchport nonegotiate` on access ports")
        elif is_new:
            bump('dtp-enabled')
            reasons.append(
                f"New DTP speaker {src} (status '{sp['status']}') not in the baseline "
                f"— unexpected device speaking DTP on this segment")
    if learned and verdict == 'dtp-enabled' and not reasons:
        reasons.append(
            "DTP is present on this segment — learned the current speaker(s) as the "
            "baseline. DTP should be disabled (`switchport nonegotiate`) on access "
            "ports; only switch↔switch trunk links should speak it")

    if speakers:
        advisories = [
            "Harden against VLAN hopping: `switchport mode access` + `switchport "
            "nonegotiate` on every access port, prune unused VLANs off trunks, and "
            "never use VLAN 1 / the native VLAN for data. DTP should not appear on any "
            "access segment."]
    else:
        advisories = []

    if reasons:
        summary = reasons
    elif not speakers:
        summary = ['No DTP seen — no Dynamic Trunking Protocol on this segment (good; '
                   'means ports are not negotiating trunks here)']
    else:
        summary = ['DTP speakers all match the trusted baseline']

    return {
        'success': True,
        'verdict': verdict,
        'reasons': summary,
        'learned': learned,
        'speaker_count': len(speakers),
        'packet_count': len(events),
        'rate': round(len(events) / seconds, 2),
        'speakers': [{
            'src': s, 'status': sp['status'], 'forming': sp['forming'],
            'domain': sp['domain'], 'neighbor': sp['neighbor'], 'count': sp['count'],
            'baseline': s in known,
        } for s, sp in sorted(speakers.items())],
        'advisories': advisories,
    }


def _dtp_capture(interface, seconds):
    """One passive tcpdump window over DTP frames -> (raw, error). Uses -e so we get
    the sending switch/host MAC; the BPF isolates DTP (PID 0x2004) from the other
    protocols that share the Cisco group MAC (CDP/VTP/UDLD/PAgP)."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    bpf = 'ether dst 01:00:0c:cc:cc:cc and ether[20:2] = 0x2004'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface, '-e',
                '-nn', '-t', '-v', '-s', '128', '-c', '20000', bpf],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()
                                   or 'syntax error' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_dtp_watch(interface=None, seconds=30, learn=True):
    """Passive DTP / VLAN-hopping scanner (detection-only). DTP hellos are ~30s apart,
    so the default window is longer. Learns the trusted DTP speakers on first run."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 30, 5, 65)

    text, err = _dtp_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    events = _parse_dtp_capture(text)

    with _dtp_watch_lock:
        baseline = _dtp_watch_load()
        result = _dtp_analyze(events, seconds, baseline, learn=learn)
        if result.get('learned'):
            _dtp_watch_save(baseline)
        if result['verdict'] not in ('clean', 'dtp-enabled'):
            b = _dtp_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_DTP_EVENTS_CAP:]
            _dtp_watch_save(b)

    result['interface'] = iface
    result['seconds'] = seconds
    return result


def _dtp_selftest():
    """Self-test the DTP detector with synthetic captures, plus a Scapy end-to-end leg
    (craft a real DTP desirable frame -> pcap -> tcpdump -e -> parse)."""
    scenarios = []

    def frame(src, status=0x03, dtptype=0xa5, neighbor=None):
        neighbor = neighbor or src
        return (f"{src} > 01:00:0c:cc:cc:cc, 802.3, length 33: LLC, dsap SNAP (0xaa) "
                f"Individual, ssap SNAP (0xaa) Command, ctrl 0x03: oui Cisco "
                f"(0x00000c), pid DTP (0x2004), length 25: DTPv1, length 25\n"
                f"\tDomain (0x0001) TLV, length 4, \n"
                f"\tStatus (0x0002) TLV, length 5, 0x{status:x}\n"
                f"\tDTP type (0x0003) TLV, length 5, 0x{dtptype:x}\n"
                f"\tNeighbor (0x0004) TLV, length 10, {neighbor}")

    def run(name, text, seconds, baseline, expect):
        events = _parse_dtp_capture(text)
        res = _dtp_analyze(events, seconds, dict(baseline or {}), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'events': len(events), 'pass': ok})
        return res

    base = {'speakers': ['00:11:22:33:44:55']}

    # 1. clean: known switch, DTP 'off' (not forming a trunk).
    run('clean', frame('00:11:22:33:44:55', status=0x02), 30, base, 'clean')
    # 2. vlan-hop: a NEW speaker sending 'desirable' (trunk-forming) — switch spoofing.
    run('vlan-hop', frame('de:ad:be:ef:00:01', status=0x03), 30, base, 'vlan-hop')
    # 3. trunk-negotiation: the known switch is in 'auto' (forming) — port not nonegotiate.
    run('trunk-negotiation', frame('00:11:22:33:44:55', status=0x04), 30, base,
        'trunk-negotiation')
    # 4. dtp-enabled: known switch, DTP 'off' but present — first-run learn (no baseline).
    run('dtp-enabled', frame('00:11:22:33:44:55', status=0x02), 30, None, 'dtp-enabled')
    # 5. parse: fields.
    pev = _parse_dtp_capture(frame('aa:bb:cc:dd:ee:ff', status=0x03,
                                   neighbor='aa:bb:cc:dd:ee:ff'))
    p_ok = (len(pev) == 1 and pev[0]['src'] == 'aa:bb:cc:dd:ee:ff'
            and pev[0]['status'] == 0x03 and pev[0]['neighbor'] == 'aa:bb:cc:dd:ee:ff'
            and _dtp_status(pev[0]['status'])[1] is True)
    scenarios.append({'name': 'dtp-parse', 'expect': 'desirable/forming',
                      'got': _dtp_status(pev[0]['status'] if pev else None)[0],
                      'pass': p_ok})

    # Scapy end-to-end.
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import Dot3, LLC, SNAP, wrpcap
        from scapy.contrib.dtp import DTP, DTPDomain, DTPStatus, DTPType, DTPNeighbor
        if _have('tcpdump'):
            pkt = (Dot3(dst='01:00:0c:cc:cc:cc', src='de:ad:be:ef:00:01')
                   / LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
                   / SNAP(OUI=0x00000c, code=0x2004)
                   / DTP(ver=1, tlvlist=[DTPDomain(domain=b''),
                                         DTPStatus(status=b'\x03'),
                                         DTPType(dtptype=b'\xa5'),
                                         DTPNeighbor(neighbor='de:ad:be:ef:00:01')]))
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, [pkt])
            res = _run(['tcpdump', '-e', '-nn', '-t', '-v', '-r', pcap_path], timeout=10)
            evs = _parse_dtp_capture(res['out'])
            e = evs[0] if evs else {}
            ok = (e.get('src') == 'de:ad:be:ef:00:01' and e.get('status') == 0x03
                  and _dtp_status(e.get('status'))[1] is True)
            scapy_result = {'ran': True, 'src': e.get('src'), 'status': e.get('status'),
                            'pass': ok, 'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and (not scapy_result.get('ran')
                                                    or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# CDP Watch: passive Cisco Discovery Protocol flood / spoof / info-leak scanner
# --------------------------------------------------------------------------
# CDP (Cisco proprietary, group MAC 01:00:0c:cc:cc:cc, SNAP OUI 0x00000c PID
# 0x2000) is on by default on every Cisco device and advertises, unauthenticated,
# to anyone on the wire: the device hostname, full IOS software version, hardware
# platform/model, management IP, native VLAN, VTP domain, voice VLAN and port-ID.
# LLDP Switch Discovery *uses* that to map the network; this Watch looks at the
# same frames as a defender and flags their abuse. Where DTP Watch (same group
# MAC, PID 0x2004) catches VLAN-hop trunk negotiation, CDP Watch flags:
#   * flood        — a spray of CDP frames / distinct device-IDs (Yersinia cdp
#     flood): fills the neighbour table and spikes switch CPU (a DoS).
#   * spoof        — a NEW CDP speaker not in the learned baseline (a rogue device
#     injecting a fake neighbour), including a fake Cisco IP Phone advertising a
#     Voice VLAN — the CDP half of a VoIP-VLAN-hop.
#   * cdp-enabled  — CDP is on here at all: the scan surfaces exactly what it
#     leaks (IOS version → CVEs, model, mgmt IP, native/voice VLAN) so an operator
#     can see the reconnaissance an attacker on that port gets for free.
# This scanner is PASSIVE: it decodes captured CDP, it never transmits CDP. First
# run learns the trusted speakers into data/cdp_watch.json; "Trust current"
# re-learns after a legitimate change.
_CDP_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'data', 'cdp_watch.json')
_cdp_watch_lock = threading.Lock()
_CDP_EVENTS_CAP = 200
_CDP_HDR_RE = re.compile(r'^([0-9a-fA-F:]{17})\s*>\s*01:00:0c:cc:cc:cc')
# CDP hellos are ~60s apart per neighbour, so any sustained rate is a flood.
_CDP_FLOOD_RATE = 10.0
# Yersinia cdp-flood sprays frames with random device-IDs; many distinct IDs in
# one short window is the flood signature even if the raw rate looks modest.
_CDP_FLOOD_IDS = 30


def _cdp_tlv_val(line):
    """Text after the final 'bytes:' / 'byte:' on a CDP TLV line, unquoted."""
    m = re.search(r'byte[s]?:\s*(.*)$', line)
    v = (m.group(1).strip() if m else '')
    return v.strip("'") if v else ''


def _parse_cdp_capture(output):
    """Parse `tcpdump -e -t -v` CDP text into per-frame events. Each frame is a
    header line (`<src> > 01:00:0c:cc:cc:cc, ... pid CDP (0x2000): CDPv2, ...`)
    followed by indented TLV lines (Device-ID, Version, Platform, Address, Native
    VLAN, VTP domain, Port-ID, Voice/appliance VLAN, Management Address)."""
    events = []
    cur = None
    collecting_version = False
    for raw in output.splitlines():
        line = raw.strip()
        m = _CDP_HDR_RE.match(line)
        if m and 'CDPv' in line:
            if cur:
                events.append(cur)
            ver = re.search(r'CDPv(\d+)', line)
            cur = {'src': m.group(1).lower(),
                   'cdpv': int(ver.group(1)) if ver else None,
                   'device_id': None, 'sw_version': None, 'platform': None,
                   'port_id': None, 'native_vlan': None, 'vtp_domain': None,
                   'mgmt_addr': None, 'address': None, 'voice_vlan': None,
                   'capabilities': None}
            collecting_version = False
            continue
        if cur is None:
            continue
        low = line.lower()
        if collecting_version:
            # A multi-line Version String continues on indented lines until the
            # next TLV header (`Name (0xNN)`).
            if re.match(r'^[A-Z][\w /-]*\(0x[0-9a-fA-F]+\)', line):
                collecting_version = False
            elif line:
                cur['sw_version'] = ((cur['sw_version'] + ' ') if cur['sw_version']
                                     else '') + line
                continue
        if low.startswith('device-id'):
            cur['device_id'] = _cdp_tlv_val(line) or None
        elif low.startswith('version string') or low.startswith('software version'):
            v = _cdp_tlv_val(line)
            if v:
                cur['sw_version'] = v
            else:
                collecting_version = True
        elif low.startswith('platform'):
            cur['platform'] = _cdp_tlv_val(line) or None
        elif low.startswith('port-id'):
            cur['port_id'] = _cdp_tlv_val(line) or None
        elif low.startswith('native vlan'):
            nv = re.search(r'byte[s]?:\s*(\d+)', line)
            cur['native_vlan'] = int(nv.group(1)) if nv else None
        elif low.startswith('vtp management domain'):
            cur['vtp_domain'] = _cdp_tlv_val(line) or None
        elif low.startswith('appliance') or 'voice vlan' in low:
            vv = re.search(r'vlan[^0-9]*(\d+)', low)
            cur['voice_vlan'] = int(vv.group(1)) if vv else cur['voice_vlan']
        elif low.startswith('address') and cur['address'] is None:
            a = re.search(r'ipv4 \(\d+\)\s*([0-9.]+)', low)
            cur['address'] = a.group(1) if a else None
        elif low.startswith('management address'):
            a = re.search(r'ipv4 \(\d+\)\s*([0-9.]+)', low)
            cur['mgmt_addr'] = a.group(1) if a else None
        elif low.startswith('capability'):
            c = re.search(r'byte[s]?:.*?:\s*(.*)$', line)
            cur['capabilities'] = (c.group(1).strip() if c else None) or None
    if cur:
        events.append(cur)
    return [e for e in events if e['src']]


def _cdp_watch_load():
    try:
        with open(_CDP_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _cdp_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_CDP_WATCH_PATH), exist_ok=True)
        tmp = _CDP_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _CDP_WATCH_PATH)
    except OSError:
        pass


def do_cdp_baseline(action='get'):
    """Manage the learned CDP baseline (trusted CDP speaker MACs — the real
    switches/phones). action='reset' re-learns on the next scan."""
    with _cdp_watch_lock:
        if action == 'reset':
            _cdp_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _cdp_watch_load()
        return {'success': True, 'baseline': {'speakers': b.get('speakers') or []}}


def _cdp_analyze(events, seconds, baseline, learn=True):
    """Pure classifier over parsed CDP events. Separated from capture for the
    self-test. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))

    speakers = {}
    for e in events:
        sp = speakers.setdefault(e['src'], {
            'src': e['src'], 'count': 0, 'device_id': None, 'sw_version': None,
            'platform': None, 'port_id': None, 'native_vlan': None,
            'vtp_domain': None, 'mgmt_addr': None, 'address': None,
            'voice_vlan': None, 'capabilities': None})
        sp['count'] += 1
        for k in ('device_id', 'sw_version', 'platform', 'port_id', 'native_vlan',
                  'vtp_domain', 'mgmt_addr', 'address', 'voice_vlan', 'capabilities'):
            if e.get(k) is not None:
                sp[k] = e[k]

    known = set(baseline.get('speakers') or [])
    had_baseline = bool(known)
    device_ids = {sp['device_id'] for sp in speakers.values() if sp['device_id']}

    learned = False
    if learn and not had_baseline and speakers:
        baseline['speakers'] = sorted(speakers.keys())
        learned = True
        known = set(speakers.keys())
        had_baseline = True

    PRIORITY = ['flood', 'spoof', 'cdp-enabled', 'clean']
    verdict = 'clean'
    reasons = []

    def bump(v):
        nonlocal verdict
        if PRIORITY.index(v) < PRIORITY.index(verdict):
            verdict = v

    # --- flood: sustained rate or a spray of distinct device-IDs (Yersinia) ---
    rate = round(len(events) / seconds, 2)
    if (rate >= _CDP_FLOOD_RATE and len(events) >= _CDP_FLOOD_RATE * seconds) \
            or len(device_ids) >= _CDP_FLOOD_IDS:
        bump('flood')
        reasons.append(f"CDP flood: {len(events)} frames in {seconds}s ({rate}/s), "
                       f"{len(device_ids)} distinct device-IDs — CDP neighbour-table / "
                       f"CPU exhaustion DoS (e.g. Yersinia cdp flood)")

    for src in sorted(speakers):
        sp = speakers[src]
        is_new = had_baseline and src not in known
        if is_new and verdict != 'flood':
            bump('spoof')
            phone = ((sp['capabilities'] and 'phone' in sp['capabilities'].lower())
                     or sp['voice_vlan'] is not None)
            tail = (f" advertising IP-Phone capability / Voice VLAN "
                    f"{sp['voice_vlan']} — possible VoIP-VLAN-hop (fake phone)"
                    if phone else "")
            reasons.append(
                f"New CDP speaker {src} claiming '{sp['device_id'] or '?'}' "
                f"({sp['platform'] or '?'}) not in the baseline — rogue/spoofed CDP "
                f"neighbour{tail}")

    # --- cdp-enabled / info-leak: surface exactly what CDP hands an attacker ---
    if verdict == 'clean' and learned and speakers:
        bump('cdp-enabled')
    if verdict == 'cdp-enabled' and not reasons:
        leaks = []
        for sp in speakers.values():
            bits = []
            if sp['sw_version']:
                bits.append('IOS/version')
            if sp['mgmt_addr'] or sp['address']:
                bits.append('mgmt IP ' + (sp['mgmt_addr'] or sp['address']))
            if sp['native_vlan'] is not None:
                bits.append(f'native VLAN {sp["native_vlan"]}')
            if sp['voice_vlan'] is not None:
                bits.append(f'voice VLAN {sp["voice_vlan"]}')
            leaks.append(f"{sp['device_id'] or sp['src']} ({sp['platform'] or '?'})"
                         + (': ' + ', '.join(bits) if bits else ''))
        reasons.append(
            "CDP is enabled on this segment — it broadcasts " + '; '.join(leaks) +
            " in clear to anyone on the wire (reconnaissance goldmine). If any of "
            "these ports face users, disable CDP there (`no cdp enable`).")

    advisories = []
    if speakers:
        advisories.append(
            "Disable CDP on access/edge ports (`no cdp enable`; `no cdp run` globally "
            "if unused). CDP is unauthenticated and leaks device model, IOS version "
            "(→ known CVEs), management IP, native/voice VLAN and port-ID to any "
            "listener. Where discovery is needed, prefer LLDP with minimal TLVs.")

    if reasons:
        summary = reasons
    elif not speakers:
        summary = ['No CDP seen — no Cisco Discovery Protocol on this segment']
    else:
        summary = ['CDP speakers all match the trusted baseline']

    return {
        'success': True,
        'verdict': verdict,
        'reasons': summary,
        'learned': learned,
        'speaker_count': len(speakers),
        'packet_count': len(events),
        'rate': rate,
        'speakers': [{
            'src': s, 'device_id': sp['device_id'], 'platform': sp['platform'],
            'sw_version': sp['sw_version'], 'port_id': sp['port_id'],
            'native_vlan': sp['native_vlan'], 'vtp_domain': sp['vtp_domain'],
            'mgmt_addr': sp['mgmt_addr'] or sp['address'],
            'voice_vlan': sp['voice_vlan'], 'count': sp['count'],
            'baseline': s in known,
        } for s, sp in sorted(speakers.items())],
        'advisories': advisories,
    }


def _cdp_capture(interface, seconds):
    """One passive tcpdump window over CDP frames -> (raw, error). Uses -e for the
    sending MAC; the BPF isolates CDP (PID 0x2000) from the other protocols that
    share the Cisco group MAC (DTP/VTP/UDLD/PAgP)."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    bpf = 'ether dst 01:00:0c:cc:cc:cc and ether[20:2] = 0x2000'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface, '-e',
                '-nn', '-t', '-v', '-s', '1500', '-c', '20000', bpf],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()
                                   or 'syntax error' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_cdp_watch(interface=None, seconds=30, learn=True):
    """Passive CDP flood / spoof / info-leak scanner (detection-only). CDP hellos
    are ~60s apart, so the default window is longer. Learns the trusted CDP
    speakers on first run."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 30, 5, 65)

    text, err = _cdp_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    events = _parse_cdp_capture(text)

    with _cdp_watch_lock:
        baseline = _cdp_watch_load()
        result = _cdp_analyze(events, seconds, baseline, learn=learn)
        if result.get('learned'):
            _cdp_watch_save(baseline)
        if result['verdict'] not in ('clean', 'cdp-enabled'):
            b = _cdp_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_CDP_EVENTS_CAP:]
            _cdp_watch_save(b)

    result['interface'] = iface
    result['seconds'] = seconds
    return result


def _cdp_selftest():
    """Self-test the CDP detector with synthetic captures, plus a Scapy end-to-end
    leg (craft a real CDP frame -> pcap -> tcpdump -e -> parse)."""
    scenarios = []

    def frame(src, device_id='Switch1.lab', version='Cisco IOS Software, C3560, '
              'Version 12.2(55)SE', platform='cisco WS-C3560-24TS', port='Fa0/1',
              native=1, vtp='lab', mgmt='10.0.0.1', voice=None,
              caps='Router, L2 Switch'):
        L = [f"{src} > 01:00:0c:cc:cc:cc, 802.3, length 337: LLC, dsap SNAP (0xaa) "
             f"Individual, ssap SNAP (0xaa) Command, ctrl 0x03: oui Cisco "
             f"(0x00000c), pid CDP (0x2000): CDPv2, ttl: 180s, checksum: 0x0000, "
             f"length 319",
             f"\tDevice-ID (0x01), length: {len(device_id)} bytes: '{device_id}'",
             f"\tVersion String (0x05), length: {len(version)} bytes: {version}",
             f"\tPlatform (0x06), length: {len(platform)} bytes: '{platform}'",
             f"\tAddress (0x02), length: 13 bytes: IPv4 (1) {mgmt}",
             f"\tPort-ID (0x03), length: {len(port)} bytes: '{port}'",
             f"\tCapability (0x04), length: 4 bytes: (0x00000029): {caps}",
             f"\tVTP Management Domain (0x09), length: {len(vtp)} bytes: '{vtp}'",
             f"\tNative VLAN ID (0x0a), length: 2 bytes: {native}",
             f"\tManagement Addresses (0x16), length: 13 bytes: IPv4 (1) {mgmt}"]
        if voice is not None:
            L.append(f"\tAppliance VLAN-ID (0x0e), length: 7 bytes: "
                     f"App id 1, vlan: {voice}")
        return "\n".join(L)

    def run(name, text, seconds, baseline, expect):
        events = _parse_cdp_capture(text)
        res = _cdp_analyze(events, seconds, dict(baseline or {}), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'events': len(events), 'pass': ok})
        return res

    base = {'speakers': ['00:11:22:33:44:55']}

    # 1. clean: known switch re-advertising.
    run('clean', frame('00:11:22:33:44:55'), 60, base, 'clean')
    # 2. spoof: a NEW CDP speaker not in baseline.
    run('spoof', frame('de:ad:be:ef:00:01', device_id='rogue'), 60, base, 'spoof')
    # 3. spoof + phone: fake IP phone advertising a Voice VLAN (VoIP-hop recon).
    rp = run('spoof-phone', frame('de:ad:be:ef:00:02', device_id='SEP001122',
             platform='cisco IP Phone 7960', voice=200, caps='Host, Phone'),
             60, base, 'spoof')
    vp_ok = any('VoIP-VLAN-hop' in x for x in rp['reasons'])
    scenarios.append({'name': 'spoof-phone-reason', 'expect': 'voip-hop',
                      'got': 'voip-hop' if vp_ok else 'missing', 'pass': vp_ok})
    # 4. cdp-enabled: first-run learn surfaces the info leak.
    rc = run('cdp-enabled', frame('00:11:22:33:44:55'), 60, None, 'cdp-enabled')
    leak_ok = any('reconnaissance goldmine' in x for x in rc['reasons'])
    scenarios.append({'name': 'cdp-leak-reason', 'expect': 'leak',
                      'got': 'leak' if leak_ok else 'missing', 'pass': leak_ok})
    # 5. flood: a spray of distinct device-IDs (Yersinia).
    flood = "\n".join(frame(f'aa:bb:cc:00:{i//256:02x}:{i%256:02x}',
                            device_id=f'rnd{i}') for i in range(40))
    run('flood', flood, 5, base, 'flood')
    # 6. parse: fields extracted incl. version, native VLAN, mgmt IP.
    pev = _parse_cdp_capture(frame('aa:bb:cc:dd:ee:ff', native=99, mgmt='192.0.2.7'))
    p_ok = (len(pev) == 1 and pev[0]['device_id'] == 'Switch1.lab'
            and pev[0]['native_vlan'] == 99 and pev[0]['mgmt_addr'] == '192.0.2.7'
            and pev[0]['platform'] == 'cisco WS-C3560-24TS'
            and '12.2(55)SE' in (pev[0]['sw_version'] or ''))
    scenarios.append({'name': 'cdp-parse', 'expect': 'id+vlan+ip+ver',
                      'got': str({k: pev[0][k] for k in
                                  ('device_id', 'native_vlan', 'mgmt_addr')}
                                 if pev else None)[:90], 'pass': p_ok})

    # Optional Scapy end-to-end: craft a real CDP frame -> pcap -> tcpdump -e -> parse.
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import Dot3, LLC, SNAP, wrpcap
        from scapy.contrib.cdp import (CDPv2_HDR, CDPMsgDeviceID, CDPMsgPlatform,
                                       CDPMsgPortID, CDPMsgNativeVLAN)
        if _have('tcpdump'):
            pkt = (Dot3(dst='01:00:0c:cc:cc:cc', src='de:ad:be:ef:00:01')
                   / LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
                   / SNAP(OUI=0x00000c, code=0x2000)
                   / CDPv2_HDR(msg=[CDPMsgDeviceID(val=b'rogue-sw'),
                                    CDPMsgPlatform(val=b'cisco WS-C2960'),
                                    CDPMsgPortID(iface=b'Fa0/9'),
                                    CDPMsgNativeVLAN(vlan=1)]))
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, [pkt])
            res = _run(['tcpdump', '-e', '-nn', '-t', '-v', '-r', pcap_path],
                       timeout=10)
            evs = _parse_cdp_capture(res['out'])
            e = evs[0] if evs else {}
            scapy_result = {'ran': True, 'device_id': e.get('device_id'),
                            'platform': e.get('platform'),
                            'pass': bool(evs) and e.get('device_id') == 'rogue-sw',
                            'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as ex:
        scapy_result = {'ran': False, 'reason': f'{type(ex).__name__}: {ex}'}

    passed = all(s['pass'] for s in scenarios) and \
        (not scapy_result.get('ran') or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# VTP Watch: passive VLAN Trunking Protocol bomb / rogue-server scanner
# --------------------------------------------------------------------------
# VTP (Cisco proprietary; same group MAC 01:00:0c:cc:cc:cc as CDP/DTP, SNAP OUI
# 0x00000c, PID 0x2003) synchronises the VLAN database across a VTP domain. Its
# whole security model rests on one 32-bit **configuration revision number**: the
# switch advertising the *highest* revision in the domain wins, and every other
# switch (in server/client mode) overwrites its VLAN database to match. So a
# rogue switch — or a forged Summary Advertisement — carrying the domain name and
# a higher revision silently **rewrites, and can delete, every VLAN across the
# entire domain**: the "VTP bomb", a one-frame domain-wide outage. VTPv1/2 have no
# per-port authentication (only an optional weak MD5 domain password). This
# scanner is PASSIVE: it decodes captured VTP Summary Advertisements, it never
# transmits VTP. It flags:
#   * revision-bomb — a config revision higher than the learned baseline coming
#     from a source that ISN'T the known VTP server: the VLAN-DB-overwrite attack.
#   * rogue-server  — a new VTP speaker, or a different VTP domain name, than the
#     learned baseline (a rogue switch positioned to seize VLAN management).
#   * vtp-enabled   — VTP present / a legit revision bump from the known server.
# First run learns the domain, revision and server into data/vtp_watch.json;
# "Trust current" re-learns after a legitimate VLAN change. NB tcpdump prints the
# config revision in hex ("Config Rev a" == 10).
_VTP_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'data', 'vtp_watch.json')
_vtp_watch_lock = threading.Lock()
_VTP_EVENTS_CAP = 200
_VTP_HDR_RE = re.compile(r'^([0-9a-fA-F:]{17})\s*>\s*01:00:0c:cc:cc:cc')
# A brand-new switch ships revision 0; an attacker sets a high one. Any higher
# revision from a source that isn't the known server is the bomb signal.
_VTP_REV_JUMP = 1


def _parse_vtp_capture(output):
    """Parse `tcpdump -e -t -v` VTP text into per-frame events. The header line
    carries `pid VTP (0x2003) ... VTPv1, Message <type> (0xNN)`; indented lines
    carry `Domain name: <d>, Followers: <n>` and `Config Rev <hex>, Updater <ip>`.
    tcpdump prints the config revision in HEX."""
    events = []
    cur = None
    for raw in output.splitlines():
        line = raw.strip()
        m = _VTP_HDR_RE.match(line)
        if m and 'VTP' in line and 'Message' in line:
            if cur:
                events.append(cur)
            mt = re.search(r'Message\s+(.+?)\s*\(0x([0-9a-fA-F]+)\)', line)
            cur = {'src': m.group(1).lower(),
                   'msgtype': mt.group(1).strip() if mt else None,
                   'msgcode': int(mt.group(2), 16) if mt else None,
                   'domain': None, 'revision': None, 'updater': None,
                   'followers': None}
            continue
        if cur is None:
            continue
        dm = re.search(r'Domain name:\s*(.+?)\s*,', line)
        if dm:
            cur['domain'] = dm.group(1)
        fm = re.search(r'Followers:\s*(\d+)', line)
        if fm:
            cur['followers'] = int(fm.group(1))
        rm = re.search(r'Config Rev\s+([0-9a-fA-F]+)', line)
        if rm:
            cur['revision'] = int(rm.group(1), 16)
        um = re.search(r'Updater\s+([0-9.]+)', line)
        if um:
            cur['updater'] = um.group(1)
    if cur:
        events.append(cur)
    return [e for e in events if e['src']]


def _vtp_watch_load():
    try:
        with open(_VTP_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _vtp_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_VTP_WATCH_PATH), exist_ok=True)
        tmp = _VTP_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _VTP_WATCH_PATH)
    except OSError:
        pass


def do_vtp_baseline(action='get'):
    """Manage the learned VTP baseline (trusted domain(s), config revision, VTP
    server(s)). action='reset' re-learns on the next scan (use after a legitimate
    VLAN-database change)."""
    with _vtp_watch_lock:
        if action == 'reset':
            _vtp_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _vtp_watch_load()
        return {'success': True, 'baseline': {'domains': b.get('domains') or {}}}


def _vtp_analyze(events, seconds, baseline, learn=True):
    """Pure classifier over parsed VTP events. Separated from capture for the
    self-test. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))

    # Aggregate by VTP domain (the config revision is domain-wide).
    domains = {}
    for e in events:
        name = e.get('domain')
        if not name:
            continue
        d = domains.setdefault(name, {'name': name, 'revision': -1,
                                      'updaters': set(), 'srcs': set(),
                                      'msgtypes': set(), 'count': 0})
        d['count'] += 1
        d['srcs'].add(e['src'])
        if e.get('updater'):
            d['updaters'].add(e['updater'])
        if e.get('msgtype'):
            d['msgtypes'].add(e['msgtype'])
        if e.get('revision') is not None and e['revision'] > d['revision']:
            d['revision'] = e['revision']

    base_domains = dict(baseline.get('domains') or {})
    had_baseline = bool(base_domains)

    learned = False
    if learn and not had_baseline and domains:
        baseline['domains'] = {n: {'revision': d['revision'],
                                   'updaters': sorted(d['updaters']),
                                   'speakers': sorted(d['srcs'])}
                               for n, d in domains.items()}
        learned = True
        base_domains = dict(baseline['domains'])
        had_baseline = True

    PRIORITY = ['revision-bomb', 'rogue-server', 'vtp-enabled', 'clean']
    verdict = 'clean'
    reasons = []

    def bump(v):
        nonlocal verdict
        if PRIORITY.index(v) < PRIORITY.index(verdict):
            verdict = v

    if learned and domains:
        bump('vtp-enabled')

    for name in sorted(domains):
        d = domains[name]
        kd = base_domains.get(name)
        if had_baseline and kd is None:
            bump('rogue-server')
            reasons.append(
                f"New VTP domain '{name}' seen from {', '.join(sorted(d['srcs']))} "
                f"— not the baseline domain; a rogue switch advertising VTP can seize "
                f"VLAN management on this segment")
            continue
        if kd is None:
            continue
        base_rev = kd.get('revision', -1)
        known_srcs = set(kd.get('speakers') or [])
        known_upd = set(kd.get('updaters') or [])
        new_src = bool(d['srcs'] - known_srcs)
        new_upd = bool(d['updaters'] - known_upd)

        if d['revision'] > base_rev and (d['revision'] - base_rev) >= _VTP_REV_JUMP:
            if new_src or new_upd:
                bump('revision-bomb')
                who = ', '.join(sorted(d['updaters'] or d['srcs']))
                reasons.append(
                    f"VTP BOMB: config revision in domain '{name}' jumped {base_rev} "
                    f"→ {d['revision']} advertised by {who} (NOT the known VTP server) "
                    f"— a higher revision overwrites the VLAN database across the whole "
                    f"domain and can delete every VLAN (domain-wide outage). Isolate "
                    f"that port now")
            else:
                bump('vtp-enabled')
                reasons.append(
                    f"Config revision in domain '{name}' increased {base_rev} → "
                    f"{d['revision']} from the known VTP server "
                    f"({', '.join(sorted(d['updaters'])) or '?'}) — the VLAN database "
                    f"changed (legitimate if you just edited VLANs; click Trust current "
                    f"to accept the new revision)")
        elif new_src or new_upd:
            bump('rogue-server')
            who = ', '.join(sorted((d['srcs'] - known_srcs)
                                   or (d['updaters'] - known_upd)))
            reasons.append(
                f"New VTP speaker {who} in domain '{name}' not in the baseline — a "
                f"rogue switch that could raise the config revision and overwrite the "
                f"domain's VLANs. Verify it, or set the port/switch to VTP transparent")

    advisories = []
    if domains:
        advisories.append(
            "Neutralise VTP bombs: run switches in `vtp mode transparent` (or VTPv3) "
            "unless you truly need domain-wide VLAN sync, always set a VTP password, "
            "and ALWAYS zero a switch's config-revision (set VTP transparent, or change "
            "the domain name and back) before connecting it — a client/server switch "
            "with a higher revision silently overwrites the entire domain's VLAN "
            "database on connect.")

    if reasons:
        summary = reasons
    elif not domains:
        summary = ['No VTP seen — no VLAN Trunking Protocol advertisements on this '
                   'segment (good; VTP is not exposed here)']
    else:
        summary = ['VTP domain/revision match the trusted baseline']

    return {
        'success': True,
        'verdict': verdict,
        'reasons': summary,
        'learned': learned,
        'domain_count': len(domains),
        'packet_count': len(events),
        'rate': round(len(events) / seconds, 2),
        'domains': [{
            'name': d['name'], 'revision': d['revision'],
            'updaters': sorted(d['updaters']), 'srcs': sorted(d['srcs']),
            'msgtypes': sorted(d['msgtypes']), 'count': d['count'],
            'baseline': d['name'] in base_domains,
            'baseline_revision': (base_domains.get(d['name']) or {}).get('revision'),
        } for _, d in sorted(domains.items())],
        'advisories': advisories,
    }


def _vtp_capture(interface, seconds):
    """One passive tcpdump window over VTP frames -> (raw, error). Uses -e for the
    sending MAC; the BPF isolates VTP (PID 0x2003) from the other protocols that
    share the Cisco group MAC (CDP/DTP/UDLD/PAgP)."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    bpf = 'ether dst 01:00:0c:cc:cc:cc and ether[20:2] = 0x2003'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface, '-e',
                '-nn', '-t', '-v', '-s', '512', '-c', '20000', bpf],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()
                                   or 'syntax error' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_vtp_watch(interface=None, seconds=30, learn=True):
    """Passive VTP bomb / rogue-server scanner (detection-only). VTP Summary
    Advertisements are ~30s apart (plus on every change), so the default window is
    longer. Learns the trusted domain/revision/server on first run."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 30, 5, 65)

    text, err = _vtp_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    events = _parse_vtp_capture(text)

    with _vtp_watch_lock:
        baseline = _vtp_watch_load()
        result = _vtp_analyze(events, seconds, baseline, learn=learn)
        if result.get('learned'):
            _vtp_watch_save(baseline)
        if result['verdict'] not in ('clean', 'vtp-enabled'):
            b = _vtp_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_VTP_EVENTS_CAP:]
            _vtp_watch_save(b)

    result['interface'] = iface
    result['seconds'] = seconds
    return result


def _vtp_selftest():
    """Self-test the VTP detector with synthetic captures, plus a Scapy end-to-end
    leg (craft a real VTP summary advert -> pcap -> tcpdump -e -> parse)."""
    scenarios = []

    def frame(src, domain='LAB', rev=10, updater='10.0.0.1', followers=1,
              msgtype='Summary advertisement', code=0x01):
        return (f"{src} > 01:00:0c:cc:cc:cc, 802.3, length 80: LLC, dsap SNAP (0xaa) "
                f"Individual, ssap SNAP (0xaa) Command, ctrl 0x03: oui Cisco "
                f"(0x00000c), pid VTP (0x2003), length 72: VTPv1, Message {msgtype} "
                f"(0x{code:02x}), length 72\n"
                f"\tDomain name: {domain}, Followers: {followers}\n"
                f"\t  Config Rev {rev:x}, Updater {updater}, Timestamp 0x0 0x0 0x0, "
                f"MD5 digest: 00000000000000000000000000000000")

    def run(name, text, seconds, baseline, expect):
        events = _parse_vtp_capture(text)
        res = _vtp_analyze(events, seconds, dict(baseline or {}), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'events': len(events), 'pass': ok})
        return res

    base = {'domains': {'LAB': {'revision': 10, 'updaters': ['10.0.0.1'],
                                'speakers': ['00:11:22:33:44:55']}}}

    # 1. clean: known server re-advertises the same revision.
    run('clean', frame('00:11:22:33:44:55', rev=10), 30, base, 'clean')
    # 2. revision-bomb: higher revision from a NEW source (the classic VTP bomb).
    rb = run('revision-bomb', frame('de:ad:be:ef:00:01', rev=99, updater='10.0.0.66'),
             30, base, 'revision-bomb')
    bomb_ok = any('VTP BOMB' in x for x in rb['reasons'])
    scenarios.append({'name': 'bomb-reason', 'expect': 'bomb',
                      'got': 'bomb' if bomb_ok else 'missing', 'pass': bomb_ok})
    # 3. vtp-enabled: higher revision from the KNOWN server = legit VLAN edit.
    run('legit-bump', frame('00:11:22:33:44:55', rev=11), 30, base, 'vtp-enabled')
    # 4. rogue-server: new speaker, same revision (rogue switch present).
    run('rogue-server', frame('de:ad:be:ef:00:02', rev=10, updater='10.0.0.1'),
        30, base, 'rogue-server')
    # 5. rogue-server: a different VTP domain name (domain confusion).
    run('rogue-domain', frame('de:ad:be:ef:00:03', domain='EVIL', rev=5),
        30, base, 'rogue-server')
    # 6. vtp-enabled: first-run learn (no baseline).
    run('learn', frame('00:11:22:33:44:55', rev=10), 30, None, 'vtp-enabled')
    # 7. parse: hex revision decoded, domain + updater extracted.
    pev = _parse_vtp_capture(frame('aa:bb:cc:dd:ee:ff', domain='PROD', rev=255,
                                   updater='192.0.2.9'))
    p_ok = (len(pev) == 1 and pev[0]['domain'] == 'PROD'
            and pev[0]['revision'] == 255 and pev[0]['updater'] == '192.0.2.9'
            and pev[0]['msgcode'] == 0x01)
    scenarios.append({'name': 'vtp-parse', 'expect': 'domain+rev255+updater',
                      'got': str({k: pev[0][k] for k in
                                  ('domain', 'revision', 'updater')} if pev else None),
                      'pass': p_ok})

    # Optional Scapy end-to-end: craft a real VTP summary advert -> pcap -> tcpdump.
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import Dot3, LLC, SNAP, wrpcap
        import scapy.contrib.vtp as vtp
        if _have('tcpdump'):
            pkt = (Dot3(dst='01:00:0c:cc:cc:cc', src='de:ad:be:ef:00:01')
                   / LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
                   / SNAP(OUI=0x00000c, code=0x2003)
                   / vtp.VTP(ver=1, code=1, followers=1, domnamelen=3,
                             domname='LAB', rev=99, uid='10.0.0.66'))
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, [pkt])
            res = _run(['tcpdump', '-e', '-nn', '-t', '-v', '-r', pcap_path],
                       timeout=10)
            evs = _parse_vtp_capture(res['out'])
            e = evs[0] if evs else {}
            scapy_result = {'ran': True, 'domain': e.get('domain'),
                            'revision': e.get('revision'), 'updater': e.get('updater'),
                            'pass': bool(evs) and e.get('domain') == 'LAB'
                                    and e.get('revision') == 99,
                            'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as ex:
        scapy_result = {'ran': False, 'reason': f'{type(ex).__name__}: {ex}'}

    passed = all(s['pass'] for s in scenarios) and \
        (not scapy_result.get('ran') or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# EIGRP Watch: passive EIGRP routing-security scanner (Cisco; detection-only)
# --------------------------------------------------------------------------
# EIGRP is Cisco's interior gateway protocol (the Cisco-world alternative to OSPF;
# advanced distance-vector, IP proto 88, multicast 224.0.0.10 / ff02::a). Like OSPF
# it has no protection on the wire unless HMAC-MD5/SHA authentication (key-chains) is
# configured, so any host on the segment can form an adjacency and inject Update
# packets with attractive metrics to blackhole or MITM traffic. Unlike OSPF, tcpdump
# fully decodes EIGRP's route TLVs — the advertised prefix, next-hop and metrics are
# visible — so this passive scanner can see route injection directly. It flags:
#   * injection    — a prefix that isn't in the baseline being advertised, or a known
#     prefix now originated by a different router / pointing at a different next-hop
#     (route/next-hop hijack).
#   * rogue-router — a new EIGRP speaker (source/AS) not in the baseline.
#   * storm        — an EIGRP flood (hello/query storm) by rate.
#   * anomaly      — K-value or AS-number mismatch between speakers (misconfig / probe).
#   * weak-auth    — EIGRP packets with no Authentication TLV (the injection enabler).
# Detection-only: it never forms an adjacency, sends a hello, or injects a route.
_EIGRP_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 'data', 'eigrp_watch.json')
_eigrp_watch_lock = threading.Lock()
_EIGRP_EVENTS_CAP = 200
_EIGRP_STORM_RATE = 25          # EIGRP pkts/s above this (with volume) == flood
_EIGRP_OPCODES = {1: 'update', 2: 'request', 3: 'query', 4: 'reply', 5: 'hello',
                  10: 'siaquery', 11: 'siareply'}
_EIGRP_V4HDR_RE = re.compile(r'^(\d+\.\d+\.\d+\.\d+)\s*>\s*(\S+):\s*$')
_EIGRP_V6HDR_RE = re.compile(r'next-header EIGRP \(88\).*?\)\s+(\S+)\s*>\s*(\S+):')
_EIGRP_OP_RE = re.compile(r'EIGRP v(\d+), opcode:\s*(\w+)\s*\((\d+)\)')


def _parse_eigrp_capture(output):
    """Parse `tcpdump -t -v` text over EIGRP into per-packet events. Block-structured:
    an IP/IP6 header line sets the current src/dst, then an `EIGRP v2, opcode:` line
    starts a packet whose TLVs (params/auth/routes) follow indented."""
    events = []
    cur = None
    cur_src = cur_dst = None
    last_kind = None
    for raw in output.splitlines():
        line = raw.strip()
        m6 = _EIGRP_V6HDR_RE.search(line)
        if m6:
            cur_src, cur_dst = m6.group(1), m6.group(2)
            continue
        m4 = _EIGRP_V4HDR_RE.match(line)
        if m4:
            cur_src, cur_dst = m4.group(1), m4.group(2)
            continue
        mo = _EIGRP_OP_RE.search(line)
        if mo:
            if cur:
                events.append(cur)
            op = int(mo.group(3))
            cur = {'src': cur_src, 'dst': cur_dst,
                   'af': 'ipv6' if (cur_dst and ':' in str(cur_dst)) else 'ipv4',
                   'opcode': _EIGRP_OPCODES.get(op, mo.group(2).lower()),
                   'opcode_num': op, 'asn': None, 'auth': False, 'kvals': None,
                   'holdtime': None, 'routes': []}
            last_kind = None
            continue
        if cur is None:
            continue
        a = re.search(r'\bAS:\s*(\d+)', line)
        if a:
            cur['asn'] = int(a.group(1))
        if 'Authentication TLV' in line:
            cur['auth'] = True
        if 'Internal routes TLV' in line:
            last_kind = 'internal'
        elif 'External routes TLV' in line:
            last_kind = 'external'
        k = re.search(r'holdtime:\s*(\d+)s,\s*k1\s*(\d+),\s*k2\s*(\d+),\s*k3\s*(\d+),'
                      r'\s*k4\s*(\d+),\s*k5\s*(\d+)', line)
        if k:
            cur['holdtime'] = int(k.group(1))
            cur['kvals'] = tuple(int(k.group(i)) for i in range(2, 7))
        pr = re.search(r'prefix:\s*([0-9a-fA-F:.]+/\d+),\s*nexthop:\s*([0-9a-fA-F:.]+)',
                       line)
        if pr:
            cur['routes'].append({'prefix': pr.group(1),
                                  'nexthop': pr.group(2).rstrip(','),
                                  'kind': last_kind or 'internal',
                                  'origin_router': None, 'origin_as': None,
                                  'origin_proto': None, 'delay': None,
                                  'bandwidth': None})
        og = re.search(r'origin-router\s*([0-9a-fA-F:.]+),\s*origin-as\s*(\d+),'
                       r'\s*origin-proto\s*(\w+)', line)
        if og and cur['routes']:
            cur['routes'][-1]['origin_router'] = og.group(1).rstrip(',')
            cur['routes'][-1]['origin_as'] = int(og.group(2))
            cur['routes'][-1]['origin_proto'] = og.group(3)
        dl = re.search(r'delay\s*(\d+)\s*ms,\s*bandwidth\s*(\d+)\s*Kbps', line)
        if dl and cur['routes']:
            cur['routes'][-1]['delay'] = int(dl.group(1))
            cur['routes'][-1]['bandwidth'] = int(dl.group(2))
    if cur:
        events.append(cur)
    return [e for e in events if e['src']]


def _eigrp_watch_load():
    try:
        with open(_EIGRP_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _eigrp_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_EIGRP_WATCH_PATH), exist_ok=True)
        tmp = _EIGRP_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _EIGRP_WATCH_PATH)
    except OSError:
        pass


def do_eigrp_baseline(action='get'):
    """Manage the learned EIGRP baseline (trusted routers + advertised prefixes)."""
    with _eigrp_watch_lock:
        if action == 'reset':
            _eigrp_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _eigrp_watch_load()
        return {'success': True, 'baseline': {
            'routers': sorted((b.get('routers') or {}).keys()),
            'prefixes': sorted((b.get('prefixes') or {}).keys())}}


def _eigrp_analyze(events, seconds, baseline, learn=True):
    """Pure classifier over parsed EIGRP events. Separated from capture for the
    self-test. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))

    routers = {}
    prefixes = {}
    noauth_any = False
    for e in events:
        r = routers.setdefault(e['src'], {
            'src': e['src'], 'af': e['af'], 'as': set(), 'kvals': set(),
            'opcodes': set(), 'auth': False, 'noauth': False, 'count': 0})
        r['count'] += 1
        r['opcodes'].add(e['opcode'])
        if e['asn'] is not None:
            r['as'].add(e['asn'])
        if e.get('kvals'):
            r['kvals'].add(e['kvals'])
        if e['auth']:
            r['auth'] = True
        else:
            r['noauth'] = True
            noauth_any = True
        for rt in e['routes']:
            prefixes.setdefault(rt['prefix'], {
                'prefix': rt['prefix'], 'origin': e['src'],
                'nexthop': rt['nexthop'], 'kind': rt['kind'], 'af': e['af']})

    known = dict(baseline.get('routers') or {})
    base_prefixes = dict(baseline.get('prefixes') or {})
    had_baseline = bool(known) or bool(base_prefixes)

    learned = False
    if learn and not had_baseline and routers:
        baseline['routers'] = {
            s: {'as': sorted(r['as']), 'kvals': [list(k) for k in r['kvals']]}
            for s, r in routers.items()}
        baseline['prefixes'] = {
            p: {'origin': d['origin'], 'nexthop': d['nexthop']}
            for p, d in prefixes.items()}
        learned = True
        known = dict(baseline['routers'])
        base_prefixes = dict(baseline['prefixes'])
        had_baseline = True

    PRIORITY = ['injection', 'rogue-router', 'storm', 'anomaly', 'weak-auth', 'clean']
    verdict = 'clean'
    reasons = []

    def bump(v):
        nonlocal verdict
        if PRIORITY.index(v) < PRIORITY.index(verdict):
            verdict = v

    # Route injection / next-hop hijack (only meaningful once a baseline exists).
    if had_baseline:
        for p in sorted(prefixes):
            d = prefixes[p]
            base = base_prefixes.get(p)
            if base is None:
                bump('injection')
                reasons.append(
                    f"EIGRP ROUTE INJECTION: prefix {p} advertised by {d['origin']} "
                    f"(next-hop {d['nexthop']}) is not in the baseline — a forged "
                    f"route that can blackhole or MITM traffic to it")
            elif base.get('nexthop') and d['nexthop'] != base['nexthop']:
                bump('injection')
                reasons.append(
                    f"EIGRP NEXT-HOP HIJACK: prefix {p} now points at next-hop "
                    f"{d['nexthop']} (was {base['nexthop']}) — traffic to {p} is being "
                    f"steered to a new gateway")

    # Rogue routers.
    for src in sorted(routers):
        if had_baseline and src not in known:
            bump('rogue-router')
            asn = ', '.join(str(a) for a in sorted(routers[src]['as'])) or '?'
            reasons.append(
                f"Rogue EIGRP speaker {src} (AS {asn}) — not in the baseline; a new "
                f"router forming adjacencies on this segment (adjacency spoofing)")

    # K-value / AS mismatch across speakers.
    all_as = set()
    all_kvals = set()
    for r in routers.values():
        all_as |= r['as']
        all_kvals |= r['kvals']
    if len(all_as) > 1:
        bump('anomaly')
        reasons.append(
            f"Multiple EIGRP AS numbers on one segment ({', '.join(str(a) for a in sorted(all_as))}) "
            f"— usually one AS per link; a mismatch is a misconfig or a probing router")
    if len(all_kvals) > 1:
        bump('anomaly')
        reasons.append(
            "EIGRP K-value mismatch between speakers — K-values must match to form an "
            "adjacency; a mismatch blocks peering (misconfig) or signals a crafted hello")

    # Weak / no authentication.
    if noauth_any:
        bump('weak-auth')
        reasons.append(
            "EIGRP packets seen without an Authentication TLV — no HMAC-MD5/SHA "
            "protection. This is what lets a forged Update win; configure an EIGRP "
            "key-chain (authentication mode md5/hmac-sha-256) on every neighbor")

    # Flooding.
    rate = round(len(events) / seconds, 2)
    if len(events) > 100 and rate > _EIGRP_STORM_RATE:
        bump('storm')
        reasons.append(
            f"EIGRP flood: {rate} pkts/s (hellos are normally every 5s) — a "
            f"hello/query storm (churn or DoS against the routing process)")

    advisories = []
    if routers:
        advisories.append(
            "Authenticate EIGRP with an HMAC-MD5/SHA-256 key-chain on every interface, "
            "make edge/access ports passive (`passive-interface`), filter proto-88 "
            "multicast off host ports, and alert on any new neighbor, new prefix or "
            "next-hop change.")

    def _pub_router(r):
        return {'src': r['src'], 'af': r['af'], 'as': sorted(r['as']),
                'opcodes': sorted(r['opcodes']),
                'auth': r['auth'] and not r['noauth'],
                'kvals': [list(k) for k in sorted(r['kvals'])], 'count': r['count'],
                'baseline': r['src'] in known}

    def _pub_prefix(p, d):
        base = base_prefixes.get(p)
        status = 'known' if base else ('new' if had_baseline else 'learned')
        if base and base.get('nexthop') and d['nexthop'] != base['nexthop']:
            status = 'nexthop-changed'
        return {'prefix': p, 'origin': d['origin'], 'nexthop': d['nexthop'],
                'kind': d['kind'], 'af': d['af'], 'status': status}

    if reasons:
        summary = reasons
    elif not routers:
        summary = ['No EIGRP traffic seen — no EIGRP on this segment']
    else:
        summary = ['All EIGRP routers and advertised prefixes match the trusted baseline']

    return {
        'success': True,
        'verdict': verdict,
        'reasons': summary,
        'learned': learned,
        'router_count': len(routers),
        'prefix_count': len(prefixes),
        'packet_count': len(events),
        'rate': rate,
        'routers': [_pub_router(routers[s]) for s in sorted(routers)],
        'prefixes': [_pub_prefix(p, prefixes[p]) for p in sorted(prefixes)],
        'advisories': advisories,
    }


def _eigrp_capture(interface, seconds):
    """One passive tcpdump window over EIGRP (IPv4 proto 88 + IPv6 proto 88)."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    bpf = 'ip proto 88 or ip6 proto 88'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface,
                '-nn', '-t', '-v', '-s', '512', '-c', '20000', bpf],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()
                                   or 'syntax error' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_eigrp_watch(interface=None, seconds=15, learn=True):
    """Passive EIGRP routing-security scanner (detection-only). Captures EIGRP for a
    few seconds and classifies: injection / rogue-router / storm / anomaly / weak-auth
    / clean. Learns the trusted routers + advertised prefixes on first run."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 15, 5, 40)

    text, err = _eigrp_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    events = _parse_eigrp_capture(text)

    with _eigrp_watch_lock:
        baseline = _eigrp_watch_load()
        result = _eigrp_analyze(events, seconds, baseline, learn=learn)
        if result.get('learned'):
            _eigrp_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _eigrp_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_EIGRP_EVENTS_CAP:]
            _eigrp_watch_save(b)

    result['interface'] = iface
    result['seconds'] = seconds
    return result


def _eigrp_selftest():
    """Self-test the EIGRP detectors with synthetic captures, plus a Scapy end-to-end
    leg (craft real EIGRP Hello + Update-with-route -> pcap -> tcpdump -> parse)."""
    scenarios = []

    def hdr4(src, dst='224.0.0.10'):
        return (f"IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto EIGRP "
                f"(88), length 60)\n    {src} > {dst}: ")

    def eigrp4(src, opcode='Update', opnum=1, asn=100, auth=False, kvals=(1, 0, 1, 0, 0),
               routes=()):
        s = hdr4(src) + "\n"
        s += f"\tEIGRP v2, opcode: {opcode} ({opnum}), chksum: 0x0, Flags: [none]\n"
        s += f"\tseq: 0x00000000, ack: 0x00000000, VRID: 0, AS: {asn}, length: 20\n"
        s += (f"\t  General Parameters TLV (0x0001), length: 12\n"
              f"\t    holdtime: 15s, k1 {kvals[0]}, k2 {kvals[1]}, k3 {kvals[2]}, "
              f"k4 {kvals[3]}, k5 {kvals[4]}\n")
        if auth:
            s += "\t  Authentication TLV (0x0002), length: 40\n"
        for (pfx, nh) in routes:
            s += (f"\t  IP Internal routes TLV (0x0102), length: 28\n"
                  f"\t    IPv4 prefix:      {pfx}, nexthop: {nh}\n"
                  f"\t      delay 1280 ms, bandwidth 256 Kbps, mtu 1500, hop 0, "
                  f"reliability 255, load 0\n")
        return s.rstrip("\n")

    def run(name, text, seconds, baseline, expect):
        events = _parse_eigrp_capture(text)
        res = _eigrp_analyze(events, seconds, dict(baseline or {}), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'events': len(events), 'pass': ok})
        return res

    base = {'routers': {'10.0.0.1': {'as': [100], 'kvals': [[1, 0, 1, 0, 0]]}},
            'prefixes': {'10.1.0.0/24': {'origin': '10.0.0.1', 'nexthop': '10.0.0.1'}}}

    # 1. clean: known router, authed, re-advertising the known prefix with same next-hop.
    run('clean', eigrp4('10.0.0.1', auth=True,
                        routes=[('10.1.0.0/24', '10.0.0.1')]), 15, base, 'clean')
    # 2. injection: a new prefix from the known router.
    run('injection', eigrp4('10.0.0.1', auth=True,
                            routes=[('10.66.66.0/24', '10.0.0.1')]), 15, base,
        'injection')
    # 3. injection via next-hop hijack: known prefix, new next-hop.
    run('nexthop-hijack', eigrp4('10.0.0.1', auth=True,
                                 routes=[('10.1.0.0/24', '10.0.0.66')]), 15, base,
        'injection')
    # 4. rogue-router: a new speaker (authed, no new routes) — not in baseline.
    run('rogue-router', eigrp4('10.0.0.66', opcode='Hello', opnum=5, auth=True), 15,
        base, 'rogue-router')
    # 5. anomaly: known router but a second AS appears.
    run('anomaly-as', eigrp4('10.0.0.1', asn=100, auth=True) + "\n"
        + eigrp4('10.0.0.1', asn=200, auth=True), 15, base, 'anomaly')
    # 6. weak-auth: known router + prefix, but no Authentication TLV.
    run('weak-auth', eigrp4('10.0.0.1', auth=False,
                            routes=[('10.1.0.0/24', '10.0.0.1')]), 15, base, 'weak-auth')
    # 7. parse: internal + external routes, auth flag, AS.
    pev = _parse_eigrp_capture(
        hdr4('10.0.0.9') + "\n"
        "\tEIGRP v2, opcode: Update (1), chksum: 0x0, Flags: [none]\n"
        "\tseq: 0x0, ack: 0x0, VRID: 0, AS: 100, length: 128\n"
        "\t  Authentication TLV (0x0002), length: 40\n"
        "\t  IP Internal routes TLV (0x0102), length: 28\n"
        "\t    IPv4 prefix:      10.66.66.0/24, nexthop: 10.0.0.9\n"
        "\t      delay 1280 ms, bandwidth 256 Kbps, mtu 1500, hop 0, reliability 255, load 0\n"
        "\t  IP External routes TLV (0x0103), length: 48\n"
        "\t    IPv4 prefix:      172.16.9.0/24, nexthop: 10.0.0.9\n"
        "\t      origin-router 192.168.0.1, origin-as 0, origin-proto Static, flags [0x00], tag 0x0, metric 0\n"
        "\t      delay 0 ms, bandwidth 256 Kbps, mtu 1500, hop 0, reliability 255, load 0")
    e0 = pev[0] if pev else {}
    kinds = {r['kind'] for r in e0.get('routes', [])}
    p_ok = (e0.get('asn') == 100 and e0.get('auth') is True
            and len(e0.get('routes', [])) == 2 and kinds == {'internal', 'external'}
            and e0['routes'][1].get('origin_router') == '192.168.0.1')
    scenarios.append({'name': 'eigrp-parse', 'expect': 'int+ext/auth/AS100',
                      'got': f"routes={len(e0.get('routes', []))} auth={e0.get('auth')}",
                      'pass': p_ok})

    # Scapy end-to-end.
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import Ether, IP, wrpcap
        import scapy.contrib.eigrp as E
        if _have('tcpdump'):
            upd = (Ether() / IP(src='10.0.0.9', dst='224.0.0.10', proto=88)
                   / E.EIGRP(opcode=1, asn=100, tlvlist=[
                       E.EIGRPParam(k1=1, k2=0, k3=1, k4=0, k5=0, holdtime=15),
                       E.EIGRPIntRoute(dst='10.66.66.0', prefixlen=24,
                                       nexthop='10.0.0.9')]))
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, [upd])
            res = _run(['tcpdump', '-nn', '-t', '-v', '-r', pcap_path], timeout=10)
            evs = _parse_eigrp_capture(res['out'])
            e = evs[0] if evs else {}
            rt = e.get('routes', [{}])[0] if e.get('routes') else {}
            ok = (e.get('src') == '10.0.0.9' and e.get('asn') == 100
                  and rt.get('prefix') == '10.66.66.0/24'
                  and rt.get('nexthop') == '10.0.0.9')
            scapy_result = {'ran': True, 'src': e.get('src'), 'asn': e.get('asn'),
                            'prefix': rt.get('prefix'), 'pass': ok,
                            'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and (not scapy_result.get('ran')
                                                    or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# FHRP Watch: passive HSRP/VRRP/GLBP/CARP hijack scanner (detection-only)
# --------------------------------------------------------------------------
# First Hop Redundancy Protocols share a *virtual gateway* (one virtual IP+MAC that
# floats between routers) so hosts keep one default gateway even when a router dies.
# The active router is picked by PRIORITY, and the hellos are multicast in the clear
# with weak/no auth (HSRP's default is the plaintext string "cisco"; VRRPv3 has no
# auth). So an attacker who sees the hellos can inject a forged hello with priority
# 255 + preempt, win the election, and take over the virtual gateway IP/MAC — every
# host's off-subnet traffic now flows through them (subnet-wide MITM, e.g. Yersinia /
# Loki). This scanner is PASSIVE: one short tcpdump window over the FHRP hellos,
# parsed and classified against a learned baseline of the segment's groups. It never
# sends an FHRP packet. What it flags:
#   * hijack        — a speaker that isn't in the baseline advertising a *winning*
#     priority (>= the active, or 250+/255), or an HSRP Coup — takeover in progress.
#   * rogue-speaker — a new speaker in a group that isn't (yet) winning.
#   * priority-change — a known speaker whose priority jumped up (pre-takeover/reconfig).
#   * weak-auth     — plaintext/no FHRP authentication (the enabler). Advisory.
# HSRP + VRRP are fully decoded by tcpdump (priority-based detection); CARP is lighter
# (advskew-based). GLBP gets a dedicated hand-rolled byte decoder (below) because
# neither tcpdump nor Scapy dissects it — and GLBP is special: it has *two* election
# planes, so it needs two hijack checks:
#   * The AVG (Active Virtual Gateway) owns the vIP and hands each host a virtual MAC.
#     Seizing it (a winning Hello priority) is a hijack worse than HSRP — the attacker
#     picks which hosts to MITM. This reuses the generic priority rules above.
#   * Up to four AVFs (Active Virtual Forwarders) each own a vMAC and forward a slice
#     of the hosts. Seizing one AVF (going Active for a forwarder you don't own, or a
#     vMAC re-homing to a new speaker) quietly captures that slice while the gateway
#     election stays healthy-looking — the stealthiest FHRP takeover. The forwarder
#     plane gets its own rules: glbp-avf-hijack and glbp-weight-skew (load-share shift).
# The sensor must sit on the FHRP group's L2 segment (SPAN/mirror or a NIC in the
# gateway VLAN) — HSRP is TTL 1, VRRP/GLBP link-local multicast. Off-segment: nothing.
_FHRP_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'data', 'fhrp_watch.json')
_fhrp_watch_lock = threading.Lock()
_FHRP_EVENTS_CAP = 200
# A priority at/above this from a source that isn't the baseline active is a takeover
# attempt (HSRP/VRRP/GLBP max is 255/254; attackers use the top of the range).
_FHRP_TAKEOVER_PRIO = 250
# A GLBP forwarder weight swing this large (default weight is 100) is a load-share
# manipulation — steering hosts onto/off an AVF without touching the election.
_FHRP_GLBP_WEIGHT_DELTA = 40
# GLBP wire enums (from the Wireshark GLBP dissector). GLBP rides UDP/3222 to
# 224.0.0.102; its payload is a 12-byte header then type/length/value TLVs.
_GLBP_VG_STATE = {4: 'Listen', 8: 'Speak', 0x10: 'Standby', 0x20: 'Active'}
_GLBP_VF_STATE = {4: 'Listen', 8: 'Speak', 0x10: 'Standby', 0x20: 'Active'}
_GLBP_AUTH = {0: 'none', 1: 'plaintext', 2: 'md5', 3: 'md5'}

_FHRP_HSRP_SRC = re.compile(r'(\d+\.\d+\.\d+\.\d+)\.1985\s*>')
_FHRP_GLBP_SRC = re.compile(r'(\d+\.\d+\.\d+\.\d+)\.3222\s*>')
_FHRP_L3_SRC = re.compile(r'^\s*(\S+?)\s*>')


def _glbp_decode(payload):
    """Hand-rolled GLBP (UDP/3222) decoder — neither tcpdump nor Scapy dissects GLBP.
    Returns {group, hello, forwarders, auth} or None if it isn't a plausible GLBP
    packet. Tolerant: never raises on malformed/truncated input.
      header (12B): version(1)=3, unknown(1), group(2 BE), unknown(2), owner-id(6)
      then TLVs: type(1), length(1, incl. header), value(length-2)
      Hello   (type 1): value[1]=VG state, [3]=AVG priority, [20]=addr-type,
                        [21]=addr-len, [22:]=virtual IP
      VF R/R  (type 2): value[0]=forwarder#, [1]=VF state, [3]=VF priority,
                        [4]=weight, [12:18]=virtual MAC
      Auth    (type 3): value[0]=auth type (0 none / 1 plaintext / 2,3 md5)
    """
    try:
        if len(payload) < 12 or payload[0] != 3:
            return None
        out = {'group': int.from_bytes(payload[2:4], 'big'),
               'hello': None, 'forwarders': [], 'auth': None}
        i, n = 12, len(payload)
        while i + 2 <= n:
            t, ln = payload[i], payload[i + 1]
            if ln < 2 or i + ln > n:
                break
            v = payload[i + 2:i + ln]
            if t == 1 and len(v) >= 22:                       # Hello (AVG plane)
                vip = None
                if v[20] == 1 and len(v) >= 26:               # IPv4 virtual address
                    vip = '.'.join(str(b) for b in v[22:26])
                out['hello'] = {'vg_state': _GLBP_VG_STATE.get(v[1], str(v[1])),
                                'priority': v[3], 'vip': vip}
            elif t == 2 and len(v) >= 18:                     # VF Request/Response
                out['forwarders'].append({
                    'forwarder': v[0],
                    'vf_state': _GLBP_VF_STATE.get(v[1], str(v[1])),
                    'priority': v[3], 'weight': v[4],
                    'vmac': ':'.join('%02x' % b for b in v[12:18])})
            elif t == 3 and len(v) >= 1:                      # Auth
                out['auth'] = _GLBP_AUTH.get(v[0], 'unknown')
            i += ln
        return out
    except Exception:
        return None


def _fhrp_glbp_from_pkts(pkts):
    """Turn decoded GLBP packets [{src, src_mac, payload}] into (avg_events, vf_events).
    avg_events feed the generic group analyzer (AVG election == a normal FHRP hijack);
    vf_events feed the dedicated forwarder-plane analyzer."""
    avg_events, vf_events = [], []
    for pk in pkts:
        d = _glbp_decode(pk.get('payload') or b'')
        if not d:
            continue
        weak = (d['auth'] in (None, 'none', 'plaintext'))
        if d['hello']:
            h = d['hello']
            avg_events.append({
                'proto': 'glbp', 'version': None, 'src': pk.get('src'),
                'group': d['group'], 'vip': h['vip'], 'priority': h['priority'],
                'opcode': 'hello', 'state': h['vg_state'],
                'authtype': d['auth'] or 'none', 'auth_weak': weak, 'advskew': None})
        for f in d['forwarders']:
            if not (1 <= f['forwarder'] <= 4):    # 0 == VF negotiation, not ownership
                continue
            vf_events.append({
                'proto': 'glbp', 'group': d['group'], 'src': pk.get('src'),
                'src_mac': pk.get('src_mac'), 'forwarder': f['forwarder'],
                'vf_state': f['vf_state'], 'vf_prio': f['priority'],
                'weight': f['weight'], 'vmac': f['vmac']})
    return avg_events, vf_events


def _parse_fhrp_capture(output):
    """Parse `tcpdump -nn -t -v` text over FHRP hellos into events. One hello is one
    content line (`<src> > <mcast>: HSRPv0-hello ... priority=255 ...` etc.). Each
    event is a dict with a normalised 'priority' (higher = wins the election):
      {proto, version, src, group, vip, priority, opcode, state, authtype,
       auth_weak, advskew}
    """
    events = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line or '>' not in line:
            continue

        if 'HSRPv' in line:                                   # HSRP (UDP 1985)
            m = _FHRP_HSRP_SRC.search(line)
            op = re.search(r'HSRPv(\d+)-(\w+)', line)
            grp = re.search(r'group=(\d+)', line)
            pri = re.search(r'priority=(\d+)', line)
            auth = re.search(r'auth="([^"]*)"', line)
            events.append({
                'proto': 'hsrp', 'version': int(op.group(1)) if op else None,
                'src': m.group(1) if m else None,
                'group': int(grp.group(1)) if grp else None,
                'vip': (re.search(r'addr=([\d.]+)', line) or [None, None])[1]
                if re.search(r'addr=([\d.]+)', line) else None,
                'priority': int(pri.group(1)) if pri else None,
                'opcode': op.group(2) if op else None,
                'state': (re.search(r'state=(\w+)', line) or [None, None])[1]
                if re.search(r'state=(\w+)', line) else None,
                'authtype': 'plaintext' if auth else None,
                'auth_weak': bool(auth), 'advskew': None})

        elif 'CARP' in line:                                  # CARP (IP proto 112)
            m = _FHRP_L3_SRC.match(raw)
            ver = re.search(r'CARPv(\d+)', line)
            vhid = re.search(r'vhid=(\d+)', line)
            skew = re.search(r'advskew=(\d+)', line)
            adv = int(skew.group(1)) if skew else None
            events.append({
                'proto': 'carp', 'version': int(ver.group(1)) if ver else None,
                'src': m.group(1) if m else None,
                'group': int(vhid.group(1)) if vhid else None, 'vip': None,
                'priority': (255 - adv) if adv is not None else None,
                'opcode': 'advertise', 'state': None, 'authtype': 'hmac',
                'auth_weak': False, 'advskew': adv})

        elif 'VRRP' in line:                                  # VRRP (IP proto 112)
            m = _FHRP_L3_SRC.match(raw)
            ver = re.search(r'VRRPv(\d+)', line)
            vrid = re.search(r'vrid (\d+)', line)
            pri = re.search(r'prio (\d+)', line)
            at = re.search(r'authtype (\w+)', line)
            addrs = re.search(r'addrs:\s*([0-9a-fA-F:., ]+)', line)
            vip = None
            if addrs:
                parts = [a.strip() for a in re.split(r'[,\s]+', addrs.group(1))
                         if a.strip()]
                vip = parts[0] if parts else None
            authtype = at.group(1).lower() if at else None
            events.append({
                'proto': 'vrrp', 'version': int(ver.group(1)) if ver else None,
                'src': m.group(1) if m else None,
                'group': int(vrid.group(1)) if vrid else None, 'vip': vip,
                'priority': int(pri.group(1)) if pri else None,
                'opcode': 'advertise', 'state': None, 'authtype': authtype,
                'auth_weak': authtype in ('none', 'simple', None), 'advskew': None})

        elif '.3222 >' in line:                               # GLBP (UDP 3222)
            m = _FHRP_GLBP_SRC.search(line)
            grp = re.search(r'[Gg]roup[= ](\d+)', line)
            pri = re.search(r'priority[= ](\d+)', line)
            events.append({
                'proto': 'glbp', 'version': None,
                'src': m.group(1) if m else None,
                'group': int(grp.group(1)) if grp else None, 'vip': None,
                'priority': int(pri.group(1)) if pri else None,
                'opcode': 'hello', 'state': None, 'authtype': None,
                'auth_weak': False, 'advskew': None})
    return [e for e in events if e['src']]


def _fhrp_watch_load():
    try:
        with open(_FHRP_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _fhrp_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_FHRP_WATCH_PATH), exist_ok=True)
        tmp = _FHRP_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _FHRP_WATCH_PATH)
    except OSError:
        pass


def do_fhrp_baseline(action='get'):
    """Manage the learned FHRP baseline (trusted groups + their speakers/priorities).
    action='reset' re-learns the segment's FHRP groups on the next scan."""
    with _fhrp_watch_lock:
        if action == 'reset':
            _fhrp_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _fhrp_watch_load()
        return {'success': True, 'baseline': {
            'groups': sorted((b.get('groups') or {}).keys()),
            'glbp_forwarders': sorted((b.get('glbp_forwarders') or {}).keys()),
        }}


def _fhrp_gkey(e):
    return f"{e['proto']}/{e['group']}" if e['group'] is not None else f"{e['proto']}/?"


def _fhrp_analyze(events, seconds, baseline, learn=True, glbp_vf=None):
    """Pure classifier over parsed FHRP events. Returns the result payload (minus
    interface). Separated from capture so the self-test can drive it with synthetic
    packets. `glbp_vf` is the list of GLBP virtual-forwarder events for the AVF-plane
    checks. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))

    groups = {}
    for e in events:
        gk = _fhrp_gkey(e)
        g = groups.setdefault(gk, {
            'gkey': gk, 'proto': e['proto'], 'group': e['group'], 'vips': set(),
            'speakers': {}, 'auth_weak': False, 'authtype': e['authtype']})
        if e['vip']:
            g['vips'].add(e['vip'])
        if e['auth_weak']:
            g['auth_weak'] = True
        if e['authtype']:
            g['authtype'] = e['authtype']
        sp = g['speakers'].setdefault(e['src'], {
            'src': e['src'], 'prio': None, 'states': set(), 'opcodes': set(),
            'count': 0})
        sp['count'] += 1
        if e['priority'] is not None:
            sp['prio'] = e['priority'] if sp['prio'] is None else max(sp['prio'],
                                                                      e['priority'])
        if e['state']:
            sp['states'].add(e['state'])
        if e['opcode']:
            sp['opcodes'].add(e['opcode'])

    known = dict(baseline.get('groups') or {})
    had_baseline = bool(known)

    learned = False
    if learn and not had_baseline and groups:
        baseline['groups'] = {
            gk: {'speakers': {s: sp['prio'] for s, sp in g['speakers'].items()},
                 'vips': sorted(g['vips']),
                 'max_prio': max([sp['prio'] for sp in g['speakers'].values()
                                  if sp['prio'] is not None] or [0])}
            for gk, g in groups.items()}
        learned = True
        known = dict(baseline['groups'])
        had_baseline = True

    PRIORITY = ['hijack', 'glbp-avf-hijack', 'rogue-speaker', 'priority-change',
                'glbp-weight-skew', 'weak-auth', 'clean']
    verdict = 'clean'
    reasons = []

    def bump(v):
        nonlocal verdict
        if PRIORITY.index(v) < PRIORITY.index(verdict):
            verdict = v

    for gk in sorted(groups):
        g = groups[gk]
        base = known.get(gk) or {}
        base_speakers = dict(base.get('speakers') or {})
        base_max = base.get('max_prio')
        vip = ', '.join(sorted(g['vips'])) or '?'
        for src in sorted(g['speakers']):
            sp = g['speakers'][src]
            is_new = had_baseline and src not in base_speakers
            coup = 'coup' in sp['opcodes']
            prio = sp['prio']
            winning = (prio is not None and base_max is not None and prio >= base_max)
            near_max = (prio is not None and prio >= _FHRP_TAKEOVER_PRIO)
            if is_new and (coup or winning or near_max):
                bump('hijack')
                p = f"priority {prio}" if prio is not None else "no priority field"
                extra = ' (HSRP Coup)' if coup else ''
                reasons.append(
                    f"FHRP HIJACK on {g['proto'].upper()} group "
                    f"{g['group'] if g['group'] is not None else '?'} (gateway "
                    f"{vip}): new speaker {src} advertising {p}{extra} — it wins the "
                    f"election and becomes the virtual gateway, MITMing the subnet")
            elif is_new:
                bump('rogue-speaker')
                reasons.append(
                    f"Unexpected {g['proto'].upper()} speaker {src} in group "
                    f"{g['group'] if g['group'] is not None else '?'} (gateway {vip}) "
                    f"— not in the baseline (FHRP injection; watch for a priority rise)")
            elif (not is_new) and prio is not None:
                base_prio = base_speakers.get(src)
                if base_prio is not None and prio > base_prio:
                    bump('priority-change')
                    reasons.append(
                        f"{g['proto'].upper()} speaker {src} in group "
                        f"{g['group'] if g['group'] is not None else '?'} raised its "
                        f"priority {base_prio} → {prio} — possible pre-takeover or a "
                        f"legitimate reconfiguration")
        if g['auth_weak']:
            bump('weak-auth')
            reasons.append(
                f"{g['proto'].upper()} group "
                f"{g['group'] if g['group'] is not None else '?'} uses weak/no "
                f"authentication ({g['authtype'] or 'none'}) — this is what lets a "
                f"forged higher-priority hello win the election; enable MD5/HMAC auth")

    # ---- GLBP forwarder (AVF) plane -----------------------------------------
    # A healthy GLBP forwarder has ONE stable Active owner + vMAC. A second speaker
    # going Active for that forwarder — or the same vMAC re-homing to a new source —
    # is a stealth slice-capture the AVG election never reveals.
    forwarders = {}
    for e in (glbp_vf or []):
        fk = f"{e['group']}/{e['forwarder']}"
        c = forwarders.setdefault(fk, {'group': e['group'], 'forwarder': e['forwarder'],
                                       'owners': {}})
        o = c['owners'].setdefault(e['src'], {
            'src': e['src'], 'src_mac': e.get('src_mac'), 'vf_prio': None,
            'weight': None, 'vmac': e['vmac'], 'states': set(), 'count': 0})
        o['count'] += 1
        o['vf_prio'] = e['vf_prio'] if o['vf_prio'] is None else max(o['vf_prio'],
                                                                     e['vf_prio'])
        o['weight'] = e['weight']
        o['vmac'] = e['vmac']
        if e['vf_state']:
            o['states'].add(e['vf_state'])

    known_fwd = dict(baseline.get('glbp_forwarders') or {})
    if learn and 'glbp_forwarders' not in baseline and forwarders:
        baseline['glbp_forwarders'] = {}
        for fk, c in forwarders.items():
            active = [o for o in c['owners'].values() if 'Active' in o['states']]
            owner = (active[0] if active
                     else max(c['owners'].values(), key=lambda o: o['vf_prio'] or 0))
            # Learn EVERY speaker of the forwarder — GLBP redundancy means a forwarder
            # legitimately has a standby speaker that shares the same vMAC in Listen
            # state, so only a *new* speaker (not in this set) is suspect.
            baseline['glbp_forwarders'][fk] = {
                'speakers': sorted(c['owners'].keys()), 'owner': owner['src'],
                'vmac': owner['vmac'], 'vf_prio': owner['vf_prio'],
                'weight': owner['weight']}
        known_fwd = dict(baseline['glbp_forwarders'])
        learned = True
    had_fwd_baseline = bool(known_fwd)

    for fk in sorted(forwarders):
        c = forwarders[fk]
        base = known_fwd.get(fk) or {}
        base_owner, base_vmac = base.get('owner'), base.get('vmac')
        base_weight, base_prio = base.get('weight'), base.get('vf_prio')
        base_speakers = set(base.get('speakers') or ([base_owner] if base_owner else []))
        for src in sorted(c['owners']):
            o = c['owners'][src]
            active = 'Active' in o['states']
            is_new = had_fwd_baseline and src not in base_speakers
            winning = o['vf_prio'] is not None and (
                o['vf_prio'] >= _FHRP_TAKEOVER_PRIO
                or (base_prio is not None and o['vf_prio'] >= base_prio))
            if is_new and (active or winning):
                bump('glbp-avf-hijack')
                stole = bool(base_vmac) and o['vmac'] == base_vmac
                why = ('claiming the Active virtual MAC' if stole
                       else f'going {"/".join(sorted(o["states"])) or "Active"} '
                            f'with VF priority {o["vf_prio"]}')
                reasons.append(
                    f"GLBP AVF HIJACK on group {c['group']} forwarder "
                    f"{c['forwarder']} (vMAC {o['vmac']}): new speaker {src} {why} — it "
                    f"captures that forwarder's slice of hosts while the AVG election "
                    f"stays healthy-looking (stealth MITM)")
            elif is_new:
                bump('rogue-speaker')
                reasons.append(
                    f"Unexpected GLBP forwarder speaker {src} on group {c['group']} "
                    f"forwarder {c['forwarder']} — not a baseline speaker "
                    f"(watch for it going Active)")
            elif src == base_owner and base_weight is not None \
                    and o['weight'] is not None \
                    and abs(o['weight'] - base_weight) >= _FHRP_GLBP_WEIGHT_DELTA:
                bump('glbp-weight-skew')
                reasons.append(
                    f"GLBP forwarder {c['group']}/{c['forwarder']} owner {src} changed "
                    f"its weight {base_weight} → {o['weight']} — a load-share shift that "
                    f"steers which hosts route through this AVF (may be object-tracking "
                    f"or selective capture)")

    def _pub_fwd(fk, c):
        base = known_fwd.get(fk) or {}
        base_speakers = set(base.get('speakers') or
                            ([base.get('owner')] if base.get('owner') else []))
        return {'group': c['group'], 'forwarder': c['forwarder'],
                'owners': [{
                    'src': s, 'vf_priority': o['vf_prio'], 'weight': o['weight'],
                    'vmac': o['vmac'], 'states': sorted(o['states']),
                    'baseline': s in base_speakers,
                } for s, o in sorted(c['owners'].items())]}

    glbp_forwarders_pub = [_pub_fwd(fk, forwarders[fk]) for fk in sorted(forwarders)]

    advisories = []
    if groups or glbp_forwarders_pub:
        advisories.append(
            "Authenticate FHRP (HSRP/VRRP MD5 or key-chain; GLBP MD5), raise the real "
            "routers to a high priority with preempt, and filter FHRP multicast on "
            "access ports (only trunk/router ports should carry HSRP 1985 / GLBP 3222 / "
            "VRRP+CARP IP-proto-112). Alert on any new speaker, priority change, or "
            "GLBP forwarder (AVF) ownership change.")

    def _pub(g):
        return {'gkey': g['gkey'], 'proto': g['proto'], 'group': g['group'],
                'vips': sorted(g['vips']), 'authtype': g['authtype'],
                'auth_weak': g['auth_weak'],
                'speakers': [{
                    'src': s, 'priority': sp['prio'],
                    'states': sorted(sp['states']), 'opcodes': sorted(sp['opcodes']),
                    'baseline': s in ((known.get(g['gkey']) or {}).get('speakers') or {}),
                } for s, sp in sorted(g['speakers'].items())]}

    if reasons:
        summary = reasons
    elif not groups and not glbp_forwarders_pub:
        summary = ['No FHRP traffic seen — no HSRP/VRRP/GLBP/CARP on this segment']
    else:
        summary = ['All FHRP groups/speakers/GLBP forwarders match the trusted baseline']

    return {
        'success': True,
        'verdict': verdict,
        'reasons': summary,
        'learned': learned,
        'group_count': len(groups),
        'packet_count': len(events),
        'rate': round(len(events) / seconds, 2),
        'groups': [_pub(groups[gk]) for gk in sorted(groups)],
        'glbp_forwarders': glbp_forwarders_pub,
        'advisories': advisories,
    }


def _fhrp_glbp_extract(pcap_path):
    """Pull GLBP (UDP/3222) packets out of a pcap as [{src, src_mac, payload}] for the
    hand-rolled decoder. Uses Scapy (lazy); returns [] if Scapy is unavailable so the
    HSRP/VRRP path still works and GLBP falls back to text new-speaker detection."""
    try:
        from scapy.all import rdpcap, Ether, IP, IPv6, UDP, Raw
    except Exception:
        return []
    pkts = []
    try:
        for p in rdpcap(pcap_path):
            if not p.haslayer(UDP) or not p.haslayer(Raw):
                continue
            u = p[UDP]
            if u.sport != 3222 and u.dport != 3222:
                continue
            ipl = p.getlayer(IP) or p.getlayer(IPv6)
            if ipl is None:
                continue
            pkts.append({'src': ipl.src,
                         'src_mac': p[Ether].src if p.haslayer(Ether) else None,
                         'payload': bytes(p[Raw].load)})
    except Exception:
        return pkts
    return pkts


def _fhrp_capture(interface, seconds):
    """One passive tcpdump window over FHRP hellos, returned as (text, glbp_pkts, err).
    We capture to a pcap so GLBP can be byte-decoded, then replay it through
    `tcpdump -r ... -v` to reuse the existing HSRP/VRRP/CARP text parser unchanged."""
    if not _have('tcpdump'):
        return '', [], 'tcpdump is not installed. Click Install to add it.'
    bpf = ('(udp and (port 1985 or port 3222)) or (ip proto 112) or '
           '(ip6 proto 112)')
    import tempfile
    fd, path = tempfile.mkstemp(suffix='.pcap')
    os.close(fd)
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface, '-p',
                '-nn', '-s', '512', '-c', '20000', '-w', path, bpf],
               timeout=seconds + 8)
    try:
        if (os.path.getsize(path) <= 24 and res['err']
                and ('permission' in res['err'].lower()
                     or "couldn't" in res['err'].lower()
                     or 'no such device' in res['err'].lower()
                     or 'syntax error' in res['err'].lower())):
            return '', [], res['err'].strip()[:200]
        text = _run(['tcpdump', '-nn', '-t', '-v', '-r', path], timeout=20)['out']
        glbp = _fhrp_glbp_extract(path)
        return text, glbp, None
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def do_fhrp_watch(interface=None, seconds=15, learn=True, quick=False):
    """Passive FHRP (HSRP/VRRP/GLBP/CARP) hijack scanner (detection-only). Captures
    FHRP hellos for a few seconds and classifies the segment: hijack / glbp-avf-hijack /
    rogue-speaker / priority-change / glbp-weight-skew / weak-auth / clean. Learns the
    trusted groups + GLBP forwarders on first run."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 15, 4, 40)

    text, glbp_pkts, err = _fhrp_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    events = _parse_fhrp_capture(text)
    # When Scapy byte-decoded GLBP, use those rich AVG events + forwarder plane and
    # drop the best-effort text GLBP events to avoid double-counting.
    glbp_vf = None
    if glbp_pkts:
        glbp_avg, glbp_vf = _fhrp_glbp_from_pkts(glbp_pkts)
        if glbp_avg or glbp_vf:           # decoded something -> prefer the rich events
            events = [e for e in events if e['proto'] != 'glbp'] + glbp_avg
        # else: all GLBP packets were undecodable -> keep the text new-speaker fallback

    with _fhrp_watch_lock:
        baseline = _fhrp_watch_load()
        result = _fhrp_analyze(events, seconds, baseline, learn=learn, glbp_vf=glbp_vf)
        if result.get('learned'):
            _fhrp_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _fhrp_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_FHRP_EVENTS_CAP:]
            _fhrp_watch_save(b)

    result['interface'] = iface
    result['seconds'] = seconds
    return result


def _fhrp_selftest():
    """Self-test the FHRP detectors with synthetic captures (no root, no live
    traffic). Feeds crafted `tcpdump -t -v` text through the real parser + classifier,
    and — if Scapy is available — builds real HSRP + VRRP hellos into a pcap and
    parses them back through tcpdump end to end. Returns a results dict."""
    scenarios = []

    def hsrp(src, group=1, prio=100, state='active', op='hello', vip='192.168.1.1',
             auth='cisco'):
        a = f' auth="{auth}"' if auth is not None else ''
        return (f"    {src}.1985 > 224.0.0.2.1985: HSRPv0-{op} 20: state={state} "
                f"group={group} addr={vip} hellotime=3s holdtime=10s "
                f"priority={prio}{a}")

    def vrrp(src, vrid=1, prio=100, authtype='none', vip='192.168.1.1'):
        return (f"    {src} > 224.0.0.18: VRRPv2, Advertisement, (ttl 255), "
                f"vrid {vrid}, prio {prio}, authtype {authtype}, intvl 1s, "
                f"length 20, addrs: {vip}")

    def run(name, text, seconds, baseline, expect):
        events = _parse_fhrp_capture(text)
        res = _fhrp_analyze(events, seconds, dict(baseline or {}), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'events': len(events), 'pass': ok})
        return res

    # Baseline: HSRP group 1 active=192.168.1.2 prio 110; VRRP vrid 1 active .3 prio 100.
    base = {'groups': {
        'hsrp/1': {'speakers': {'192.168.1.2': 110}, 'vips': ['192.168.1.1'],
                   'max_prio': 110},
        'vrrp/1': {'speakers': {'192.168.1.3': 100}, 'vips': ['192.168.1.1'],
                   'max_prio': 100}}}

    # 1. clean: the known active re-advertising at its known priority (MD5 auth so no
    #    weak-auth), + known VRRP with AH auth.
    run('clean', hsrp('192.168.1.2', prio=110, auth=None) + "\n"
        + vrrp('192.168.1.3', prio=100, authtype='ah'), 15, base, 'clean')

    # 2. hijack: a NEW HSRP speaker advertising priority 255 — wins + becomes gateway.
    run('hijack', hsrp('192.168.1.66', prio=255, auth=None), 15, base, 'hijack')

    # 3. hijack via Coup from a new speaker.
    run('coup', hsrp('192.168.1.66', prio=120, op='coup', auth=None), 15, base,
        'hijack')

    # 4. rogue-speaker: a new speaker but at a losing priority (below the active).
    run('rogue-speaker', hsrp('192.168.1.66', prio=50, auth=None), 15, base,
        'rogue-speaker')

    # 5. priority-change: the known active raises its priority.
    run('priority-change', hsrp('192.168.1.2', prio=200, auth=None), 15, base,
        'priority-change')

    # 6. weak-auth: known speakers but plaintext HSRP auth + VRRP authtype none.
    run('weak-auth', hsrp('192.168.1.2', prio=110, auth='cisco') + "\n"
        + vrrp('192.168.1.3', prio=100, authtype='none'), 15, base, 'weak-auth')

    # 7. vrrp-hijack: a new VRRP speaker at prio 254.
    run('vrrp-hijack', vrrp('192.168.1.77', vrid=1, prio=254, authtype='ah'), 15,
        base, 'hijack')

    # ---- GLBP (byte-decoded: two election planes, AVG + AVF) ----------------
    def glbp_vmac(group, fwd):
        return bytes([0x00, 0x07, 0xb4, 0x00, group & 0xff, fwd & 0xff])

    def glbp_pkt(src, group=1, avg_prio=100, vg_state=0x20, vip='192.168.1.1',
                 forwarders=(), auth=2, include_hello=True):
        """Fabricate a raw GLBP payload (header + optional Hello TLV + VF TLVs + Auth)
        wrapped as a capture record. forwarders: (fwd#, vf_state, vf_prio, weight)."""
        hdr = (bytes([3, 0]) + int(group).to_bytes(2, 'big') + bytes([0, 0])
               + b'\x00\x00\x00\x00\x00\x01')          # owner-id
        body = b''
        if include_hello:
            ipb = bytes(int(x) for x in vip.split('.'))
            hv = (bytes([0, vg_state, 0, avg_prio, 0, 0]) + b'\x00\x00\x00\x00'
                  + b'\x00\x00\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00'
                  + bytes([1, 4]) + ipb)                # addrtype=IPv4, addrlen=4, vip
            body += bytes([1, len(hv) + 2]) + hv
        for (fn, st, pr, wt) in forwarders:
            vfv = bytes([fn, st, 0, pr, wt]) + b'\x00' * 7 + glbp_vmac(group, fn)
            body += bytes([2, len(vfv) + 2]) + vfv
        if auth is not None:
            body += bytes([3, 4, auth, 0])
        return {'src': src, 'src_mac': '00:11:22:33:44:55', 'payload': hdr + body}

    def run_glbp(name, pkts, baseline, expect):
        avg, vf = _fhrp_glbp_from_pkts(pkts)
        res = _fhrp_analyze(avg, 15, dict(baseline or {}), learn=not baseline,
                            glbp_vf=vf)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'events': len(avg) + len(vf), 'pass': ok})
        return res

    # Baseline: GLBP group 1, AVG=.2 prio 100; forwarder 1 owned by .2 with .3 as a
    # legitimate standby speaker (GLBP redundancy — both know the same vMAC).
    gbase = {'groups': {'glbp/1': {'speakers': {'192.168.1.2': 100, '192.168.1.3': 100},
                                   'vips': ['192.168.1.1'], 'max_prio': 100}},
             'glbp_forwarders': {'1/1': {'speakers': ['192.168.1.2', '192.168.1.3'],
                                         'owner': '192.168.1.2',
                                         'vmac': '00:07:b4:00:01:01',
                                         'vf_prio': 167, 'weight': 100}}}

    # 8. glbp-clean: the AVG + its forwarder re-advertising, MD5 auth.
    run_glbp('glbp-clean', [glbp_pkt('192.168.1.2', avg_prio=100,
             forwarders=[(1, 0x20, 167, 100)], auth=2)], gbase, 'clean')

    # 8b. glbp-standby-ok: a legit STANDBY forwarder speaker (.3) sharing the vMAC in
    #     Listen state must NOT be flagged as an AVF hijack (regression guard).
    run_glbp('glbp-standby-ok', [
        glbp_pkt('192.168.1.2', avg_prio=100, forwarders=[(1, 0x20, 167, 100)], auth=2),
        glbp_pkt('192.168.1.3', avg_prio=100, forwarders=[(1, 4, 100, 100)], auth=2)],
        gbase, 'clean')

    # 9. glbp-avg-hijack: a new speaker wins the AVG election (Hello priority 255).
    run_glbp('glbp-avg-hijack', [glbp_pkt('192.168.1.66', avg_prio=255, auth=2)],
             gbase, 'hijack')

    # 10. glbp-avf-hijack: a new speaker goes Active for forwarder 1 (stealth slice
    #     capture) without touching the AVG election — forwarder-plane only.
    run_glbp('glbp-avf-hijack', [glbp_pkt('192.168.1.66',
             forwarders=[(1, 0x20, 167, 100)], auth=2, include_hello=False)],
             gbase, 'glbp-avf-hijack')

    # 11. glbp-weight-skew: the real AVF owner drops its weight 100 -> 20 (load-share
    #     manipulation to steer hosts).
    run_glbp('glbp-weight-skew', [glbp_pkt('192.168.1.2', avg_prio=100,
             forwarders=[(1, 0x20, 167, 20)], auth=2)], gbase, 'glbp-weight-skew')

    # 12. glbp-decode: the byte decoder reads header + Hello + VF + auth correctly.
    dec = _glbp_decode(glbp_pkt('192.168.1.2', group=7, avg_prio=200,
                       forwarders=[(3, 0x20, 150, 80)], auth=1)['payload'])
    d_ok = (dec and dec['group'] == 7 and dec['hello']['priority'] == 200
            and dec['hello']['vg_state'] == 'Active' and dec['auth'] == 'plaintext'
            and dec['forwarders'] and dec['forwarders'][0]['forwarder'] == 3
            and dec['forwarders'][0]['weight'] == 80
            and dec['forwarders'][0]['vmac'] == '00:07:b4:00:07:03')
    scenarios.append({'name': 'glbp-decode', 'expect': 'group7/prio200/fwd3',
                      'got': f"g={dec and dec['group']} "
                             f"vmac={dec and dec['forwarders'][0]['vmac']}",
                      'pass': bool(d_ok)})

    # 13. parse: HSRP fields + VRRP fields + CARP + GLBP.
    pev = _parse_fhrp_capture(
        hsrp('192.168.1.2', prio=255, op='coup') + "\n"
        + vrrp('192.168.1.3', vrid=7, prio=200) + "\n"
        + "    10.0.0.9 > 224.0.0.18: CARPv2-advertise 36: vhid=1 advbase=1 advskew=0\n"
        + "    10.0.0.8.3222 > 224.0.0.102.3222: UDP, length 40")
    protos = {e['proto'] for e in pev}
    hsrp_ev = next((e for e in pev if e['proto'] == 'hsrp'), {})
    p_ok = (protos == {'hsrp', 'vrrp', 'carp', 'glbp'}
            and hsrp_ev.get('opcode') == 'coup' and hsrp_ev.get('priority') == 255
            and hsrp_ev.get('auth_weak') is True)
    scenarios.append({'name': 'fhrp-parse', 'expect': 'hsrp/vrrp/carp/glbp',
                      'got': str(sorted(protos)), 'pass': p_ok})

    # Optional Scapy end-to-end: craft real HSRP + VRRP -> pcap -> tcpdump -> parse,
    # and a real GLBP packet -> pcap -> the byte extractor -> decoder.
    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import Ether, IP, UDP, Raw, wrpcap
        from scapy.layers.hsrp import HSRP
        from scapy.layers.vrrp import VRRP
        if _have('tcpdump'):
            gpayload = glbp_pkt('192.168.1.66', group=1,
                                forwarders=[(1, 0x20, 167, 100)],
                                include_hello=False)['payload']
            pkts = [
                Ether() / IP(src='192.168.1.66', dst='224.0.0.2')
                / UDP(sport=1985, dport=1985)
                / HSRP(group=1, priority=255, state=16, virtualIP='192.168.1.1'),
                Ether() / IP(src='192.168.1.3', dst='224.0.0.18', proto=112)
                / VRRP(vrid=5, priority=254, ipcount=1, addrlist=['192.168.1.1'],
                       version=2),
                Ether(src='de:ad:be:ef:00:66') / IP(src='192.168.1.66',
                dst='224.0.0.102') / UDP(sport=3222, dport=3222) / Raw(gpayload)]
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, pkts)
            res = _run(['tcpdump', '-nn', '-t', '-v', '-r', pcap_path], timeout=10)
            evs = _parse_fhrp_capture(res['out'])
            hs = next((e for e in evs if e['proto'] == 'hsrp'), {})
            vr = next((e for e in evs if e['proto'] == 'vrrp'), {})
            _, gvf = _fhrp_glbp_from_pkts(_fhrp_glbp_extract(pcap_path))
            glbp_ok = bool(gvf) and gvf[0]['forwarder'] == 1 \
                and gvf[0]['vf_state'] == 'Active'
            ok = (hs.get('priority') == 255 and hs.get('src') == '192.168.1.66'
                  and vr.get('priority') == 254 and vr.get('group') == 5 and glbp_ok)
            scapy_result = {'ran': True, 'protos': sorted({e['proto'] for e in evs}),
                            'hsrp_prio': hs.get('priority'),
                            'vrrp_prio': vr.get('priority'),
                            'glbp_vf': len(gvf), 'pass': ok,
                            'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and (not scapy_result.get('ran')
                                                    or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# OSPF Watch: passive OSPF security scanner (detection-only)
# --------------------------------------------------------------------------
# OSPF is the interior routing control plane (IP proto 89, multicast 224.0.0.5/6).
# It is the classic target for route poisoning: without cryptographic auth, any
# host on the segment can inject/spoof LSAs and silently redirect traffic
# (persistent OSPF poisoning, disguised-LSA and fight-back-bypass attacks —
# Nakibly et al.). This scanner is PASSIVE: one short tcpdump window, parsed and
# classified. It never forms an adjacency, never floods an LSA, never touches the
# LSDB — inspired by OSPFwatcher (topology-change monitoring) and FRR-MAD
# (expected-vs-observed LSDB anomaly detection), approximated here from the wire
# with a learned baseline. What it looks for:
#   * weak_auth — Auth Type 0 (none) / 1 (plaintext). The enabler for every
#     injection attack, and the one thing we can always see. Surfaces advisories.
#   * anomaly   — a new/rogue OSPF router (adjacency spoofing), a duplicate
#     Router-ID (RID conflict/spoof), DR takeover, or Hello parameter mismatch.
#   * injection — an LSA whose Advertising Router isn't a known router (spoofed
#     LSA), a MaxSequence (0x7fffffff) or MaxAge fight-provoking LSA, rapid
#     re-origination of one LSA (fight-back = active injection in progress), or a
#     new AS-External (Type-5) originator (route injection / default hijack).
#   * storm     — an LS-Update flood (control-plane DoS).
# Version-specific CVEs (FRR/Quagga ospfd crashes via malformed/opaque LSAs) are
# NOT visible on the wire, so instead of guessing a version we detect the
# exposure conditions and point at OSV for a version lookup (honest by design).

_OSPF_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'data', 'ospf_watch.json')
_ospf_watch_lock = threading.Lock()

_OSPF_MAXAGE = 3600            # LSA MaxAge — used by the premature-aging attack
_OSPF_MAXSEQ = 0x7fffffff      # LSA MaxSequence — used by the seq-wrap attack
# LS-Update rate/sec at or above which the window is a flood (LSU is low-rate).
_OSPF_LSU_STORM_RATE = 20.0
# Distinct increasing sequence numbers for one (lsa-id, adv-router) in the window
# at or above which it's rapid re-origination — the fight-back signature.
_OSPF_FIGHTBACK_SEQS = 4
_OSPF_EVENTS_CAP = 200

# Curated OSPF vulnerability references, surfaced by observed condition. Version-
# specific CVEs can't be fingerprinted passively, so these tie to what IS visible
# (auth posture, opaque/malformed LSAs) and point at OSV for the version lookup.
_OSPF_OSV_URL = 'https://osv.dev/list?ecosystem=&q=frr%20ospfd'
_OSPF_ADVISORIES = {
    'no_auth': {
        'severity': 'high',
        'title': 'OSPF without cryptographic authentication',
        'detail': ('Auth Type 0 (none) or 1 (plaintext) lets any host on the '
                   'segment inject or spoof LSAs — the enabler for persistent '
                   'route poisoning, disguised-LSA and fight-back-bypass attacks '
                   '(Nakibly et al.). Enable RFC 5709 HMAC-SHA cryptographic auth '
                   '(OSPFv2) or IPsec AH/ESP (OSPFv3).'),
        'refs': ['RFC 5709'],
    },
    'opaque_lsa': {
        'severity': 'medium',
        'title': 'Opaque/TE LSAs present — patch ospfd for malformed-LSA crashes',
        'detail': ('Opaque (Type 9/10/11) / TE LSAs are on the segment. Several '
                   'FRRouting ospfd DoS crashes are triggered by malformed opaque '
                   'LSAs (e.g. CVE-2024-27913, CVE-2025-61107, CVE-2025-61105). '
                   'The software version is not visible on the wire — check OSV '
                   'for your ospfd build and patch. Cisco ASA/FTD have had '
                   'equivalent OSPF-LSA DoS advisories.'),
        'refs': ['CVE-2024-27913', 'CVE-2025-61107', 'CVE-2025-61105', _OSPF_OSV_URL],
    },
}

_OSPF_LSA_TYPES = [
    (re.compile(r'\bRouter\s+LSA\b', re.I), 'router'),
    (re.compile(r'\bNetwork\s+LSA\b', re.I), 'network'),
    (re.compile(r'\bASBR[- ]Summary\s+LSA\b', re.I), 'asbr-summary'),
    (re.compile(r'\bSummary\s+LSA\b', re.I), 'summary'),
    (re.compile(r'\b(?:AS[- ]?)?External\s+LSA\b', re.I), 'external'),
    (re.compile(r'\bNSSA\s+LSA\b', re.I), 'nssa'),
    (re.compile(r'\b(?:Opaque|Grace|TE)\s+LSA\b', re.I), 'opaque'),
]
_OSPF_IPRE = r'(\d{1,3}(?:\.\d{1,3}){3})'
_OSPF_HDR_RE = re.compile(r'(?:IP6?\s+)?' + _OSPF_IPRE + r'(?:\.\d+)?\s+>\s+\S+:\s+OSPFv(\d),\s*([^,]+)')


def _ospf_pkt_type(kw):
    k = kw.strip().lower()
    if k.startswith('hello'):
        return 'hello'
    if k.startswith('ls-update') or k.startswith('ls update'):
        return 'lsupdate'
    if k.startswith('ls-ack') or k.startswith('ls ack'):
        return 'lsack'
    if k.startswith('database') or k == 'dd':
        return 'dd'
    if k.startswith('ls-request') or k.startswith('ls request'):
        return 'lsrequest'
    return k.split()[0] if k else 'other'


def _parse_ospf_capture(output):
    """Parse `tcpdump -nn -v 'proto ospf'` text into a list of packet dicts:
    {src, version, type, router_id, area, auth, hello{...}, lsas[...]}. Tolerant
    of tcpdump version differences — it keys off the OSPFv2/OSPFv3 header line and
    pulls whatever fields it can from the indented body of each packet."""
    packets = []
    cur = None

    def flush():
        if cur is not None:
            packets.append(cur)

    for raw in output.splitlines():
        line = raw.rstrip()
        h = _OSPF_HDR_RE.search(line)
        if h:
            flush()
            cur = {'src': h.group(1), 'version': int(h.group(2)),
                   'type': _ospf_pkt_type(h.group(3)), 'router_id': None,
                   'area': None, 'auth': None,
                   'hello': None, 'adv_router': None, 'lsas': []}
            continue
        if cur is None:
            continue
        rid = re.search(r'Router-ID\s+' + _OSPF_IPRE, line)
        if rid:
            cur['router_id'] = rid.group(1)
        if cur['area'] is None:
            if re.search(r'Backbone Area', line):
                cur['area'] = '0.0.0.0'
            else:
                am = re.search(r'\bArea\s+' + _OSPF_IPRE, line)
                if am:
                    cur['area'] = am.group(1)
        au = re.search(r'Authentication Type:\s*\w+\s*\((\d)\)', line)
        if au:
            cur['auth'] = int(au.group(1))
        av = re.search(r'Advertising Router:?\s+' + _OSPF_IPRE, line)
        if av and cur['adv_router'] is None:
            cur['adv_router'] = av.group(1)
        # Real tcpdump prints the per-LSA "Advertising Router X, seq 0x.., age Ns"
        # line BEFORE the "X LSA (n), LSA-ID: Y" line, so stash that metadata and
        # attach it to the next LSA header. (The self-test's single-line format
        # carries seq/age on the header line itself; both are handled below.)
        meta = re.search(r'Advertising Router:?\s+' + _OSPF_IPRE +
                         r',\s*seq\s+(0x[0-9a-fA-F]+)(?:,\s*age\s+(\d+))?', line)
        if meta:
            cur['_pend_lsa'] = {'adv': meta.group(1), 'seq': int(meta.group(2), 16),
                                'age': int(meta.group(3)) if meta.group(3) else None}
        if cur['type'] == 'hello':
            hp = cur['hello'] or {'hello_timer': None, 'dead_timer': None,
                                  'mask': None, 'dr': None, 'neighbors': []}
            ht = re.search(r'Hello Timer\s+(\d+)s', line)
            if ht:
                hp['hello_timer'] = int(ht.group(1))
            dt = re.search(r'Dead Timer\s+(\d+)s', line)
            if dt:
                hp['dead_timer'] = int(dt.group(1))
            mk = re.search(r'Mask\s+' + _OSPF_IPRE, line)
            if mk:
                hp['mask'] = mk.group(1)
            dr = re.search(r'Designated Router(?:\s+\(ID\))?\s+' + _OSPF_IPRE, line)
            if dr:
                hp['dr'] = dr.group(1)
            nb = re.search(r'Neighbor\s+' + _OSPF_IPRE, line)
            if nb:
                hp['neighbors'].append(nb.group(1))
            cur['hello'] = hp
        # LSA header line ("X LSA (n), LSA-ID: Y"). Require an LSA-ID so sub-lines
        # like "Router LSA Options: [none]" don't get parsed as ghost LSAs. seq/
        # age/adv come from this line if present (single-line format), else from
        # the preceding "Advertising Router ..." metadata line (real tcpdump).
        for rx, lsa_type in _OSPF_LSA_TYPES:
            if rx.search(line):
                lid = re.search(r'LSA-ID:?\s+' + _OSPF_IPRE, line)
                if not lid:
                    break
                pend = cur.get('_pend_lsa') or {}
                adv = re.search(r'Advertising Router:?\s+' + _OSPF_IPRE, line)
                sq = re.search(r'seq\s+(0x[0-9a-fA-F]+)', line)
                ag = re.search(r'age\s+(\d+)', line)
                cur['lsas'].append({
                    'lsa_type': lsa_type,
                    'lsa_id': lid.group(1),
                    'adv_router': (adv.group(1) if adv else
                                   pend.get('adv') or cur.get('adv_router')),
                    'seq': int(sq.group(1), 16) if sq else pend.get('seq'),
                    'age': int(ag.group(1)) if ag else pend.get('age'),
                })
                cur['_pend_lsa'] = None
                break
    flush()
    return packets


def _ospf_watch_load():
    try:
        with open(_OSPF_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _ospf_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_OSPF_WATCH_PATH), exist_ok=True)
        tmp = _OSPF_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _OSPF_WATCH_PATH)
    except OSError:
        pass


def do_ospf_baseline(action='get'):
    """Manage the learned OSPF baseline (trusted routers + Type-5 originators).
    action='reset' clears it so the current segment is re-learned next scan."""
    with _ospf_watch_lock:
        if action == 'reset':
            _ospf_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _ospf_watch_load()
        return {'success': True, 'baseline': {
            'routers': sorted(b.get('routers') or []),
            'asbrs': sorted(b.get('asbrs') or []),
        }}


def _ospf_analyze(packets, seconds, baseline, learn=True):
    """Pure classifier over parsed OSPF packets. Returns the result payload
    (minus interface). Split from capture so the self-test can drive it with
    synthetic packets. May mutate+persist `baseline` when learn=True."""
    seconds = max(1, int(seconds))
    hellos = [p for p in packets if p['type'] == 'hello']
    lsupdates = [p for p in packets if p['type'] == 'lsupdate']
    total = len(packets)

    # routers seen (via Hello Router-ID), and the src IP(s) each was seen from
    rid_srcs = {}
    for p in hellos:
        if p.get('router_id'):
            rid_srcs.setdefault(p['router_id'], set()).add(p.get('src'))
    routers_seen = set(rid_srcs.keys())

    # auth posture
    auth_types = sorted({p['auth'] for p in packets if p.get('auth') is not None})

    # all LSAs, flattened
    lsas = []
    for p in lsupdates:
        for l in p['lsas']:
            l = dict(l)
            l['pkt_src'] = p.get('src')
            l['pkt_router_id'] = p.get('router_id')
            lsas.append(l)
    adv_routers = {l['adv_router'] for l in lsas if l.get('adv_router')}
    asbrs_seen = {l['adv_router'] for l in lsas
                  if l.get('lsa_type') == 'external' and l.get('adv_router')}
    has_opaque = any(l.get('lsa_type') == 'opaque' for l in lsas)

    trusted_routers = set(baseline.get('routers') or [])
    trusted_asbrs = set(baseline.get('asbrs') or [])
    known_advs = set(baseline.get('advs') or []) | trusted_routers
    learned = False
    have_baseline = bool(trusted_routers or known_advs or baseline.get('asbrs') is not None)
    if learn and not have_baseline and (routers_seen or adv_routers):
        baseline['routers'] = sorted(routers_seen)
        baseline['advs'] = sorted(adv_routers | routers_seen)
        baseline['asbrs'] = sorted(asbrs_seen)
        learned = True
        trusted_routers = set(routers_seen)
        known_advs = adv_routers | routers_seen
        trusted_asbrs = set(asbrs_seen)
        have_baseline = True

    findings = []      # (level, category, text)
    categories = set()
    advisories = []

    # weak / no authentication
    if 0 in auth_types:
        categories.add('weak_auth')
        advisories.append(dict(_OSPF_ADVISORIES['no_auth'], key='no_auth'))
        findings.append(('warn', 'weak_auth',
                         'OSPF packets use Authentication Type 0 (none) — any host '
                         'can inject LSAs; enable cryptographic auth'))
    if 1 in auth_types:
        categories.add('weak_auth')
        if not any(a.get('key') == 'no_auth' for a in advisories):
            advisories.append(dict(_OSPF_ADVISORIES['no_auth'], key='no_auth'))
        findings.append(('warn', 'weak_auth',
                         'OSPF uses Authentication Type 1 (plaintext) — trivially '
                         'forged; move to cryptographic (HMAC) auth'))

    # storm
    lsu_rate = round(len(lsupdates) / seconds, 1)
    if lsu_rate >= _OSPF_LSU_STORM_RATE:
        categories.add('storm')
        findings.append(('crit', 'storm',
                         f'{len(lsupdates)} LS-Updates in {seconds}s ({lsu_rate}/s) '
                         '— OSPF flooding / control-plane DoS'))

    # rogue / new router (adjacency spoofing)
    if have_baseline:
        for rid in sorted(routers_seen - trusted_routers):
            categories.add('anomaly')
            findings.append(('warn', 'anomaly',
                             f'new OSPF router {rid} (from {", ".join(sorted(s for s in rid_srcs[rid] if s))}) '
                             '— not in the learned baseline (possible rogue adjacency)'))
    # duplicate Router-ID (conflict / spoof)
    for rid, srcs in rid_srcs.items():
        real = {s for s in srcs if s}
        if len(real) > 1:
            categories.add('anomaly')
            findings.append(('crit', 'anomaly',
                             f'Router-ID {rid} claimed by multiple sources '
                             f'({", ".join(sorted(real))}) — Router-ID conflict or spoof'))
    # Hello parameter mismatch on the segment
    hp_params = {(p['hello'].get('hello_timer'), p['hello'].get('dead_timer'), p.get('area'))
                 for p in hellos if p.get('hello')}
    hp_params = {x for x in hp_params if x != (None, None, None)}
    if len(hp_params) > 1:
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         'mismatched Hello parameters (hello/dead timer or area) on '
                         'the segment — misconfig or an attacker probing for adjacency'))

    # injection — spoofed advertising router
    if have_baseline:
        spoofed = sorted({a for a in adv_routers if a not in known_advs and a not in routers_seen})
        for a in spoofed:
            categories.add('injection')
            findings.append(('crit', 'injection',
                             f'LSA advertised by {a}, which never announced itself via '
                             'Hello and is not in the baseline — spoofed/injected LSA'))
        # new AS-External (Type-5) originator — route injection / default hijack
        for a in sorted(asbrs_seen - trusted_asbrs):
            categories.add('injection')
            findings.append(('crit', 'injection',
                             f'new AS-External (Type-5) LSAs from {a} — not a known '
                             'ASBR; possible route injection / default-route hijack'))

    # MaxSequence / MaxAge attack signatures
    if any(l.get('seq') == _OSPF_MAXSEQ for l in lsas):
        categories.add('injection')
        findings.append(('crit', 'injection',
                         'LSA with MaxSequence (0x7fffffff) — sequence-wrap attack to '
                         'force LSDB reset'))
    # MaxAge for an LSA-ID that is ALSO seen fresh in the window = premature-aging
    fresh_ids = {l['lsa_id'] for l in lsas if l.get('age') is not None and l['age'] < _OSPF_MAXAGE}
    maxage_hot = sorted({l['lsa_id'] for l in lsas
                         if l.get('age') is not None and l['age'] >= _OSPF_MAXAGE
                         and l['lsa_id'] in fresh_ids and l['lsa_id']})
    for lid in maxage_hot:
        categories.add('injection')
        findings.append(('warn', 'injection',
                         f'LSA {lid} flooded at MaxAge while also fresh — premature-'
                         'aging (MaxAge) attack to flush it from the LSDB'))

    # fight-back — rapid re-origination of one (lsa-id, adv-router)
    seq_by_lsa = {}
    for l in lsas:
        if l.get('lsa_id') and l.get('adv_router') and l.get('seq') is not None:
            seq_by_lsa.setdefault((l['lsa_id'], l['adv_router']), set()).add(l['seq'])
    for (lid, adv), seqs in seq_by_lsa.items():
        if len(seqs) >= _OSPF_FIGHTBACK_SEQS:
            categories.add('injection')
            findings.append(('crit', 'injection',
                             f'LSA {lid} from {adv} re-originated {len(seqs)} times with '
                             'rising sequence — fight-back: the owner is countering an '
                             'active LSA injection'))

    if has_opaque:
        advisories.append(dict(_OSPF_ADVISORIES['opaque_lsa'], key='opaque_lsa'))

    # version anomaly
    versions = sorted({p['version'] for p in packets})
    if len(versions) > 1:
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         f'mixed OSPF versions {versions} on the segment'))

    order = ['storm', 'injection', 'anomaly', 'weak_auth']
    verdict = next((c for c in order if c in categories), 'clean')
    if not findings:
        findings.append(('ok', 'clean', 'No OSPF anomalies in the capture window.'))

    routers_out = []
    for rid in sorted(routers_seen):
        routers_out.append({'router_id': rid,
                            'sources': sorted(s for s in rid_srcs[rid] if s),
                            'new': bool(have_baseline and rid not in trusted_routers)})
    lsa_summary = {}
    for l in lsas:
        lsa_summary[l['lsa_type']] = lsa_summary.get(l['lsa_type'], 0) + 1

    return {
        'success': True, 'verdict': verdict, 'seconds': seconds,
        'packets': total, 'hellos': len(hellos), 'ls_updates': len(lsupdates),
        'lsu_per_s': lsu_rate, 'learned': learned,
        'auth_types': auth_types, 'versions': versions,
        'routers': routers_out, 'trusted_routers': sorted(trusted_routers),
        'lsa_counts': lsa_summary,
        'advisories': [{'key': a.get('key'), 'severity': a['severity'],
                        'title': a['title'], 'detail': a['detail'],
                        'refs': a.get('refs', [])} for a in advisories],
        'findings': [{'level': l, 'category': c, 'text': t} for l, c, t in findings],
        'reasons': [t for _l, _c, t in findings if _l != 'ok'],
    }


def _ospf_capture(interface, seconds):
    """Run one passive tcpdump OSPF window and return (raw_text, error)."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface,
                '-nn', '-t', '-v', '-s', '512', '-c', '20000', 'proto', 'ospf'],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_ospf_watch(interface=None, seconds=15, learn=True, quick=False):
    """Passive OSPF security scanner (detection-only). Captures OSPF for a few
    seconds and classifies the segment: weak_auth / anomaly / injection / storm /
    clean, with CVE/OSV advisories for observed exposure conditions. Learns the
    routers + Type-5 originators on first run; never forms an adjacency."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 15, 5, 40)

    text, err = _ospf_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    packets = _parse_ospf_capture(text)

    with _ospf_watch_lock:
        baseline = _ospf_watch_load()
        result = _ospf_analyze(packets, seconds, baseline, learn=learn)
        if result.get('learned'):
            _ospf_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _ospf_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_OSPF_EVENTS_CAP:]
            _ospf_watch_save(b)

    if not packets:
        result['note'] = ('No OSPF seen — this segment may not run OSPF, or the Pi '
                          'is not on the OSPF broadcast domain (put it on a SPAN/'
                          'mirror or the routed VLAN to observe).')
    result['interface'] = iface
    return result


def _ospf_selftest():
    """Self-test the OSPF detectors with synthetic tcpdump captures (no root, no
    live traffic), plus an optional Scapy end-to-end leg (scapy.contrib.ospf ->
    pcap -> tcpdump -> parse). Mirrors the IGMP/MAC Watch self-tests."""
    scenarios = []

    def run(name, text, seconds, baseline, expect):
        pkts = _parse_ospf_capture(text)
        res = _ospf_analyze(pkts, seconds, dict(baseline), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'packets': len(pkts), 'pass': ok})
        return res

    base = {'routers': ['10.0.0.1', '10.0.0.2'],
            'advs': ['10.0.0.1', '10.0.0.2'], 'asbrs': ['10.0.0.1']}

    clean = "\n".join([
        "10.0.0.1 > 224.0.0.5: OSPFv2, Hello, length 48",
        "\tRouter-ID 10.0.0.1, Backbone Area, Authentication Type: Cryptographic (2)",
        "\tHello Timer 10s, Dead Timer 40s, Mask 255.255.255.0",
        "10.0.0.2 > 224.0.0.5: OSPFv2, LS-Update, length 64",
        "\tRouter-ID 10.0.0.2, Backbone Area, Authentication Type: Cryptographic (2)",
        "\tRouter LSA (1), LSA-ID: 10.0.0.2, Advertising Router: 10.0.0.2, seq 0x80000005, age 12",
    ])
    run('clean', clean, 15, base, 'clean')

    weak = "\n".join([
        "10.0.0.1 > 224.0.0.5: OSPFv2, Hello, length 48",
        "\tRouter-ID 10.0.0.1, Backbone Area, Authentication Type: none (0)",
        "\tHello Timer 10s, Dead Timer 40s, Mask 255.255.255.0",
    ])
    run('weak_auth', weak, 15, base, 'weak_auth')

    rogue = "\n".join([
        "10.0.0.9 > 224.0.0.5: OSPFv2, Hello, length 48",
        "\tRouter-ID 10.0.0.9, Backbone Area, Authentication Type: Cryptographic (2)",
        "\tHello Timer 10s, Dead Timer 40s, Mask 255.255.255.0",
    ])
    run('anomaly', rogue, 15, base, 'anomaly')

    inject = "\n".join([
        "10.0.0.66 > 224.0.0.5: OSPFv2, LS-Update, length 64",
        "\tRouter-ID 10.0.0.1, Backbone Area, Authentication Type: Cryptographic (2)",
        "\tRouter LSA (1), LSA-ID: 10.0.0.66, Advertising Router: 10.0.0.66, seq 0x80000002, age 1",
    ])
    run('injection', inject, 15, base, 'injection')

    maxseq = "\n".join([
        "10.0.0.1 > 224.0.0.5: OSPFv2, LS-Update, length 64",
        "\tRouter-ID 10.0.0.1, Backbone Area, Authentication Type: Cryptographic (2)",
        "\tRouter LSA (1), LSA-ID: 10.0.0.1, Advertising Router: 10.0.0.1, seq 0x7fffffff, age 1",
    ])
    run('injection-maxseq', maxseq, 15, base, 'injection')

    # parser check: a full LS-Update parses out the LSA fields.
    p = _parse_ospf_capture(clean)
    lsu = [x for x in p if x['type'] == 'lsupdate']
    parse_ok = bool(lsu and lsu[0]['lsas'] and
                    lsu[0]['lsas'][0]['adv_router'] == '10.0.0.2' and
                    lsu[0]['lsas'][0]['seq'] == 0x80000005)
    scenarios.append({'name': 'lsa-parse', 'expect': 'adv=10.0.0.2 seq=0x80000005',
                      'got': str(lsu[0]['lsas'][0] if lsu and lsu[0]['lsas'] else None),
                      'pass': parse_ok})

    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import IP, Ether, wrpcap  # noqa
        try:
            from scapy.contrib.ospf import (OSPF_Hdr, OSPF_Hello, OSPF_LSUpd,
                                            OSPF_Router_LSA)
        except Exception:
            OSPF_Hdr = None
        if OSPF_Hdr is not None and _have('tcpdump'):
            hello = (Ether() / IP(src='10.0.0.5', dst='224.0.0.5', proto=89) /
                     OSPF_Hdr(version=2, type=1, src='10.0.0.5', area='0.0.0.0',
                              authtype=0) / OSPF_Hello(mask='255.255.255.0'))
            # An LS-Update too: real tcpdump prints seq/age on the "Advertising
            # Router" line ABOVE the "Router LSA, LSA-ID" line — the layout that
            # broke seq/age parsing (and MaxSeq/MaxAge/fight-back) until fixed.
            lsu = (Ether() / IP(src='10.0.0.5', dst='224.0.0.5', proto=89) /
                   OSPF_Hdr(version=2, type=4, src='10.0.0.5', area='0.0.0.0') /
                   OSPF_LSUpd(lsalist=[OSPF_Router_LSA(id='10.0.0.5', adrouter='10.0.0.5',
                                                       seq=0x80000005, age=1)]))
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, [hello, lsu])
            res = _run(['tcpdump', '-nn', '-t', '-v', '-r', pcap_path, 'proto', 'ospf'],
                       timeout=10)
            parsed = _parse_ospf_capture(res['out'])
            got_auth = next((x.get('auth') for x in parsed if x.get('auth') is not None), None)
            lsas = [l for x in parsed for l in x.get('lsas', [])]
            # Regression guard: seq parsed off REAL tcpdump, and no ghost LSAs
            # (sub-lines like "Router LSA Options" must not create lsa_id=None).
            seq_ok = any(l.get('seq') == 0x80000005 for l in lsas)
            no_ghost = all(l.get('lsa_id') for l in lsas)
            scapy_result = {'ran': True, 'parsed_packets': len(parsed),
                            'auth': got_auth, 'lsa_seq_parsed': seq_ok,
                            'no_ghost_lsa': no_ghost, 'lsas': len(lsas),
                            'pass': len(parsed) >= 1 and seq_ok and no_ghost,
                            'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and \
        (not scapy_result.get('ran') or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


# --------------------------------------------------------------------------
# BGP Path Watch: passive BGP routing-security scanner (detection-only)
# --------------------------------------------------------------------------
# BGP is the exterior/edge routing control plane (TCP 179). Unlike OSPF it is
# unicast between peers, so the Pi only sees it when it is INLINE, on a SPAN/
# mirror, or is itself a peer — this is made explicit in the UI. Where visible,
# BGP is the highest-value thing to watch: origin hijacks, sub-prefix hijacks,
# route leaks and session resets are how traffic gets silently redirected across
# the Internet edge. This scanner is PASSIVE: one short tcpdump window parsed and
# classified. It never opens a session, never announces or withdraws a route.
# Companion to OSPF Watch (L3 routing security). What it looks for:
#   * injection — an announced prefix whose ORIGIN AS changed vs the baseline
#     (prefix / origin hijack), or a new more-specific of a baseline prefix
#     (sub-prefix hijack — the most effective real-world BGP attack).
#   * anomaly   — a new/rogue peer (new AS or BGP-ID), a NOTIFICATION / session
#     reset (teardown / flap), a private or bogon ASN in a received AS-path
#     (route leak), a bogon/martian prefix announcement, an AS-path loop, or a
#     BLACKHOLE community (65535:666).
#   * storm     — a route-churn / UPDATE flood, or a per-peer prefix-count spike
#     (full-table leak).
#   * weak_session — BGP seen but no TCP-MD5/TCP-AO signature (RFC 2385/5925);
#     exposed to off-path session-reset attacks. Advisory only.
# Version CVEs (FRR/BIRD bgpd crashes on malformed UPDATE attributes) aren't on
# the wire, so — as with OSPF — the exposure conditions are flagged and OSV is
# pointed at for the version lookup.

_BGP_WATCH_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'data', 'bgp_watch.json')
_bgp_watch_lock = threading.Lock()

# UPDATE messages/sec at or above which the window is churn/flood.
_BGP_STORM_RATE = 40.0
# A peer announcing at or above this many prefixes in the window, when the
# baseline saw far fewer, is a route-leak (full-table) signature.
_BGP_LEAK_PREFIXES = 500
_BGP_EVENTS_CAP = 200

# Bogon / martian IPv4 prefixes that should never be announced in BGP.
_BGP_BOGON_NETS = [
    ('0.0.0.0', 8), ('10.0.0.0', 8), ('100.64.0.0', 10), ('127.0.0.0', 8),
    ('169.254.0.0', 16), ('172.16.0.0', 12), ('192.0.0.0', 24),
    ('192.0.2.0', 24), ('192.168.0.0', 16), ('198.18.0.0', 15),
    ('198.51.100.0', 24), ('203.0.113.0', 24), ('224.0.0.0', 4), ('240.0.0.0', 4),
]

_BGP_OSV_URL = 'https://osv.dev/list?ecosystem=&q=frr%20bgpd'
_BGP_ADVISORIES = {
    'no_md5': {
        'severity': 'medium',
        'title': 'BGP sessions without TCP-MD5 / TCP-AO authentication',
        'detail': ('No TCP-MD5 (RFC 2385) or TCP-AO (RFC 5925) signature was seen '
                   'on the BGP session. Unauthenticated sessions are exposed to '
                   'off-path RST/session-reset attacks and easier hijacking. '
                   'Enable TCP-MD5/TCP-AO and RPKI Route Origin Validation to '
                   'reject invalid origins.'),
        'refs': ['RFC 2385', 'RFC 5925', 'RFC 6811'],
    },
    'malformed_attr': {
        'severity': 'medium',
        'title': 'Patch bgpd for malformed BGP-UPDATE attribute crashes',
        'detail': ('Malformed BGP path attributes have repeatedly crashed router '
                   'BGP daemons (e.g. FRRouting CVE-2023-38802 via a corrupted '
                   'Tunnel-Encapsulation attribute; CERT VU#347067 covers multiple '
                   'implementations). The software version is not visible on the '
                   'wire — check OSV for your bgpd build and patch.'),
        'refs': ['CVE-2023-38802', 'VU#347067', _BGP_OSV_URL],
    },
}

# Classify an ASN. Only 'reserved' / 'documentation' ASNs are truly illegitimate
# in any AS-path; 'private' (RFC 6996) is normal on internal/DC BGP fabric — which
# is exactly where a passive Pi is most likely to sit — so it is NOT alerted on.
def _bgp_asn_class(asn):
    if asn in (0, 23456, 65535, 4294967295):
        return 'reserved'
    if 64496 <= asn <= 64511 or 65536 <= asn <= 65551:   # RFC 5398 documentation
        return 'documentation'
    if 64512 <= asn <= 65534 or 4200000000 <= asn <= 4294967294:  # RFC 6996 private
        return 'private'
    return None


def _ip_to_int(ip):
    try:
        a, b, c, d = (int(x) for x in ip.split('.'))
        return (a << 24) | (b << 16) | (c << 8) | d
    except (ValueError, AttributeError):
        return None


def _bgp_is_bogon(prefix):
    """True if an IPv4 CIDR announcement falls inside a bogon/martian net."""
    try:
        net, length = prefix.split('/')
        length = int(length)
    except ValueError:
        return False
    n = _ip_to_int(net)
    if n is None:
        return False
    if length < 8:            # absurdly short — /0../7 (near-default hijack)
        return True
    for bnet, blen in _BGP_BOGON_NETS:
        bn = _ip_to_int(bnet)
        if bn is None:
            continue
        mask = (0xffffffff << (32 - blen)) & 0xffffffff
        if length >= blen and (n & mask) == (bn & mask):
            return True
    return False


_BGP_IPRE = r'(\d{1,3}(?:\.\d{1,3}){3})'
_BGP_CIDR_RE = re.compile(r'^' + _BGP_IPRE + r'/(\d{1,2})\s*$')
_BGP_HDR_RE = re.compile(r'(?:IP6?\s+)?' + _BGP_IPRE + r'\.(\d+)\s+>\s+' + _BGP_IPRE + r'\.(\d+):')


def _parse_bgp_capture(output):
    """Parse `tcpdump -nn -t -v 'tcp port 179'` text into BGP messages:
    {src, dst, type, ...}. Tolerant of tcpdump version differences — keys off the
    'Open/Update/Notification/Keepalive Message' lines and pulls whatever path
    attributes and NLRI it can from the indented body."""
    messages = []
    cur = None
    flow = (None, None)   # (src, dst) of the current TCP segment
    nlri_mode = None      # 'announced' | 'withdrawn'
    md5_seen = ['md5' in output.lower()]

    def flush():
        if cur is not None:
            messages.append(cur)

    for raw in output.splitlines():
        line = raw.rstrip()
        h = _BGP_HDR_RE.search(line)
        if h:
            # 179 side is the sender's BGP port; keep src/dst as printed.
            flow = (h.group(1), h.group(3))
        mt = re.search(r'\b(Open|Update|Notification|Keepalive|Route Refresh)\s+Message\b', line)
        if mt:
            flush()
            nlri_mode = None
            cur = {'src': flow[0], 'dst': flow[1],
                   'type': mt.group(1).lower().replace(' ', '_'),
                   'my_as': None, 'holdtime': None, 'bgp_id': None, 'version': None,
                   'as_path': [], 'origin': None, 'next_hop': None,
                   'communities': [], 'announced': [], 'withdrawn': [],
                   'notif_code': None, 'notif_sub': None}
            if cur['type'] == 'open':
                m = re.search(r'my AS\s+(\d+)', line)
                if m:
                    cur['my_as'] = int(m.group(1))
                m = re.search(r'Holdtime\s+(\d+)', line)
                if m:
                    cur['holdtime'] = int(m.group(1))
                m = re.search(r'\bID\s+' + _BGP_IPRE, line)
                if m:
                    cur['bgp_id'] = m.group(1)
            if cur['type'] == 'notification':
                m = re.search(r'Message\s*\(3\),[^,]*,\s*([A-Za-z /]+?)\s*\((\d+)\)', line)
                if m:
                    cur['notif_code'] = m.group(1).strip()
                m = re.search(r'subcode\s+([A-Za-z /]+?)\s*\((\d+)\)', line)
                if m:
                    cur['notif_sub'] = m.group(1).strip()
            continue
        if cur is None:
            continue
        # OPEN continuation
        if cur['type'] == 'open':
            if cur['my_as'] is None:
                m = re.search(r'my AS\s+(\d+)', line)
                if m:
                    cur['my_as'] = int(m.group(1))
            if cur['bgp_id'] is None:
                m = re.search(r'\bID\s+' + _BGP_IPRE, line)
                if m:
                    cur['bgp_id'] = m.group(1)
        # UPDATE attributes + NLRI
        if cur['type'] == 'update':
            # AS numbers come after the final colon (past "length: N, Flags [T]:").
            ap = re.search(r'AS Path\b.*:\s*([0-9][0-9 {},]*)\s*$', line)
            if ap and not cur['as_path']:
                cur['as_path'] = [int(x) for x in re.findall(r'\d+', ap.group(1))]
            og = re.search(r'\bOrigin\b.*?:\s*(IGP|EGP|Incomplete)', line)
            if og:
                cur['origin'] = og.group(1)
            nh = re.search(r'Next Hop\b.*?:\s*' + _BGP_IPRE, line)
            if nh:
                cur['next_hop'] = nh.group(1)
            if re.search(r'\bCommunity\b', line):
                for tok in re.findall(r'\b(\d{1,10}:\d{1,10})\b', line):
                    cur['communities'].append(tok)
            if re.search(r'blackhole', line, re.I):
                cur['communities'].append('blackhole')
            if re.search(r'Updated routes|Advertised routes|Prefixes', line, re.I):
                nlri_mode = 'announced'
            elif re.search(r'Withdrawn routes', line, re.I):
                nlri_mode = 'withdrawn'
            cidr = _BGP_CIDR_RE.match(line.strip())
            if cidr and nlri_mode:
                pfx = f'{cidr.group(1)}/{cidr.group(2)}'
                cur[nlri_mode].append(pfx)
    flush()
    for m in messages:
        m['md5'] = md5_seen[0]
    return messages


def _bgp_watch_load():
    try:
        with open(_BGP_WATCH_PATH) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _bgp_watch_save(d):
    try:
        os.makedirs(os.path.dirname(_BGP_WATCH_PATH), exist_ok=True)
        tmp = _BGP_WATCH_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, _BGP_WATCH_PATH)
    except OSError:
        pass


def do_bgp_baseline(action='get'):
    """Manage the learned BGP baseline (trusted peer ASNs + prefix→origin map).
    action='reset' re-learns the current peers/origins on the next scan."""
    with _bgp_watch_lock:
        if action == 'reset':
            _bgp_watch_save({})
            return {'success': True, 'reset': True, 'baseline': {}}
        b = _bgp_watch_load()
        return {'success': True, 'baseline': {
            'peers': sorted(b.get('peers') or []),
            'prefixes': len((b.get('origins') or {})),
        }}


def _bgp_analyze(messages, seconds, baseline, learn=True):
    """Pure classifier over parsed BGP messages. Returns the result payload
    (minus interface). Split from capture so the self-test can drive it."""
    seconds = max(1, int(seconds))
    opens = [m for m in messages if m['type'] == 'open']
    updates = [m for m in messages if m['type'] == 'update']
    notifs = [m for m in messages if m['type'] == 'notification']
    total = len(messages)

    peers = sorted({m['my_as'] for m in opens if m.get('my_as')})
    peer_ids = sorted({m['bgp_id'] for m in opens if m.get('bgp_id')})
    md5 = any(m.get('md5') for m in messages)

    # prefix -> origin AS (rightmost ASN in the path), and per-peer prefix counts
    origins = {}
    per_peer_prefixes = {}
    for m in updates:
        origin_as = m['as_path'][-1] if m.get('as_path') else None
        src = m.get('src')
        for pfx in m.get('announced', []):
            origins.setdefault(pfx, origin_as)
            per_peer_prefixes.setdefault(src, set()).add(pfx)

    trusted_peers = set(baseline.get('peers') or [])
    base_origins = dict(baseline.get('origins') or {})
    base_counts = dict(baseline.get('prefix_count') or {})
    have_baseline = bool(trusted_peers or base_origins or baseline.get('peers') is not None)
    learned = False
    if learn and not have_baseline and (peers or origins):
        baseline['peers'] = peers
        baseline['origins'] = {p: o for p, o in origins.items() if o is not None}
        baseline['prefix_count'] = {s: len(v) for s, v in per_peer_prefixes.items()}
        learned = True
        trusted_peers = set(peers)
        base_origins = dict(baseline['origins'])
        have_baseline = True

    findings = []
    categories = set()
    advisories = []

    # storm — UPDATE churn
    upd_rate = round(len(updates) / seconds, 1)
    if upd_rate >= _BGP_STORM_RATE:
        categories.add('storm')
        findings.append(('crit', 'storm',
                         f'{len(updates)} BGP UPDATEs in {seconds}s ({upd_rate}/s) '
                         '— route churn / flooding'))
    # route leak — per-peer prefix-count spike
    for src, pfxs in per_peer_prefixes.items():
        base_n = base_counts.get(src, 0)
        if len(pfxs) >= _BGP_LEAK_PREFIXES and (not base_n or len(pfxs) > base_n * 5):
            categories.add('storm')
            findings.append(('crit', 'storm',
                             f'peer {src} announced {len(pfxs)} prefixes '
                             f'(baseline {base_n or "—"}) — possible full-table route leak'))

    # injection — origin hijack (same prefix, different origin AS)
    if have_baseline:
        for pfx, origin_as in origins.items():
            b = base_origins.get(pfx)
            if b is not None and origin_as is not None and origin_as != b:
                categories.add('injection')
                findings.append(('crit', 'injection',
                                 f'prefix {pfx} now originated by AS{origin_as} '
                                 f'(baseline AS{b}) — BGP origin hijack'))
        # sub-prefix hijack — a new more-specific of a baseline prefix
        for pfx, origin_as in origins.items():
            if pfx in base_origins:
                continue
            for bpfx, bas in base_origins.items():
                if _bgp_prefix_covers(bpfx, pfx) and origin_as != bas:
                    categories.add('injection')
                    findings.append(('crit', 'injection',
                                     f'more-specific {pfx} (inside baseline {bpfx}) '
                                     f'from AS{origin_as} — sub-prefix hijack'))
                    break

    # anomaly — new/rogue peer
    if have_baseline:
        for asn in peers:
            if asn not in trusted_peers:
                categories.add('anomaly')
                findings.append(('warn', 'anomaly',
                                 f'new BGP peer AS{asn} — not in the learned baseline'))
    # session reset / teardown
    for m in notifs:
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         f'BGP NOTIFICATION ({m.get("notif_code") or "?"}'
                         f'{"/" + m["notif_sub"] if m.get("notif_sub") else ""}) '
                         '— session reset / teardown'))
    # private / bogon ASN in a received path
    seen_bad_asn = set()
    for m in updates:
        for asn in m.get('as_path', []):
            klass = _bgp_asn_class(asn)
            # private ASNs are normal on internal/DC fabric — only alert on
            # reserved/documentation ASNs, which are never legitimate in a path.
            if klass in ('reserved', 'documentation') and asn not in seen_bad_asn:
                seen_bad_asn.add(asn)
                categories.add('anomaly')
                findings.append(('warn', 'anomaly',
                                 f'{klass} ASN {asn} in a received AS-path — route leak / misconfig'))
        # AS-path loop (an ASN appears more than once non-adjacently)
        path = m.get('as_path', [])
        # collapse consecutive repeats (legitimate prepending), then a repeat
        # of the same ASN is a loop
        dedup = [a for i, a in enumerate(path) if i == 0 or a != path[i - 1]]
        if len(dedup) != len(set(dedup)):
            categories.add('anomaly')
            findings.append(('warn', 'anomaly',
                             f'AS-path loop in {" ".join(map(str, path))}'))
    # bogon / martian prefix announcement
    bogons = sorted({p for p in origins if _bgp_is_bogon(p)})
    for p in bogons:
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         f'bogon/martian prefix {p} announced in BGP — route leak or hijack'))
    # blackhole community
    if any('blackhole' in c.lower() or '65535:666' in c for m in updates for c in m.get('communities', [])):
        categories.add('anomaly')
        findings.append(('warn', 'anomaly',
                         'BLACKHOLE community (65535:666) seen — RTBH in use (verify it is intended)'))

    # weak session — no TCP-MD5/TCP-AO seen while BGP is present
    if messages and not md5:
        categories.add('weak_session')
        advisories.append(dict(_BGP_ADVISORIES['no_md5'], key='no_md5'))
        findings.append(('warn', 'weak_session',
                         'no TCP-MD5/TCP-AO signature on the BGP session — exposed to '
                         'off-path session-reset attacks'))
    if updates:
        advisories.append(dict(_BGP_ADVISORIES['malformed_attr'], key='malformed_attr'))

    order = ['storm', 'injection', 'anomaly', 'weak_session']
    verdict = next((c for c in order if c in categories), 'clean')
    if not findings:
        findings.append(('ok', 'clean', 'No BGP anomalies in the capture window.'))

    prefixes_out = []
    for pfx in sorted(origins):
        oa = origins[pfx]
        prefixes_out.append({'prefix': pfx, 'origin_as': oa,
                             'baseline_as': base_origins.get(pfx),
                             'hijack': bool(have_baseline and base_origins.get(pfx) is not None
                                            and oa is not None and oa != base_origins.get(pfx)),
                             'bogon': _bgp_is_bogon(pfx)})

    return {
        'success': True, 'verdict': verdict, 'seconds': seconds,
        'messages': total, 'opens': len(opens), 'updates': len(updates),
        'notifications': len(notifs), 'update_per_s': upd_rate, 'learned': learned,
        'peers': peers, 'peer_ids': peer_ids, 'trusted_peers': sorted(trusted_peers),
        'md5': md5, 'prefixes': prefixes_out[:100], 'prefix_total': len(origins),
        'advisories': [{'key': a.get('key'), 'severity': a['severity'],
                        'title': a['title'], 'detail': a['detail'],
                        'refs': a.get('refs', [])} for a in advisories],
        'findings': [{'level': l, 'category': c, 'text': t} for l, c, t in findings],
        'reasons': [t for _l, _c, t in findings if _l != 'ok'],
    }


def _bgp_prefix_covers(supernet, subnet):
    """True if CIDR `supernet` strictly contains CIDR `subnet` (more-specific)."""
    try:
        sn, sl = supernet.split('/'); sl = int(sl)
        tn, tl = subnet.split('/'); tl = int(tl)
    except ValueError:
        return False
    if tl <= sl:
        return False
    a, b = _ip_to_int(sn), _ip_to_int(tn)
    if a is None or b is None:
        return False
    mask = (0xffffffff << (32 - sl)) & 0xffffffff
    return (a & mask) == (b & mask)


# --- ASN enrichment via Team Cymru IP-to-ASN whois (TCP/43) -----------------
# Turns raw AS numbers / peer IPs into AS names + owner country. Purely additive
# and SOFT-FAILING: a NOC that egress-filters outbound TCP/43 just gets IP/AS-
# number-only output (per Solarflere's note). Results are cached, and a failed
# lookup is negatively cached for a few minutes so a blocked egress doesn't add
# a connect-timeout to every scan.
_CYMRU_HOST = 'whois.cymru.com'
_CYMRU_PORT = 43
_CYMRU_TTL = 86400          # ASN mappings are stable — cache a day
_CYMRU_FAIL_TTL = 300       # after a failure, don't retry for 5 min (fast soft-fail)
_cymru_cache = {}           # ('ip'|'as', key) -> (ts, value)
_cymru_lock = threading.Lock()
_cymru_blocked_until = [0.0]


def _cymru_query(lines, timeout):
    """Send a bulk Team Cymru whois query; return the raw response or None on any
    failure (soft-fail: outbound TCP/43 may be filtered)."""
    payload = ('begin\nverbose\n' + '\n'.join(lines) + '\nend\n').encode()
    try:
        with socket.create_connection((_CYMRU_HOST, _CYMRU_PORT), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(payload)
            chunks = []
            while True:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
        return b''.join(chunks).decode('utf-8', 'replace')
    except Exception:
        return None


def _parse_cymru(resp, out):
    now = time.time()
    for raw in resp.splitlines():
        line = raw.strip()
        if not line or '|' not in line or line.lower().startswith('bulk mode') \
           or 'AS Name' in line:
            continue
        parts = [p.strip() for p in line.split('|')]
        if len(parts) >= 7:            # AS | IP | Prefix | CC | Registry | Alloc | Name
            asn, ip, prefix, cc = parts[0], parts[1], parts[2], parts[3]
            name = parts[6]
            try:
                asn_i = int(asn)
            except ValueError:
                asn_i = None
            rec = {'asn': asn_i, 'name': name or None,
                   'prefix': prefix if prefix and prefix != 'NA' else None,
                   'cc': cc if cc and cc != 'NA' else None}
            out['ips'][ip] = rec
            with _cymru_lock:
                _cymru_cache[('ip', ip)] = (now, rec)
            if asn_i is not None:
                out['asns'].setdefault(asn_i, name or None)
                with _cymru_lock:
                    _cymru_cache[('as', asn_i)] = (now, name or None)
        elif len(parts) >= 5:          # AS | CC | Registry | Alloc | Name
            try:
                asn_i = int(parts[0])
            except ValueError:
                continue
            name = parts[4]
            out['asns'][asn_i] = name or None
            with _cymru_lock:
                _cymru_cache[('as', asn_i)] = (now, name or None)


def _cymru_asn_lookup(ips=None, asns=None, timeout=4):
    """Enrich IPs -> {asn,name,prefix,cc} and ASNs -> name via Team Cymru. Cached;
    soft-fails to whatever the cache holds (possibly nothing) so callers degrade
    to IP/AS-number-only output. `out['ok']` is False when the live lookup was
    skipped/failed and nothing came back."""
    ips = sorted({i for i in (ips or []) if i})
    asns = sorted({int(a) for a in (asns or []) if a is not None})
    out = {'ips': {}, 'asns': {}, 'ok': False, 'filtered': False}
    if not ips and not asns:
        out['ok'] = True
        return out
    now = time.time()
    need_ips, need_asns = [], []
    with _cymru_lock:
        for ip in ips:
            c = _cymru_cache.get(('ip', ip))
            if c and now - c[0] < _CYMRU_TTL:
                out['ips'][ip] = c[1]
            else:
                need_ips.append(ip)
        for a in asns:
            c = _cymru_cache.get(('as', a))
            if c and now - c[0] < _CYMRU_TTL:
                out['asns'][a] = c[1]
            else:
                need_asns.append(a)
        blocked = now < _cymru_blocked_until[0]
    if need_ips or need_asns:
        if blocked:
            out['filtered'] = True
        else:
            resp = _cymru_query(need_ips + [f'AS{a}' for a in need_asns], timeout)
            if resp:
                _parse_cymru(resp, out)
            else:
                out['filtered'] = True
                with _cymru_lock:
                    _cymru_blocked_until[0] = now + _CYMRU_FAIL_TTL
    out['ok'] = not out['filtered'] or bool(out['ips'] or out['asns'])
    return out


def _bgp_capture(interface, seconds):
    """Run one passive tcpdump BGP window and return (raw_text, error)."""
    if not _have('tcpdump'):
        return '', 'tcpdump is not installed. Click Install to add it.'
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface,
                '-nn', '-t', '-v', '-s', '1500', '-c', '20000', 'tcp', 'port', '179'],
               timeout=seconds + 8)
    out = res['out']
    if not out and res['err'] and ('permission' in res['err'].lower()
                                   or "couldn't" in res['err'].lower()
                                   or 'no such device' in res['err'].lower()):
        return '', res['err'].strip()[:200]
    return out, None


def do_bgp_watch(interface=None, seconds=15, learn=True, quick=False, enrich=True):
    """Passive BGP path/security scanner (detection-only). Captures BGP for a few
    seconds and classifies the edge: injection (hijack) / anomaly / storm /
    weak_session / clean, with CVE/OSV advisories. Learns peers + prefix origins
    on first run; never opens a session or announces a route.

    enrich=True adds Team Cymru ASN names/owner (outbound TCP/43, soft-fails to
    AS-number-only if egress filters it)."""
    iface = interface if _valid_iface(interface or '') else _capture_iface()
    if not iface:
        return {'success': False, 'error': 'no interface to capture on'}
    if iface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {iface}'}
    seconds = _clamp_int(seconds, 15, 5, 40)

    text, err = _bgp_capture(iface, seconds)
    if err:
        return {'success': False, 'interface': iface, 'error': err,
                'missing_tool': 'tcpdump' if 'not installed' in err else None}
    messages = _parse_bgp_capture(text)

    with _bgp_watch_lock:
        baseline = _bgp_watch_load()
        result = _bgp_analyze(messages, seconds, baseline, learn=learn)
        if result.get('learned'):
            _bgp_watch_save(baseline)
        if result['verdict'] != 'clean':
            b = _bgp_watch_load()
            evs = b.get('events') or []
            evs.append({'ts': int(time.time()), 'verdict': result['verdict'],
                        'reasons': result['reasons'][:6]})
            b['events'] = evs[-_BGP_EVENTS_CAP:]
            _bgp_watch_save(b)

    # ASN enrichment (additive, soft-failing). Kept out of _bgp_analyze so the
    # self-test stays offline/deterministic.
    if enrich and (result.get('peers') or result.get('prefixes')):
        asns = set(result.get('peers') or [])
        for p in result.get('prefixes', []):
            if p.get('origin_as') is not None:
                asns.add(p['origin_as'])
        enr = _cymru_asn_lookup(ips=result.get('peer_ids') or [], asns=asns)
        result['asn_names'] = {str(k): v for k, v in enr['asns'].items() if v}
        result['enriched'] = enr['ok'] and bool(enr['asns'] or enr['ips'])
        if enr.get('filtered'):
            result['enrich_note'] = ('ASN name enrichment unavailable — needs '
                                     'outbound TCP/43 to whois.cymru.com; showing '
                                     'AS numbers only.')
        for p in result.get('prefixes', []):
            oa = p.get('origin_as')
            if oa is not None and enr['asns'].get(oa):
                p['origin_name'] = enr['asns'][oa]
        result['peer_info'] = enr.get('ips') or {}

    if not messages:
        result['note'] = ('No BGP seen — BGP is unicast TCP/179 between routers, so '
                          'the Pi must be inline, on a SPAN/mirror, or a peer to '
                          'observe it (unlike OSPF, it is not on the broadcast domain).')
    result['interface'] = iface
    return result


def _bgp_selftest():
    """Self-test the BGP detectors with synthetic tcpdump captures (no root, no
    live traffic), plus an optional Scapy end-to-end leg (scapy.contrib.bgp ->
    pcap -> tcpdump -> parse). Mirrors the OSPF/IGMP self-tests."""
    scenarios = []

    def run(name, text, seconds, baseline, expect):
        msgs = _parse_bgp_capture(text)
        res = _bgp_analyze(msgs, seconds, dict(baseline), learn=not baseline)
        ok = res['verdict'] == expect
        scenarios.append({'name': name, 'expect': expect, 'got': res['verdict'],
                          'messages': len(msgs), 'pass': ok})
        return res

    base = {'peers': [65001, 65002],
            'origins': {'93.184.216.0/24': 65002, '45.33.0.0/16': 65003},
            'prefix_count': {'10.0.0.1': 2}}

    clean = "\n".join([
        "10.0.0.1.179 > 10.0.0.2.179: Flags [P.], length 60: BGP md5",
        "\tUpdate Message (2), length: 55",
        "\t  Origin (1), length: 1, Flags [T]: IGP",
        "\t  AS Path (2), length: 6, Flags [T]: 65001 65002",
        "\t  Updated routes:",
        "\t    93.184.216.0/24",
    ])
    run('clean', clean, 15, base, 'clean')

    hijack = "\n".join([
        "10.0.0.1.179 > 10.0.0.2.179: Flags [P.], length 60: BGP md5",
        "\tUpdate Message (2), length: 55",
        "\t  AS Path (2), length: 6, Flags [T]: 65001 65666",
        "\t  Updated routes:",
        "\t    93.184.216.0/24",
    ])
    run('injection-hijack', hijack, 15, base, 'injection')

    subprefix = "\n".join([
        "10.0.0.1.179 > 10.0.0.2.179: Flags [P.], length 60: BGP md5",
        "\tUpdate Message (2), length: 55",
        "\t  AS Path (2), length: 6, Flags [T]: 65001 65666",
        "\t  Updated routes:",
        "\t    93.184.216.128/25",
    ])
    run('injection-subprefix', subprefix, 15, base, 'injection')

    notif = "\n".join([
        "10.0.0.9.179 > 10.0.0.2.179: Flags [P.], length 40: BGP md5",
        "\tNotification Message (3), length: 21, Cease (6), subcode Administrative Reset (4)",
    ])
    run('anomaly-notif', notif, 15, base, 'anomaly')

    bogon = "\n".join([
        "10.0.0.1.179 > 10.0.0.2.179: Flags [P.], length 60: BGP md5",
        "\tUpdate Message (2), length: 55",
        "\t  AS Path (2), length: 6, Flags [T]: 65001 65002",
        "\t  Updated routes:",
        "\t    192.168.0.0/16",
    ])
    run('anomaly-bogon', bogon, 15, base, 'anomaly')

    # parser check
    msgs = _parse_bgp_capture(clean)
    up = [m for m in msgs if m['type'] == 'update']
    parse_ok = bool(up and up[0]['as_path'] == [65001, 65002] and
                    '93.184.216.0/24' in up[0]['announced'])
    scenarios.append({'name': 'update-parse',
                      'expect': 'path=[65001,65002] pfx=93.184.216.0/24',
                      'got': str({'as_path': up[0]['as_path'], 'announced': up[0]['announced']} if up else None),
                      'pass': parse_ok})

    scapy_result = {'ran': False, 'reason': 'scapy or tcpdump unavailable'}
    try:
        import tempfile
        from scapy.all import IP, TCP, Ether, wrpcap  # noqa
        try:
            from scapy.contrib.bgp import BGPHeader, BGPKeepAlive
        except Exception:
            BGPHeader = None
        if BGPHeader is not None and _have('tcpdump'):
            pkt = (Ether() / IP(src='10.0.0.1', dst='10.0.0.2') /
                   TCP(sport=179, dport=50000, flags='PA') /
                   BGPHeader(type=4) / BGPKeepAlive())
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
                pcap_path = tf.name
            wrpcap(pcap_path, [pkt])
            res = _run(['tcpdump', '-nn', '-t', '-v', '-r', pcap_path, 'tcp', 'port', '179'],
                       timeout=10)
            parsed = _parse_bgp_capture(res['out'])
            scapy_result = {'ran': True, 'parsed_messages': len(parsed),
                            'pass': True, 'tcpdump_out': res['out'].strip()[:200]}
            try:
                os.remove(pcap_path)
            except OSError:
                pass
    except Exception as e:
        scapy_result = {'ran': False, 'reason': f'{type(e).__name__}: {e}'}

    passed = all(s['pass'] for s in scenarios) and \
        (not scapy_result.get('ran') or scapy_result.get('pass'))
    return {'success': passed, 'scenarios': scenarios, 'scapy': scapy_result}


def _tls_selftest():
    """Adapt tls_watch.selftest() to the aggregator's scenarios/scapy shape."""
    r = tls_watch.selftest()
    scen = [{'name': c['name'], 'pass': c['pass'],
             'expect': c.get('want'), 'got': c.get('got')}
            for c in r['checks'] if not c.get('skipped')]
    return {'success': r['success'], 'scenarios': scen,
            'scapy': {'ran': _have_scapy(),
                      'pass': all(c['pass'] for c in r['checks'])}}


def _ldap_selftest():
    """Adapt ldap_watch.selftest() to the aggregator's scenarios/scapy shape. The
    LDAP parse+detect path is pure-Python, so it needs no Scapy for the harness."""
    r = ldap_watch.selftest()
    scen = [{'name': c['name'], 'pass': c['pass'],
             'expect': c.get('want'), 'got': c.get('got')}
            for c in r['checks']]
    return {'success': r['success'], 'scenarios': scen,
            'scapy': {'ran': True, 'pass': r['success']}}


def do_routing_selftest():
    """Run the IGMP / OSPF / BGP detector self-tests and report a combined result
    plus whether Scapy is available for the end-to-end packet-crafting leg. Drives
    the web 'validate detectors' panel. No root, no live traffic, no persistence."""
    suites = {'igmp': _igmp_selftest(), 'ipv6': _ipv6_selftest(),
              'ndp': _ndp_selftest(), 'raguard': _raguard_selftest(),
              'ntp': _ntp_selftest(), 'icmp': _icmp_selftest(),
              'snmp': _snmp_selftest(), 'cert': _cert_selftest(),
              'stp': _stp_selftest(), 'isis': _isis_selftest(),
              'smb': _smb_selftest(), 'relay': _relay_selftest(),
              'dtp': _dtp_selftest(), 'cdp': _cdp_selftest(), 'vtp': _vtp_selftest(),
              'eigrp': _eigrp_selftest(),
              'fhrp': _fhrp_selftest(), 'tls': _tls_selftest(),
              'ldap': _ldap_selftest(),
              'ospf': _ospf_selftest(), 'bgp': _bgp_selftest(),
              'bgp_speaker': bgp_speaker.selftest(), 'path_asymmetry': path_asymmetry.selftest()}
    return {
        'success': all(s['success'] for s in suites.values()),
        'scapy_available': _have_scapy(),
        'suites': {k: {
            'success': v['success'],
            'passed': sum(1 for s in v['scenarios'] if s['pass']),
            'total': len(v['scenarios']),
            'scenarios': v['scenarios'],
            'scapy': v.get('scapy') or v.get('e2e'),
        } for k, v in suites.items()},
    }


# --------------------------------------------------------------------------
# BGP Route Collector (receive-only speaker) + Path Asymmetry (OWD) + correlator
# --------------------------------------------------------------------------
# Control-plane truth (bgp_speaker.BGPSpeaker's Adj-RIB-In) tied to data-plane
# measurement (path_asymmetry's measured one-way delay), via path_asymmetry.
# correlate(). Both the collector session and the OWD reflector are long-lived
# daemons, so these managers keep a single instance each with start/stop/status.

_bgp_collector = {'speakers': {}, 'events': []}     # name -> BGPSpeaker (multi-carrier)
_bgp_collector_lock = threading.Lock()
_owd_reflector = {'reflector': None}
_owd_lock = threading.Lock()
_COLLECTOR_EVENT_CAP = 100


def _collector_on_update(upd, changed):
    """RIB update hook — reserved for pushing churn into a live correlation feed.
    Kept lightweight; correlation is done on demand in do_path_asymmetry."""
    return None


def _collector_statuses():
    return [dict(sp.status(), name=name)
            for name, sp in _bgp_collector['speakers'].items()]


def do_bgp_collector(action='status', peer_ip=None, peer_as=None, local_as=None,
                     router_id=None, port=179, hold=90, peers=None, peer=None):
    """Manage the receive-only BGP collector — MULTI-SESSION: one session per
    carrier-facing router, each with its own RIB, so a convergence event can name
    which carrier moved. `peers` is a list of {ip, as, name}; a single peer_ip/
    peer_as still works (backward compatible). Never advertises a route.
    Actions: start / stop [peer] / status / rib [peer]."""
    with _bgp_collector_lock:
        speakers = _bgp_collector['speakers']
        if action == 'start':
            plist = list(peers or [])
            if not plist and peer_ip:
                plist = [{'ip': peer_ip, 'as': peer_as, 'name': peer_ip}]
            if not plist:
                return {'success': False, 'error': 'need peers[] or peer_ip/peer_as'}
            try:
                ipaddress.ip_address(router_id or '')
                local_as = int(local_as)
                port = _clamp_int(port, 179, 1, 65535)
                hold = _clamp_int(hold, 90, 0, 65535)
            except (ValueError, TypeError):
                return {'success': False, 'error': 'need valid router_id and local_as'}
            if not (0 < local_as <= 0xFFFFFFFF):
                return {'success': False, 'error': 'local_as out of range'}
            started, errs = [], []
            for pr in plist:
                pip, pas = pr.get('ip'), pr.get('as')
                name = str(pr.get('name') or pip)
                try:
                    ipaddress.ip_address(pip or '')
                    pas = int(pas)
                except (ValueError, TypeError):
                    errs.append({'peer': name, 'error': 'invalid ip/as'})
                    continue
                if not (0 < pas <= 0xFFFFFFFF):
                    errs.append({'peer': name, 'error': 'as out of range'})
                    continue
                ex = speakers.get(name)
                if ex and ex.state != 'Idle':
                    started.append(name)
                    continue                          # already running
                sp = bgp_speaker.BGPSpeaker(pip, pas, local_as, router_id,
                                            hold_time=hold, port=port,
                                            on_update=_collector_on_update)
                sp.start()
                speakers[name] = sp
                started.append(name)
            time.sleep(0.3)
            return {'success': bool(started), 'started': started, 'errors': errs,
                    'sessions': _collector_statuses()}
        if action == 'stop':
            if peer and peer in speakers:
                speakers[peer].stop()
                speakers.pop(peer, None)
                return {'success': True, 'stopped': [peer]}
            for sp in list(speakers.values()):
                sp.stop()
            _bgp_collector['speakers'] = {}
            return {'success': True, 'stopped': 'all'}
        if action == 'rib':
            per = {name: {'state': sp.state, **{k: sp.rib.snapshot(0)[k]
                          for k in ('total', 'active', 'flapping')}}
                   for name, sp in speakers.items()}
            target_peer = peer if peer in speakers else (
                next(iter(speakers), None))
            rib = speakers[target_peer].rib.snapshot(200) if target_peer else {
                'total': 0, 'routes': []}
            return {'success': True, 'peer': target_peer, 'peers': per, 'rib': rib}
        # status (default)
        return {'success': True, 'sessions': _collector_statuses(),
                'events': _bgp_collector['events'][-20:]}


def do_owd_reflector(action='status', port=path_asymmetry.DEFAULT_PORT):
    """Manage the local one-way-delay reflector so another node can probe THIS
    box for measured asymmetry. Actions: start / stop / status."""
    with _owd_lock:
        r = _owd_reflector['reflector']
        if action == 'start':
            if r and r._thread and r._thread.is_alive():
                return {'success': True, 'already_running': True, 'port': r.port}
            port = _clamp_int(port, path_asymmetry.DEFAULT_PORT, 1, 65535)
            try:
                r = path_asymmetry.Reflector(port=port)
                r.start()
            except OSError as e:
                return {'success': False, 'error': f'could not bind udp/{port}: {e}'}
            _owd_reflector['reflector'] = r
            return {'success': True, 'running': True, 'port': port}
        if action == 'stop':
            if r:
                r.stop()
            return {'success': True, 'stopped': True}
        running = bool(r and r._thread and r._thread.is_alive())
        return {'success': True, 'running': running,
                'port': r.port if r else path_asymmetry.DEFAULT_PORT,
                'reflected': r.count if r else 0}


def do_path_asymmetry(target, port=path_asymmetry.DEFAULT_PORT, count=20,
                      threshold_ms=5.0, clock_synced=False):
    """Measure one-way-delay asymmetry to a target running the OWD reflector, and
    correlate any asymmetry event against the BGP collector's RIB (control-plane
    truth). Falls back to a note if no reflector answers."""
    try:
        ipaddress.ip_address(target or '')
    except (ValueError, TypeError):
        # allow hostnames — resolve
        try:
            target = socket.gethostbyname(target)
        except (OSError, TypeError):
            return {'success': False, 'error': 'invalid or unresolvable target'}
    port = _clamp_int(port, path_asymmetry.DEFAULT_PORT, 1, 65535)
    count = _clamp_int(count, 20, 5, 100)
    det = path_asymmetry.AsymmetryDetector(threshold_ms=float(threshold_ms),
                                           clock_synced=bool(clock_synced), target=target)
    samples = path_asymmetry.probe_series(target, port=port, count=count, interval=0.03)
    events = []
    for s in samples:
        ev = det.add(*s)
        if ev:
            events.append(ev)
    # correlate events against every carrier's live RIB (control-plane truth) —
    # names which carrier moved for a multi-homed setup.
    named_ribs = {}
    with _bgp_collector_lock:
        for name, sp in _bgp_collector['speakers'].items():
            if sp and sp.state == 'Established':
                named_ribs[name] = sp.rib
    if named_ribs:
        correlated = [path_asymmetry.correlate_multi(e, named_ribs) for e in events]
    else:
        correlated = events
    if correlated:
        with _bgp_collector_lock:
            _bgp_collector['events'] = (_bgp_collector['events'] + correlated)[-_COLLECTOR_EVENT_CAP:]
    out = {'success': True, 'target': target, 'port': port,
           'probes_sent': count, 'replies': len(samples),
           'summary': det.summary(), 'events': correlated,
           'rib_correlation': bool(named_ribs),
           'carriers': sorted(named_ribs.keys())}
    if not samples:
        out['note'] = ('No reply from the OWD reflector at %s:%d. Run the reflector '
                       'on the target (`python3 path_asymmetry.py reflector %d`) or '
                       'enable it there, then retry. Without a reflector, only the '
                       'passive TTL hop-count fallback is available.' % (target, port, port))
    return out


# --------------------------------------------------------------------------
# PCAP Analyzer: triage an uploaded capture with tshark/capinfos
# --------------------------------------------------------------------------

# pcap (LE/BE, us & ns) and pcapng magic numbers.
_PCAP_MAGICS = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',
                b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a')

# IEEE 802.11 deauth/disassoc reason codes (the "why did the client drop" field).
_WIFI_REASONS = {
    1: 'Unspecified', 2: 'Previous auth no longer valid', 3: 'Deauth — STA leaving',
    4: 'Disassoc — inactivity', 5: 'Disassoc — AP out of resources',
    6: 'Class-2 frame from non-authed STA', 7: 'Class-3 frame from non-assoc STA',
    8: 'Disassoc — STA leaving BSS', 9: 'STA not authenticated',
    13: 'Invalid information element', 14: 'MIC failure',
    15: '4-way handshake timeout', 16: 'Group-key handshake timeout',
    17: '4-way handshake IE mismatch', 18: 'Invalid group cipher',
    19: 'Invalid pairwise cipher', 20: 'Invalid AKMP', 23: '802.1X auth failed',
    24: 'Cipher suite rejected (policy)', 34: 'Disassoc — poor RF / low ACK',
}
# 802.11 auth/assoc status codes (0 = success).
_WIFI_STATUS = {
    1: 'Unspecified failure', 10: 'Cannot support all capabilities',
    11: 'Reassoc denied', 12: 'Assoc denied (unspecified)',
    13: 'Auth algorithm unsupported', 15: 'Auth timeout',
    17: 'AP unable to handle more STAs (capacity)', 18: 'Assoc denied — basic-rate mismatch',
    40: 'Invalid IE', 43: 'Invalid pairwise cipher', 45: 'Invalid AKMP',
}


def _tshark_fields(path, display_filter, fields, timeout=120):
    cmd = ['tshark', '-r', path, '-Y', display_filter, '-T', 'fields']
    for f in fields:
        cmd += ['-e', f]
    return _run(cmd, timeout=timeout)['out'].splitlines()


def _to_int(v):
    try:
        return int(v, 16) if v.lower().startswith('0x') else int(v)
    except (ValueError, AttributeError):
        return None


def _pcap_wifi(path, total_wlan_frames):
    """Extract the 802.11 events that explain client drops: deauth/disassoc
    reason codes (per client), auth/assoc failure status codes, EAPOL 4-way
    handshake volume, retry rate, and SSIDs. tshark gives reason/status as hex."""
    def code_table(counter, table):
        return sorted(({'code': c, 'label': table.get(c, f'code {c}'), 'count': n}
                       for c, n in counter.items()), key=lambda x: x['count'], reverse=True)

    def collect(subtypes_filter):
        deauth_reasons, deauth_clients = {}, {}
        for line in _tshark_fields(path, subtypes_filter,
                                   ['wlan.fc.type_subtype', 'wlan.fixed.reason_code',
                                    'wlan.da', 'wlan.sa']):
            cols = (line.split('\t') + ['', '', '', ''])[:4]
            rc = _to_int(cols[1])
            client = cols[2] or cols[3]
            if rc is not None:
                deauth_reasons[rc] = deauth_reasons.get(rc, 0) + 1
            if client:
                deauth_clients[client] = deauth_clients.get(client, 0) + 1
        return deauth_reasons, deauth_clients

    de_reasons, de_clients = collect('wlan.fc.type_subtype==0x0c')     # deauth
    dis_reasons, dis_clients = collect('wlan.fc.type_subtype==0x0a')   # disassoc

    # auth (0x0b) + assoc/reassoc responses (0x01/0x03): non-zero status = failure
    status = {}
    for line in _tshark_fields(path,
                               'wlan.fc.type_subtype==0x0b||wlan.fc.type_subtype==0x01||wlan.fc.type_subtype==0x03',
                               ['wlan.fixed.status_code']):
        sc = _to_int(line.split('\t')[0])
        if sc:  # non-zero only
            status[sc] = status.get(sc, 0) + 1

    eapol = len([l for l in _tshark_fields(path, 'eapol', ['frame.number']) if l.strip()])
    retries = len([l for l in _tshark_fields(path, 'wlan.fc.retry==1', ['frame.number']) if l.strip()])
    ssids = set()
    for line in _tshark_fields(path, 'wlan.fc.type_subtype==0x08', ['wlan.ssid']):
        v = line.strip()
        if v:
            try:
                ssids.add(bytes.fromhex(v).decode('utf-8', 'replace'))
            except ValueError:
                ssids.add(v)

    retry_pct = round(100.0 * retries / total_wlan_frames, 1) if total_wlan_frames else None

    def top_clients(d):
        return sorted(({'mac': m, 'count': n} for m, n in d.items()),
                      key=lambda x: x['count'], reverse=True)[:8]

    de = code_table(de_reasons, _WIFI_REASONS)
    dis = code_table(dis_reasons, _WIFI_REASONS)
    st = code_table(status, _WIFI_STATUS)

    # Quick heuristics (useful even without AI, and they seed the AI prompt).
    findings = []
    reasons_present = {r['code'] for r in de} | {r['code'] for r in dis}
    if 15 in reasons_present or 16 in reasons_present:
        findings.append('4-way/group-key handshake timeouts — wrong PSK, RADIUS/EAP timing, or a flaky supplicant.')
    if 14 in reasons_present:
        findings.append('MIC failures — mismatched passphrase or possible attack.')
    if 23 in reasons_present:
        findings.append('802.1X authentication failed — RADIUS/cert/credentials issue.')
    if 4 in reasons_present:
        findings.append('Inactivity deauths — idle/power-save clients being aged out (often benign).')
    if reasons_present & {6, 7}:
        findings.append('Class-2/3 frames from unassociated STAs — clients losing association / roaming churn.')
    if 2 in reasons_present:
        findings.append('"Previous auth no longer valid" — roaming, or the AP reset/rebooted.')
    if any(s['code'] == 17 for s in st):
        findings.append('AP returning "unable to handle more STAs" — capacity/association-limit reached.')
    if retry_pct is not None and retry_pct > 30:
        findings.append(f'High retry rate ({retry_pct}%) — RF interference, weak signal, or distance/co-channel.')

    return {
        'is_wifi': True, 'wlan_frames': total_wlan_frames, 'retry_pct': retry_pct,
        'eapol_frames': eapol, 'ssids': sorted(ssids),
        'deauth': {'total': sum(de_reasons.values()), 'by_reason': de, 'top_clients': top_clients(de_clients)},
        'disassoc': {'total': sum(dis_reasons.values()), 'by_reason': dis, 'top_clients': top_clients(dis_clients)},
        'auth_assoc_failures': {'total': sum(status.values()), 'by_status': st},
        'findings': findings,
    }


def do_pcap_analyze(path):
    """Triage a capture file: summary (packets/bytes/duration/rate), protocol
    hierarchy, top talkers (by bytes), and tshark's expert info (errors/warnings
    /notes — retransmissions, resets, dup-ACKs, malformed …). Read-only analysis
    via tshark/capinfos, the way you'd eyeball a pcap in Wireshark's Statistics."""
    if not _have('tshark'):
        return {'success': False, 'missing_tool': 'tshark',
                'error': 'tshark is not installed. Click Install to add it.'}
    if not os.path.isfile(path):
        return {'success': False, 'error': 'capture file not found'}

    # 1) File summary (capinfos ships with tshark).
    summary = {}
    if _have('capinfos'):
        t = _run(['capinfos', '-M', path], timeout=30)['out']

        def cap(pat, cast=float):
            m = re.search(pat, t)
            if not m:
                return None
            try:
                return cast(m.group(1))
            except ValueError:
                return m.group(1)
        summary = {
            'packets': cap(r'Number of packets:\s*(\d+)', int),
            'file_size': cap(r'File size:\s*(\d+)', int),
            'data_size': cap(r'Data size:\s*(\d+)', int),
            'duration_s': cap(r'Capture duration:\s*([\d.]+)'),
            'avg_packet_size': cap(r'Average packet size:\s*([\d.]+)'),
            'data_byte_rate': cap(r'Data byte rate:\s*([\d.]+)'),
            'start_time': cap(r'(?:Earliest packet time|First packet time|Start time):\s*(.+)', str),
            'end_time': cap(r'(?:Latest packet time|Last packet time|End time):\s*(.+)', str),
            'encapsulation': cap(r'File encapsulation:\s*(.+)', str),
        }

    # 2) Protocol hierarchy (io,phs gives raw byte counts).
    protocols = []
    for line in _run(['tshark', '-r', path, '-q', '-z', 'io,phs'], timeout=90)['out'].splitlines():
        m = re.match(r'^(\s*)([\w:.-]+)\s+frames:(\d+)\s+bytes:(\d+)', line)
        if m:
            protocols.append({'proto': m.group(2), 'depth': len(m.group(1)) // 2,
                              'frames': int(m.group(3)), 'bytes': int(m.group(4))})

    # 3) Top talkers by bytes. conv,ip humanises bytes ("24 kB"), so aggregate
    #    raw frame lengths per IP pair from -T fields instead.
    agg = {}
    fields = _run(['tshark', '-r', path, '-T', 'fields', '-e', 'ip.src',
                   '-e', 'ip.dst', '-e', 'frame.len'], timeout=120)
    for line in fields['out'].splitlines():
        parts = line.split('\t')
        if len(parts) < 3 or not parts[0] or not parts[1]:
            continue
        try:
            blen = int((parts[2] or '0').split(',')[0])
        except ValueError:
            blen = 0
        key = tuple(sorted((parts[0], parts[1])))
        e = agg.setdefault(key, [0, 0])
        e[0] += 1
        e[1] += blen
    talkers = sorted(({'a': k[0], 'b': k[1], 'frames': v[0], 'bytes': v[1]}
                      for k, v in agg.items()), key=lambda t: t['bytes'], reverse=True)[:12]

    # 4) Expert info (Errors / Warns / Notes / Chats).
    expert = {'errors': 0, 'warnings': 0, 'notes': 0, 'items': []}
    sev = None
    sev_key = {'Errors': 'errors', 'Warns': 'warnings', 'Notes': 'notes'}
    # Normal TCP connection lifecycle (SYN establishment, FIN teardown) is
    # surfaced by tshark as low-severity notes. It is NOT a fault — feeding it to
    # the AI made routine teardown read as "instability" — so drop these items and
    # discount them from the note total so the counts stay honest.
    _normal_seq = ('the connection closing', 'connection establish request',
                   'connection establish acknowledge')
    for line in _run(['tshark', '-r', path, '-q', '-z', 'expert'], timeout=90)['out'].splitlines():
        hm = re.match(r'^(Errors|Warns|Notes|Chats)\s*\((\d+)\)', line)
        if hm:
            sev = hm.group(1)
            if sev in sev_key:
                expert[sev_key[sev]] = int(hm.group(2))
            continue
        rm = re.match(r'^\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+?)\s*$', line)
        if rm and sev and sev != 'Chats':
            desc = rm.group(4).strip()   # NB: not `summary` — that name holds the file-summary dict
            if any(p in desc.lower() for p in _normal_seq):
                if sev in sev_key:      # keep the badge total consistent with items
                    expert[sev_key[sev]] = max(0, expert[sev_key[sev]] - int(rm.group(1)))
                continue
            expert['items'].append({'severity': sev_key.get(sev, sev.lower()),
                                    'count': int(rm.group(1)), 'protocol': rm.group(3),
                                    'summary': desc})
    expert['items'].sort(key=lambda i: i['count'], reverse=True)
    expert['items'] = expert['items'][:20]

    # If this is an 802.11 capture, add the WiFi/AP drop analysis.
    wifi = None
    wlan_frames = next((p['frames'] for p in protocols if p['proto'] == 'wlan'), 0)
    if wlan_frames:
        try:
            wifi = _pcap_wifi(path, wlan_frames)
        except Exception:  # pragma: no cover - WiFi extraction is best-effort
            wifi = None

    return {'success': True, 'summary': summary, 'protocols': protocols,
            'talkers': talkers, 'expert': expert, 'wifi': wifi}


def do_pcap_from_upload(file_storage, max_bytes=100 * 1024 * 1024):
    """Save an uploaded capture to a temp file (size-guarded, magic-checked) and
    analyze it, then delete it."""
    if file_storage is None:
        return {'success': False, 'error': 'no file uploaded'}
    fd, tmp = tempfile.mkstemp(suffix='.pcap')
    try:
        total = 0
        with os.fdopen(fd, 'wb') as out:
            while True:
                chunk = file_storage.stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    return {'success': False,
                            'error': f'file too large (max {max_bytes // (1024 * 1024)} MB)'}
                out.write(chunk)
        if total == 0:
            return {'success': False, 'error': 'uploaded file is empty'}
        with open(tmp, 'rb') as fh:
            if fh.read(4) not in _PCAP_MAGICS:
                return {'success': False,
                        'error': 'not a valid pcap/pcapng capture (bad magic bytes)'}
        return do_pcap_analyze(tmp)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


# --------------------------------------------------------------------------
# PCAP sources beyond upload: browse captures already on the box, and record a
# fresh one on an interface. Both feed the exact same do_pcap_analyze() path (and
# therefore the "Explain with AI" button) — upload is just one of three sources.
# --------------------------------------------------------------------------

_PCAP_EXTS = ('.pcap', '.pcapng', '.cap')
# Dirs never descended while hunting captures (cost / noise / privacy).
_PCAP_SKIP_DIRS = {'.git', 'node_modules', '__pycache__', 'proc', 'sys', 'dev',
                   'run', '.cache', 'site-packages', 'venv', '.venv',
                   'snap', 'lost+found'}


def _pcap_capture_dir():
    """Directory where Ragnar-recorded captures are kept (and later browsable)."""
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'pcaps')
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def _pcap_search_roots():
    """Curated roots scanned for stored captures — deliberately NOT a full-disk
    walk. Ragnar's own capture dir, the app tree, temp dirs, and the running
    user's / root's home cover where captures realistically land. Deduped by
    realpath; existing directories only."""
    roots = [
        _pcap_capture_dir(),
        os.path.dirname(os.path.abspath(__file__)),
        '/tmp', '/var/tmp',
        os.path.expanduser('~'),
        '/home', '/root',
        os.getcwd(),
    ]
    seen, out = set(), []
    for r in roots:
        try:
            rp = os.path.realpath(r)
        except OSError:
            continue
        if rp in seen or not os.path.isdir(rp):
            continue
        seen.add(rp)
        out.append(rp)
    return out


def _pcap_under_roots(realpath, roots):
    """True if `realpath` is one of, or lives under, an allowed root."""
    return any(realpath == r or realpath.startswith(r.rstrip('/') + '/')
               for r in roots)


def do_pcap_list_stored(max_results=300, max_depth=5):
    """Find capture files under the curated roots. Bounded walk (depth + count),
    skips heavy/system dirs, opens nothing — metadata only. Newest first."""
    cap_dir = os.path.realpath(_pcap_capture_dir())
    found, seen_paths = [], set()
    for root in _pcap_search_roots():
        base_depth = root.rstrip('/').count('/')
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames
                           if d not in _PCAP_SKIP_DIRS and not d.startswith('.')]
            if dirpath.rstrip('/').count('/') - base_depth >= max_depth:
                dirnames[:] = []
            for fn in filenames:
                if not fn.lower().endswith(_PCAP_EXTS):
                    continue
                rp = os.path.realpath(os.path.join(dirpath, fn))
                if rp in seen_paths:
                    continue
                try:
                    stt = os.stat(rp)
                except OSError:
                    continue
                if not os.path.isfile(rp) or stt.st_size == 0:
                    continue
                seen_paths.add(rp)
                found.append({
                    'path': rp, 'name': fn, 'dir': os.path.dirname(rp),
                    'size': stt.st_size, 'mtime': int(stt.st_mtime),
                    'captured': rp.startswith(cap_dir),  # Ragnar-recorded
                })
            if len(found) >= max_results * 3:
                break
    found.sort(key=lambda f: f['mtime'], reverse=True)
    return {'success': True, 'files': found[:max_results],
            'roots': _pcap_search_roots(), 'capture_dir': cap_dir,
            'truncated': len(found) > max_results}


def do_pcap_analyze_path(path):
    """Analyze a stored capture chosen from the browser. Confined to the same
    curated roots we list from (no arbitrary path read), magic-byte checked, then
    handed to the normal do_pcap_analyze()."""
    if not path:
        return {'success': False, 'error': 'no path given'}
    rp = os.path.realpath(path)
    if not os.path.isfile(rp):
        return {'success': False, 'error': 'capture file not found'}
    if not _pcap_under_roots(rp, _pcap_search_roots()):
        return {'success': False,
                'error': 'path is outside the allowed capture locations'}
    try:
        with open(rp, 'rb') as fh:
            if fh.read(4) not in _PCAP_MAGICS:
                return {'success': False,
                        'error': 'not a valid pcap/pcapng capture (bad magic bytes)'}
    except OSError as exc:
        return {'success': False, 'error': 'cannot read file: %s' % exc}
    out = do_pcap_analyze(rp)
    if isinstance(out, dict):
        out['source_file'] = rp
        out['source_name'] = os.path.basename(rp)
    return out


def _pcap_auto_iface(valid):
    """Resolve the 'Auto (wired first)' choice for live capture.

    Among interfaces that are link-up (carrier==1), prefer in this order:
      1. wired LAN (onboard Ethernet)
      2. USB wired LAN (Ethernet via a USB adapter / gadget)
      3. wlan1+ (e.g. an external USB Wi-Fi dongle)
      4. wlan0 (onboard Wi-Fi)

    Unlike _capture_iface() (which targets wired SPAN/mirror ports and skips
    wireless, so it comes back empty on a WiFi-managed box whose cables are
    down), this always falls back to any usable interface so Auto never errors.
    """
    skip = ('br-', 'veth', 'docker', 'tun', 'tap', 'wg', 'zt', 'tailscale')

    def _up(name):
        try:
            with open('/sys/class/net/%s/carrier' % name) as f:
                return f.read().strip() == '1'
        except OSError:      # admin-down / no carrier file — treat as down
            return False

    def _is_usb(name):
        try:
            return '/usb' in os.path.realpath('/sys/class/net/%s' % name)
        except OSError:
            return False

    def _rank(name):
        if _is_wireless(name):
            return 4 if name == 'wlan0' else 3
        return 2 if _is_usb(name) else 1

    cands = [n for n in _list_iface_names(include_virtual=False)
             if n in valid and not n.startswith(skip)]
    up = [n for n in cands if _up(n)]
    if up:
        up.sort(key=lambda n: (_rank(n), n))
        return up[0]
    # Nothing link-up: fall back to the default route, else the first real NIC,
    # else anything capturable — so Auto still resolves to *something*.
    dflt = _default_route_iface()
    if dflt and dflt in valid:
        return dflt
    if cands:
        cands.sort(key=lambda n: (_rank(n), n))
        return cands[0]
    return sorted(valid)[0] if valid else None


def _wifi_link_state(iface):
    """Best-effort {mode, connected} for a Wi-Fi interface via `iw`. `mode` is
    'managed'/'monitor'/etc or None; `connected` is True/False/None (None when
    unknown, e.g. iw missing). Used to explain a 0-packet capture on Wi-Fi."""
    state = {'mode': None, 'connected': None}
    if not _have('iw'):
        return state
    info = _run(['iw', 'dev', iface, 'info'], timeout=5)['out']
    m = re.search(r'^\s*type\s+(\S+)', info, re.MULTILINE)
    if m:
        state['mode'] = m.group(1).lower()
    link = _run(['iw', 'dev', iface, 'link'], timeout=5)['out']
    if re.search(r'Connected to', link):
        state['connected'] = True
    elif re.search(r'Not connected', link):
        state['connected'] = False
    return state


def _pcap_zero_note(iface, seconds):
    """Human note explaining why a capture saw 0 packets, tailored to the
    interface: an unassociated / monitor-mode Wi-Fi card is the usual reason a
    Wi-Fi capture is empty, and that is NOT 'the wrong interface'."""
    base = 'Capture ran for %ds but recorded 0 packets on %s' % (seconds, iface)
    if _is_wireless(iface):
        st = _wifi_link_state(iface)
        if st.get('mode') == 'monitor':
            return (base + ' — it is in monitor mode, so plain capture sees nothing. '
                    'Use the Wi-Fi Defense / Spectrum tools for monitor-mode 802.11 '
                    'sniffing.')
        if st.get('connected') is False:
            return (base + ' — this Wi-Fi interface is not associated to any network, '
                    'so it carries no traffic. Connect it to an AP to capture its link, '
                    'or use monitor mode (Wi-Fi tools) to sniff nearby 802.11 frames.')
        return (base + ' — the Wi-Fi link looks idle; try a longer window or pick the '
                'interface actually carrying traffic.')
    return base + ' — wrong interface, the cable is down, or the filter matched nothing.'


# A broad 2.4 + 5 GHz sweep for monitor-mode surveys (non-overlapping 2.4 GHz +
# common 5 GHz UNII channels). Channels the adapter can't tune just fail the `iw`
# call harmlessly, so a 2.4-only card still works — it only dwells on 1/6/11.
_PCAP_HOP_CHANNELS = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]


def _channel_hop(iface, stop, dwell=0.35):
    """Round-robin the monitor interface across channels until `stop` is set, so a
    survey capture sees APs/traffic on every band instead of one parked channel."""
    i = 0
    while not stop.is_set():
        ch = _PCAP_HOP_CHANNELS[i % len(_PCAP_HOP_CHANNELS)]
        _run(['iw', 'dev', iface, 'set', 'channel', str(ch)], timeout=3)
        i += 1
        stop.wait(dwell)


def do_pcap_capture(interface=None, seconds=10, bpf=None, max_seconds=60,
                    monitor=False, channel=None):
    """Record live traffic on `interface` for `seconds` into a saved pcap (kept in
    the capture dir so it then shows up under 'stored'), and analyze it. Passive:
    a plain ``tcpdump -w`` with no injected traffic. Needs root for the capture
    (the Ragnar service runs as root).

    With ``monitor=True`` on a Wi-Fi interface, flip the adapter into monitor
    mode (via wifi_defense.enable_monitor — a separate vif where the driver
    allows it, else switching the adapter) and capture raw 802.11 with radiotap.
    With a ``channel`` it parks there (focus on one AP); with no channel it
    channel-hops across 2.4/5 GHz for a broad survey. Monitor mode is always torn
    down afterward, restoring the managed link."""
    if not _have('tcpdump'):
        return {'success': False, 'missing_tool': 'tcpdump',
                'error': 'tcpdump is not installed. Click Install to add it.'}
    valid = set(_list_iface_names(include_virtual=True))
    if not valid:
        return {'success': False, 'error': 'no capturable interfaces found'}
    # Empty selection means "Auto (wired first)": pick the best link-up NIC
    # (LAN > USB LAN > wlan1 > wlan0), falling back so it never errors.
    if not interface:
        interface = _pcap_auto_iface(valid)
    if not interface or interface not in valid:
        return {'success': False,
                'error': 'unknown interface — pick one of: %s'
                         % ', '.join(sorted(valid))}
    if monitor and not _is_wireless(interface):
        return {'success': False,
                'error': '%s is not a Wi-Fi interface — monitor mode only applies '
                         'to wireless adapters.' % interface}
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        seconds = 10
    seconds = max(3, min(max_seconds, seconds))

    ts = datetime.now().strftime('%Y%m%d-%H%M%S')
    safe_if = re.sub(r'[^A-Za-z0-9_.-]', '_', interface)
    path = os.path.join(_pcap_capture_dir(), 'ragnar-%s-%s.pcap' % (safe_if, ts))

    # For monitor capture, put the radio into monitor mode first (and remember to
    # restore it). cap_iface is what tcpdump actually listens on (a monitor vif
    # like ragmon0, or the adapter itself in switch mode).
    cap_iface = interface
    mon_state = None
    warning = None
    if monitor:
        try:
            import wifi_defense
        except Exception as exc:      # pragma: no cover - defensive
            return {'success': False, 'error': 'monitor mode unavailable: %s' % exc}
        res = wifi_defense.enable_monitor(interface)
        if not isinstance(res, dict) or res.get('error'):
            return {'success': False,
                    'error': 'could not enable monitor mode: %s'
                             % (res or {}).get('error', 'unknown')}
        mon_state = res
        cap_iface = res.get('mon_iface') or interface
        warning = res.get('warning')
        if channel:
            try:
                _run(['iw', 'dev', cap_iface, 'set', 'channel', str(int(channel))],
                     timeout=5)
            except (ValueError, TypeError):
                channel = None       # ignore a non-numeric channel

    # No fixed channel on a monitor capture → sweep channels so the survey isn't
    # stuck on one (which is why a parked capture only sees a few beacons).
    hop_stop = hop_thread = None
    if monitor and not channel:
        hop_stop = threading.Event()
        hop_thread = threading.Thread(target=_channel_hop, args=(cap_iface, hop_stop),
                                      daemon=True)
        hop_thread.start()

    try:
        # -U writes each packet as it arrives, so the file is a valid pcap even
        # though we stop tcpdump by killing it at the time window (it never
        # self-terminates).
        cmd = ['tcpdump', '-i', cap_iface, '-w', path, '-s', '0', '-U', '-q']
        if bpf:
            bpf = str(bpf).strip()
            if len(bpf) > 200:
                return {'success': False, 'error': 'capture filter too long'}
            cmd.append(bpf)          # tcpdump joins trailing args into the BPF filter
        try:
            subprocess.run(cmd, timeout=seconds, capture_output=True)
        except subprocess.TimeoutExpired:
            pass                     # expected: the timeout IS how we end the capture
        except Exception as exc:     # pragma: no cover - defensive
            return {'success': False, 'error': 'capture failed: %s' % exc}
    finally:
        if hop_stop:                 # stop the channel hopper before teardown
            hop_stop.set()
            if hop_thread:
                hop_thread.join(timeout=2)
        if mon_state:                # always restore the managed link
            try:
                import wifi_defense
                wifi_defense.disable_monitor(mon_state.get('mon_iface'))
            except Exception:        # pragma: no cover - best-effort restore
                pass

    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return {'success': False,
                'error': 'capture produced no file — check that %s exists and the '
                         'service can open it (needs root / a valid BPF filter)'
                         % interface}
    out = do_pcap_analyze(path)
    if isinstance(out, dict):
        out['captured_file'] = path
        out['captured_name'] = os.path.basename(path)
        out['interface'] = interface
        out['seconds'] = seconds
        out['monitor'] = bool(monitor)
        if monitor:
            out['channel_mode'] = ('parked ch %s' % channel) if channel else 'swept 2.4/5 GHz'
        if warning:
            out['monitor_warning'] = warning
        if out.get('success') and not (out.get('summary') or {}).get('packets'):
            if monitor and channel:
                out['note'] = ('Monitor capture saw 0 frames in %ds on ch %s — no nearby '
                               'AP/traffic on that channel. Try leaving the channel blank '
                               'to sweep all channels.' % (seconds, channel))
            elif monitor:
                out['note'] = ('Monitor capture saw 0 frames in %ds while sweeping — no '
                               '802.11 in range, or the adapter could not tune any channel. '
                               'Check the antenna and that the card supports monitor mode.'
                               % seconds)
            else:
                out['note'] = _pcap_zero_note(interface, seconds)
    return out


# --------------------------------------------------------------------------
# Flow telemetry (per-connection RTT / retransmits) + PTP timing detection
# --------------------------------------------------------------------------

def do_flow_telemetry(limit=15):
    """Per-connection kernel telemetry from `ss -ti`: RTT, min-RTT and TCP
    retransmits for every established flow — the light, dependency-free version
    of the eBPF per-flow visibility big shops run. A flow with retransmits or an
    RTT far above its min-RTT is where loss/bufferbloat is biting."""
    if not _have('ss'):
        return {'success': False, 'error': 'ss (iproute2) is not available'}
    res = _run(['ss', '-tino'], timeout=8)
    conns, cur = [], None
    for line in res['out'].splitlines():
        if line.startswith('State') or not line.strip():
            continue
        if not line[0].isspace():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == 'ESTAB' and not parts[4].startswith('127.'):
                cur = {'local': parts[3], 'peer': parts[4]}
            else:
                cur = None
        elif cur is not None:
            def g(pat, info=line):
                m = re.search(pat, info)
                return m.group(1) if m else None
            rtt, minrtt = g(r'\brtt:([\d.]+)'), g(r'\bminrtt:([\d.]+)')
            retr = g(r'\bretrans:\d+/(\d+)')
            mss = g(r'\bmss:(\d+)')
            cur.update({'rtt_ms': float(rtt) if rtt else None,
                        'min_rtt_ms': float(minrtt) if minrtt else None,
                        'retransmits': int(retr) if retr else 0,
                        'mss': int(mss) if mss else None})
            conns.append(cur)
            cur = None
    conns.sort(key=lambda c: (c.get('retransmits') or 0, c.get('rtt_ms') or 0), reverse=True)
    return {'success': True, 'total': len(conns),
            'with_retransmits': sum(1 for c in conns if c.get('retransmits')),
            'connections': conns[:_clamp_int(limit, 15, 1, 100)],
            'engine': 'bpftrace' if _have('bpftrace') else 'ss'}


def do_ptp_detect(interface, seconds=8):
    """Detect PTP (IEEE-1588 / PTPv2) on a segment by sniffing the PTP event/
    general UDP ports and the 802.1AS ethertype. Reports whether a grandmaster
    is announcing, which message types are present, and the domain(s). Precise
    clock-offset needs ptp4l running; this is the field 'is PTP here?' check for
    AV-over-IP / finance / 5G-fronthaul networks."""
    interface = (interface or '').strip()
    if not interface:
        return {'success': False, 'error': 'interface required'}
    if not _have('tcpdump'):
        return {'success': False, 'missing_tool': 'tcpdump',
                'error': 'tcpdump is not installed. Click Install to add it.'}
    if interface not in _list_iface_names(include_virtual=True):
        return {'success': False, 'error': f'unknown interface: {interface}'}
    seconds = _clamp_int(seconds, 8, 3, 30)
    res = _run(['timeout', str(seconds), 'tcpdump', '-i', interface, '-nn', '-v', '-c', '200',
                'udp port 319 or udp port 320 or ether proto 0x88f7'], timeout=seconds + 8)
    out = res['out']
    pkt_lines = [l for l in out.splitlines() if re.search(r'\bIP6?\b|PTP|ethertype', l)]
    present = bool(pkt_lines) or 'PTP' in out
    msg_types = set()
    for kw in ('announce', 'sync', 'follow_up', 'delay_req', 'delay_resp', 'pdelay'):
        if kw in out.lower():
            msg_types.add(kw)
    domains = set(re.findall(r'domain\s*(?:number)?\s*:?\s*(\d+)', out, re.I))
    return {'success': True, 'interface': interface, 'seconds': seconds,
            'ptp_present': present,
            'packets': len(pkt_lines),
            'message_types': sorted(msg_types),
            'domains': sorted(domains),
            'note': ('PTP traffic detected on this segment.' if present else
                     'No PTP traffic seen — no grandmaster here, or PTP isn\'t in use.'),
            'offset_note': 'Detection only — precise clock-offset measurement needs a running ptp4l.'}


# --------------------------------------------------------------------------
# On-demand tool install (whitelisted apt packages, invoked from the UI)
# --------------------------------------------------------------------------

# Stable tool key -> (binary to probe, apt package name). Only these packages
# can be installed via /api/net/install-tool, so the tool name is never
# interpolated into a shell command.
_NET_TOOL_PKGS = {
    'ping': ('ping', 'iputils-ping'),
    'lldpd': ('lldpctl', 'lldpd'),
    'arp-scan': ('arp-scan', 'arp-scan'),
    'ethtool': ('ethtool', 'ethtool'),
    'mtr': ('mtr', 'mtr-tiny'),
    'whois': ('whois', 'whois'),
    'traceroute': ('traceroute', 'traceroute'),
    'speedtest-cli': ('speedtest-cli', 'speedtest-cli'),
    'curl': ('curl', 'curl'),
    'dig': ('dig', 'dnsutils'),
    'iperf3': ('iperf3', 'iperf3'),
    'tcpdump': ('tcpdump', 'tcpdump'),
    'wg': ('wg', 'wireguard-tools'),
    'tshark': ('tshark', 'tshark'),
}


def _configure_lldpd():
    """Enable CDPv1/v2/EDP/FDP/SONMP decoding and (re)start lldpd -- mirrors the
    Ragnar installer/updater so on-demand installs also see non-LLDP switches."""
    try:
        os.makedirs('/etc/default', exist_ok=True)
        with open('/etc/default/lldpd', 'w') as f:
            f.write('# Ragnar: decode CDPv1/v2 (Cisco), EDP (Extreme), FDP (Foundry), '
                    'SONMP (Nortel)\n')
            f.write('# neighbours in addition to LLDP, so switch discovery covers '
                    'non-LLDP gear.\n')
            f.write('DAEMON_ARGS="-c -e -f -s"\n')
    except OSError:
        pass
    _run(['systemctl', 'enable', 'lldpd'], timeout=15)
    _run(['systemctl', 'restart', 'lldpd'], timeout=15)


def _install_scapy():
    """Install the Scapy Python module (used by the scanners' end-to-end self-test
    leg). Prefers the Debian package python3-scapy so it lands in the system
    interpreter the service runs under; falls back to pip (PEP-668 override on
    Pi OS). Idempotent."""
    if _have_scapy():
        return {'success': True, 'already_installed': True, 'tool': 'scapy',
                'message': 'scapy is already installed.'}
    env = dict(os.environ)
    env['DEBIAN_FRONTEND'] = 'noninteractive'
    res = {'err': '', 'out': ''}
    if _have('apt-get'):
        res = _run(['apt-get', 'install', '-y', 'python3-scapy'], timeout=300, env=env)
        if not _have_scapy():
            _run(['apt-get', 'update', '-y'], timeout=180, env=env)
            res = _run(['apt-get', 'install', '-y', 'python3-scapy'], timeout=300, env=env)
    if not _have_scapy():
        import sys
        py = sys.executable or 'python3'
        res = _run([py, '-m', 'pip', 'install', '--break-system-packages', 'scapy'],
                   timeout=300, env=env)
    if not _have_scapy():
        tail = (res.get('err') or res.get('out') or '').strip()[-400:]
        return {'success': False, 'tool': 'scapy',
                'error': 'Could not install scapy (tried apt python3-scapy and pip). '
                         + (f'Detail: {tail}' if tail else '')}
    return {'success': True, 'tool': 'scapy', 'message': 'Installed scapy.'}


def do_install_tool(tool):
    """Install a missing network tool on demand via apt. Whitelisted packages
    only. The Ragnar service runs as root, so apt is invoked directly."""
    if tool == 'scapy':
        return _install_scapy()
    entry = _NET_TOOL_PKGS.get(tool)
    if entry is None:
        return {'success': False, 'error': f'Unknown or non-installable tool: {tool}'}
    binary, pkg = entry
    if _have(binary):
        if tool == 'lldpd':
            _configure_lldpd()
        return {'success': True, 'already_installed': True, 'tool': tool,
                'message': f'{binary} is already installed.'}
    if not _have('apt-get'):
        return {'success': False, 'tool': tool,
                'error': 'apt-get is not available; install the package manually.'}
    env = dict(os.environ)
    env['DEBIAN_FRONTEND'] = 'noninteractive'
    res = _run(['apt-get', 'install', '-y', pkg], timeout=300, env=env)
    if not _have(binary):
        # A stale or empty package index is the usual reason apt can't find the
        # package on an updated (vs freshly installed) box. Refresh once and
        # retry before giving up.
        _run(['apt-get', 'update', '-y'], timeout=180, env=env)
        res = _run(['apt-get', 'install', '-y', pkg], timeout=300, env=env)
    if not _have(binary) and 'dpkg was interrupted' in (res['err'] or '') + (res['out'] or ''):
        # A previously interrupted apt/dpkg run leaves the package system
        # half-configured; apt then refuses to do anything until it's fixed.
        # Recover automatically ('dpkg --configure -a') and retry so the user
        # doesn't have to drop to a shell.
        _run(['dpkg', '--configure', '-a'], timeout=300, env=env)
        res = _run(['apt-get', 'install', '-y', pkg], timeout=300, env=env)
    if not _have(binary):
        tail = (res['err'] or res['out'] or '').strip()
        tail = tail[-400:] if tail else 'no output'
        return {'success': False, 'tool': tool,
                'error': f'Installing {pkg} did not provide {binary}. '
                         f'apt may need a working network / package index. Detail: {tail}'}
    if tool == 'lldpd':
        _configure_lldpd()
    return {'success': True, 'tool': tool, 'message': f'Installed {pkg}.'}


def _ports_to_list(ports):
    """Best-effort port list from a hosts.ports cell (JSON array, or a
    comma/space-separated string like '22/tcp,80')."""
    if not ports:
        return []
    if isinstance(ports, (list, tuple)):
        raw = ports
    else:
        try:
            raw = json.loads(ports)
            if not isinstance(raw, list):
                raise ValueError
        except (ValueError, TypeError):
            raw = re.split(r'[,\s]+', str(ports))
    out = []
    for p in raw:
        m = re.match(r'\s*(\d+)', str(p))
        if m:
            out.append(m.group(1))
    return out


def _enrich_airtime_identity(result):
    """Join the hosts inventory (from the connected radio) onto the monitor-mode
    per-client rows by MAC, so a legacy station reads as a named device. Fully
    best-effort: any missing piece (no DB, no classifier) just leaves the row
    with whatever OUI vendor we can derive. Also rewrites slow_client findings
    to name the device instead of a bare MAC."""
    clients = result.get('clients') or []
    host_map = {}
    try:
        from init_shared import shared_data
        db = getattr(shared_data, 'db', None)
        hosts = db.get_all_hosts() if db is not None else []
    except Exception:
        hosts = []
    try:
        import device_classifier
    except Exception:
        device_classifier = None
    for h in hosts or []:
        mac = (h.get('mac') or '').strip().lower()
        if not mac:
            continue
        vendor = h.get('vendor') or None
        dtype = dlabel = None
        if device_classifier is not None:
            try:
                cls = device_classifier.classify_device(
                    vendor, _ports_to_list(h.get('ports')), device_ip=h.get('ip'))
                dtype = cls.get('device_type')
                dlabel = cls.get('label')
            except Exception:
                pass
        host_map[mac] = {'ip': h.get('ip'), 'hostname': h.get('hostname'),
                         'vendor': vendor, 'device_type': dtype,
                         'device_label': dlabel}
    wifi_defense.enrich_identity(clients, host_map, wifi_analyzer._oui_lookup)
    # Give the slow_client findings a human name where we resolved one.
    names = {}
    for c in clients:
        label = c.get('hostname') or c.get('device_label') or c.get('vendor')
        if label:
            names[c['client']] = label + (f" ({c['ip']})" if c.get('ip') else '')
    for f in result.get('findings') or []:
        if f.get('type') == 'slow_client' and f.get('client') in names:
            f['detail'] = f"{names[f['client']]} [{f['client']}]" + \
                f['detail'][len(f['client']):]


# --------------------------------------------------------------------------
# Route registration
# --------------------------------------------------------------------------

def register_network_diagnostics(app, logger=None):
    """Register all /api/net/* diagnostic routes on the given Flask app."""

    def _log(msg):
        if logger is not None:
            try:
                logger.info(msg)
            except Exception:
                pass

    def _bad(msg, code=400):
        return jsonify({'success': False, 'error': msg}), code

    @app.route('/api/net/ping', methods=['POST'])
    def net_ping():
        data = request.get_json(silent=True) or {}
        target = (data.get('target') or '').strip()
        if not _valid_target(target):
            return _bad('Invalid target')
        _log(f"net/ping {target}")
        return jsonify(do_ping(target, data.get('count', 4)))

    @app.route('/api/net/traceroute', methods=['POST'])
    def net_traceroute():
        data = request.get_json(silent=True) or {}
        target = (data.get('target') or '').strip()
        if not _valid_target(target):
            return _bad('Invalid target')
        _log(f"net/traceroute {target}")
        return jsonify(do_traceroute(target, data.get('max_hops', 20)))

    @app.route('/api/net/mtr', methods=['POST'])
    def net_mtr():
        data = request.get_json(silent=True) or {}
        target = (data.get('target') or '').strip()
        if not _valid_target(target):
            return _bad('Invalid target')
        source = (data.get('source') or '').strip() or None
        if source is not None and not _valid_target(source):
            return _bad('Invalid source')
        _log(f"net/mtr {target}" + (f" from {source}" if source else ""))
        return jsonify(do_mtr(target, data.get('count', 5), source))

    @app.route('/api/net/whois', methods=['POST'])
    def net_whois():
        data = request.get_json(silent=True) or {}
        target = (data.get('target') or '').strip()
        if not _valid_target(target):
            return _bad('Invalid target')
        _log(f"net/whois {target}")
        return jsonify(do_whois(target))

    @app.route('/api/net/ip-intel', methods=['POST'])
    def net_ip_intel():
        """Attribute an IP: country, ASN, ISP/network owner, and the abuse
        contact to report it to. Registry-derived (RDAP + Team Cymru), never a
        street address — see ip_intel.py."""
        data = request.get_json(silent=True) or {}
        target = (data.get('ip') or data.get('target') or '').strip()
        if not target:
            return _bad('No IP provided')
        _log(f"net/ip-intel {target}")
        return jsonify(do_ip_intel(target, offline=bool(data.get('offline'))))

    @app.route('/api/net/speedtest', methods=['POST'])
    def net_speedtest():
        _log("net/speedtest")
        body = request.get_json(silent=True) or {}
        iface = str(body.get('interface') or '').strip() or None
        return jsonify(do_speedtest(interface=iface))

    @app.route('/api/net/lldp', methods=['GET'])
    def net_lldp():
        _log("net/lldp")
        iface = (request.args.get('interface') or '').strip() or None
        return jsonify(do_lldp(interface=iface))

    @app.route('/api/net/arp-scan', methods=['GET'])
    def net_arp_scan():
        iface = (request.args.get('interface') or '').strip()
        if iface and not _valid_iface(iface):
            return _bad('Invalid interface')
        _log(f"net/arp-scan {iface or 'auto'}")
        return jsonify(do_arp_scan(iface or None))

    @app.route('/api/net/arp-check', methods=['GET'])
    def net_arp_check():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        _log(f"net/arp-check iface={iface or 'default-route'}")
        return jsonify(do_arp_check(interface=iface))

    @app.route('/api/net/arp-baseline', methods=['GET', 'POST'])
    def net_arp_baseline():
        # POST {action:'reset'} clears the trusted gateway baseline so the
        # current binding is re-learned (after a legitimate gateway change).
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/arp-baseline {action}")
        return jsonify(do_arp_baseline(action))

    @app.route('/api/net/dhcp-guardian', methods=['GET'])
    def net_dhcp_guardian():
        iface = (request.args.get('interface') or '').strip() or None
        secs = _clamp_int(request.args.get('seconds'), 6, 2, 20)
        quick = request.args.get('quick', '0') in ('1', 'true', 'yes')
        _log(f"net/dhcp-guardian iface={iface} quick={quick}")
        return jsonify(do_dhcp_guardian(interface=iface, capture_seconds=secs, quick=quick))

    @app.route('/api/net/dhcp-baseline', methods=['GET', 'POST'])
    def net_dhcp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/dhcp-baseline {action}")
        return jsonify(do_dhcp_baseline(action))

    @app.route('/api/net/dhcp-snoop/status', methods=['GET'])
    def net_dhcp_snoop_status():
        _log("net/dhcp-snoop/status")
        return jsonify(do_dhcp_snoop_status())

    @app.route('/api/net/dhcp-snoop/config', methods=['GET', 'POST'])
    def net_dhcp_snoop_config():
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            t = (data.get('trusted') or '').strip() or None
            u = (data.get('untrusted') or '').strip() or None
            _log(f"net/dhcp-snoop/config trusted={t} untrusted={u}")
            return jsonify(do_dhcp_snoop_config(trusted=t, untrusted=u))
        return jsonify(do_dhcp_snoop_config())

    @app.route('/api/net/dhcp-snoop/setup', methods=['POST'])
    def net_dhcp_snoop_setup():
        data = request.get_json(silent=True) or {}
        action = 'destroy' if (data.get('action') == 'destroy') else 'create'
        a = (data.get('iface_a') or '').strip()
        b = (data.get('iface_b') or '').strip()
        _log(f"net/dhcp-snoop/setup {action} {a} {b}")
        return jsonify(do_dhcp_snoop_setup(a, b, action=action))

    @app.route('/api/net/dhcp-snoop', methods=['GET'])
    def net_dhcp_snoop():
        t = (request.args.get('trusted') or '').strip() or None
        u = (request.args.get('untrusted') or '').strip() or None
        secs = _clamp_int(request.args.get('seconds'), 20, 4, 60)
        _log(f"net/dhcp-snoop trusted={t} untrusted={u} secs={secs}")
        return jsonify(do_dhcp_snoop(trusted=t, untrusted=u, seconds=secs))

    @app.route('/api/net/mac-watch', methods=['GET'])
    def net_mac_watch():
        # scan=0 reads the neighbour table only (no arp-scan sweep, silent);
        # default runs an arp-scan sweep to widen coverage.
        scan = request.args.get('scan', '1') not in ('0', 'false', 'no')
        iface = (request.args.get('interface') or '').strip() or None
        _log(f"net/mac-watch scan={scan}")
        return jsonify(do_mac_watch(scan=scan, interface=iface))

    @app.route('/api/net/mac-watch-reset', methods=['POST'])
    def net_mac_watch_reset():
        _log("net/mac-watch-reset")
        return jsonify(do_mac_watch_reset())

    @app.route('/api/net/igmp-watch', methods=['GET'])
    def net_igmp_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 12, 4, 30)
        _log(f"net/igmp-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_igmp_watch(interface=iface, seconds=secs))

    @app.route('/api/net/igmp-baseline', methods=['GET', 'POST'])
    def net_igmp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/igmp-baseline {action}")
        return jsonify(do_igmp_baseline(action))

    @app.route('/api/net/tls-watch', methods=['GET'])
    def net_tls_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        iface = iface or _capture_iface()
        secs = _clamp_int(request.args.get('seconds'), 12, 4, 30)
        no_quic = (request.args.get('no_quic') or '').lower() in ('1', 'true', 'yes')
        _log(f"net/tls-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_tls_watch(interface=iface, seconds=secs, no_quic=no_quic))

    @app.route('/api/net/ldap-watch', methods=['GET'])
    def net_ldap_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        iface = iface or _capture_iface()
        secs = _clamp_int(request.args.get('seconds'), 15, 5, 60)
        _log(f"net/ldap-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_ldap_watch(interface=iface, seconds=secs))

    @app.route('/api/net/ipv6-watch', methods=['GET'])
    def net_ipv6_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 12, 4, 40)
        _log(f"net/ipv6-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_ipv6_watch(interface=iface, seconds=secs))

    @app.route('/api/net/ipv6-baseline', methods=['GET', 'POST'])
    def net_ipv6_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/ipv6-baseline {action}")
        return jsonify(do_ipv6_baseline(action))

    @app.route('/api/net/ndp-watch', methods=['GET'])
    def net_ndp_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 12, 4, 40)
        _log(f"net/ndp-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_ndp_watch(interface=iface, seconds=secs))

    @app.route('/api/net/ndp-baseline', methods=['GET', 'POST'])
    def net_ndp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/ndp-baseline {action}")
        return jsonify(do_ndp_baseline(action))

    @app.route('/api/net/raguard', methods=['GET', 'POST'])
    def net_raguard():
        action = 'check'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'harden' if (data.get('action') == 'harden') else 'check'
        _log(f"net/raguard {action}")
        return jsonify(do_raguard(action))

    @app.route('/api/net/ntp-watch', methods=['GET'])
    def net_ntp_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 15, 5, 40)
        _log(f"net/ntp-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_ntp_watch(interface=iface, seconds=secs))

    @app.route('/api/net/ntp-baseline', methods=['GET', 'POST'])
    def net_ntp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/ntp-baseline {action}")
        return jsonify(do_ntp_baseline(action))

    @app.route('/api/net/icmp-watch', methods=['GET'])
    def net_icmp_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 12, 4, 40)
        _log(f"net/icmp-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_icmp_watch(interface=iface, seconds=secs))

    @app.route('/api/net/icmp-baseline', methods=['GET', 'POST'])
    def net_icmp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/icmp-baseline {action}")
        return jsonify(do_icmp_baseline(action))

    @app.route('/api/net/snmp-watch', methods=['GET'])
    def net_snmp_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 12, 4, 40)
        _log(f"net/snmp-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_snmp_watch(interface=iface, seconds=secs))

    @app.route('/api/net/snmp-baseline', methods=['GET', 'POST'])
    def net_snmp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/snmp-baseline {action}")
        return jsonify(do_snmp_baseline(action))

    @app.route('/api/net/cert-watch', methods=['POST'])
    def net_cert_watch():
        data = request.get_json(silent=True) or {}
        targets = (data.get('targets') or '')[:4000]
        discover = bool(data.get('discover'))
        iface = (data.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(data.get('seconds'), 8, 4, 30)
        _log(f"net/tls-watch discover={discover} iface={iface or '-'} "
             f"targets={len(_tls_parse_targets(targets))}")
        return jsonify(do_cert_watch(targets=targets, interface=iface, seconds=secs,
                                    discover=discover))

    @app.route('/api/net/cert-baseline', methods=['GET', 'POST'])
    def net_cert_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/tls-baseline {action}")
        return jsonify(do_cert_baseline(action))

    @app.route('/api/net/relay-watch', methods=['GET'])
    def net_relay_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 20, 5, 50)
        _log(f"net/relay-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_relay_watch(interface=iface, seconds=secs))

    @app.route('/api/net/relay-baseline', methods=['GET', 'POST'])
    def net_relay_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/relay-baseline {action}")
        return jsonify(do_relay_baseline(action))

    @app.route('/api/net/smb-watch', methods=['GET'])
    def net_smb_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 20, 5, 50)
        _log(f"net/smb-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_smb_watch(interface=iface, seconds=secs))

    @app.route('/api/net/smb-baseline', methods=['GET', 'POST'])
    def net_smb_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/smb-baseline {action}")
        return jsonify(do_smb_baseline(action))

    @app.route('/api/net/isis-watch', methods=['GET'])
    def net_isis_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 20, 5, 50)
        _log(f"net/isis-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_isis_watch(interface=iface, seconds=secs))

    @app.route('/api/net/isis-baseline', methods=['GET', 'POST'])
    def net_isis_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/isis-baseline {action}")
        return jsonify(do_isis_baseline(action))

    @app.route('/api/net/stp-watch', methods=['GET'])
    def net_stp_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 20, 5, 50)
        _log(f"net/stp-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_stp_watch(interface=iface, seconds=secs))

    @app.route('/api/net/stp-baseline', methods=['GET', 'POST'])
    def net_stp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/stp-baseline {action}")
        return jsonify(do_stp_baseline(action))

    @app.route('/api/net/dtp-watch', methods=['GET'])
    def net_dtp_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 30, 5, 65)
        _log(f"net/dtp-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_dtp_watch(interface=iface, seconds=secs))

    @app.route('/api/net/dtp-baseline', methods=['GET', 'POST'])
    def net_dtp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/dtp-baseline {action}")
        return jsonify(do_dtp_baseline(action))

    @app.route('/api/net/cdp-watch', methods=['GET'])
    def net_cdp_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 30, 5, 65)
        _log(f"net/cdp-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_cdp_watch(interface=iface, seconds=secs))

    @app.route('/api/net/cdp-baseline', methods=['GET', 'POST'])
    def net_cdp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/cdp-baseline {action}")
        return jsonify(do_cdp_baseline(action))

    @app.route('/api/net/vtp-watch', methods=['GET'])
    def net_vtp_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 30, 5, 65)
        _log(f"net/vtp-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_vtp_watch(interface=iface, seconds=secs))

    @app.route('/api/net/vtp-baseline', methods=['GET', 'POST'])
    def net_vtp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/vtp-baseline {action}")
        return jsonify(do_vtp_baseline(action))

    @app.route('/api/net/eigrp-watch', methods=['GET'])
    def net_eigrp_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 15, 5, 40)
        _log(f"net/eigrp-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_eigrp_watch(interface=iface, seconds=secs))

    @app.route('/api/net/eigrp-baseline', methods=['GET', 'POST'])
    def net_eigrp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/eigrp-baseline {action}")
        return jsonify(do_eigrp_baseline(action))

    @app.route('/api/net/fhrp-watch', methods=['GET'])
    def net_fhrp_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 15, 4, 40)
        _log(f"net/fhrp-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_fhrp_watch(interface=iface, seconds=secs))

    @app.route('/api/net/fhrp-baseline', methods=['GET', 'POST'])
    def net_fhrp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/fhrp-baseline {action}")
        return jsonify(do_fhrp_baseline(action))

    @app.route('/api/net/ospf-watch', methods=['GET'])
    def net_ospf_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 15, 5, 40)
        _log(f"net/ospf-watch iface={iface or 'default-route'} secs={secs}")
        return jsonify(do_ospf_watch(interface=iface, seconds=secs))

    @app.route('/api/net/ospf-baseline', methods=['GET', 'POST'])
    def net_ospf_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/ospf-baseline {action}")
        return jsonify(do_ospf_baseline(action))

    @app.route('/api/net/bgp-watch', methods=['GET'])
    def net_bgp_watch():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        secs = _clamp_int(request.args.get('seconds'), 15, 5, 40)
        enrich = request.args.get('enrich', '1') not in ('0', 'false', 'no')
        _log(f"net/bgp-watch iface={iface or 'default-route'} secs={secs} enrich={enrich}")
        return jsonify(do_bgp_watch(interface=iface, seconds=secs, enrich=enrich))

    @app.route('/api/net/bgp-baseline', methods=['GET', 'POST'])
    def net_bgp_baseline():
        action = 'get'
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            action = 'reset' if (data.get('action') == 'reset') else 'get'
        _log(f"net/bgp-baseline {action}")
        return jsonify(do_bgp_baseline(action))

    @app.route('/api/net/bgp-collector', methods=['GET', 'POST'])
    def net_bgp_collector():
        if request.method == 'GET':
            action = (request.args.get('action') or 'status').strip()
            if action not in ('status', 'rib'):
                action = 'status'
            _log(f"net/bgp-collector {action}")
            return jsonify(do_bgp_collector(action))
        data = request.get_json(silent=True) or {}
        action = (data.get('action') or 'status').strip()
        if action not in ('start', 'stop', 'status', 'rib'):
            return _bad('action must be start/stop/status/rib')
        _log(f"net/bgp-collector {action} peer={data.get('peer_ip')} "
             f"peers={len(data.get('peers') or [])}")
        return jsonify(do_bgp_collector(
            action, peer_ip=data.get('peer_ip'), peer_as=data.get('peer_as'),
            local_as=data.get('local_as'), router_id=data.get('router_id'),
            port=data.get('port', 179), hold=data.get('hold', 90),
            peers=data.get('peers'), peer=data.get('peer')))

    @app.route('/api/net/owd-reflector', methods=['GET', 'POST'])
    def net_owd_reflector():
        if request.method == 'GET':
            return jsonify(do_owd_reflector('status'))
        data = request.get_json(silent=True) or {}
        action = (data.get('action') or 'status').strip()
        if action not in ('start', 'stop', 'status'):
            return _bad('action must be start/stop/status')
        _log(f"net/owd-reflector {action}")
        return jsonify(do_owd_reflector(action, port=data.get('port', path_asymmetry.DEFAULT_PORT)))

    @app.route('/api/net/path-asymmetry', methods=['POST'])
    def net_path_asymmetry():
        data = request.get_json(silent=True) or {}
        target = (data.get('target') or '').strip()
        if not target:
            return _bad('target required')
        _log(f"net/path-asymmetry target={target}")
        return jsonify(do_path_asymmetry(
            target, port=data.get('port', path_asymmetry.DEFAULT_PORT),
            count=data.get('count', 20), threshold_ms=data.get('threshold_ms', 5.0),
            clock_synced=bool(data.get('clock_synced', False))))

    @app.route('/api/net/routing-selftest', methods=['GET'])
    def net_routing_selftest():
        _log("net/routing-selftest")
        return jsonify(do_routing_selftest())

    @app.route('/api/net/identity', methods=['GET'])
    def net_identity():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        _log(f"net/identity {iface or 'auto'}")
        return jsonify(do_network_identity(interface=iface))

    @app.route('/api/net/install-tool', methods=['POST'])
    def net_install_tool():
        data = request.get_json(silent=True) or {}
        tool = (data.get('tool') or '').strip()
        _log(f"net/install-tool {tool}")
        return jsonify(do_install_tool(tool))

    @app.route('/api/net/interfaces', methods=['GET'])
    def net_interfaces():
        _log("net/interfaces")
        include_virtual = request.args.get('all') in ('1', 'true', 'yes')
        return jsonify(do_interfaces(include_virtual=include_virtual))

    # ------------------------------------------------------------------
    # Passive Wi-Fi spectrum analyzer (wifi_analyzer.py) — Ekahau-style
    # tri-band troubleshooter. Strictly passive: iw scan passive only.
    # ------------------------------------------------------------------
    @app.route('/api/net/wifi/interfaces', methods=['GET'])
    def net_wifi_interfaces():
        _log("net/wifi/interfaces")
        return jsonify({"interfaces": wifi_analyzer.list_wifi_interfaces()})

    @app.route('/api/net/wifi/scan', methods=['GET'])
    def net_wifi_scan():
        iface = (request.args.get('interface') or 'wlan0').strip()
        band = (request.args.get('band') or 'all').strip()
        if not _valid_iface(iface):
            return _bad('Invalid interface')
        if band not in ('all', '2.4', '5', '6'):
            return _bad('Invalid band')
        _log(f"net/wifi/scan {iface} band={band}")
        return jsonify(wifi_analyzer.do_scan(interface=iface, band=band, passive=True))

    @app.route('/api/net/wifi/report', methods=['POST'])
    def net_wifi_report():
        """Render the on-screen spectrum scan as a printable HTML report.

        Takes the scan JSON the client already has (same pattern as the AI
        analysis) so it reports exactly what's shown, with no extra re-scan."""
        data = request.get_json(silent=True) or {}
        scan = data.get('scan') or {}
        if not isinstance(scan, dict) or not scan.get('aps'):
            return _bad('No scan data — run a spectrum scan first')
        device = (data.get('device') or 'Ragnar').strip()[:64]
        # Optional companions the panel carries: the live 2.4 GHz Bluetooth /
        # Zigbee overlays and the last AI analysis, so the report mirrors the UI.
        bt = data.get('bt') if isinstance(data.get('bt'), dict) else None
        zb = data.get('zb') if isinstance(data.get('zb'), dict) else None
        ai = data.get('ai') if isinstance(data.get('ai'), dict) else None
        _log("net/wifi/report")
        html = report_common.build_spectrum_report_html(
            scan, device_name=device, bt=bt, zb=zb, ai=ai)
        return html, 200, {'Content-Type': 'text/html; charset=utf-8'}

    @app.route('/api/net/wifi/radius', methods=['GET'])
    def net_wifi_radius():
        iface = (request.args.get('interface') or 'wlan0').strip()
        bssid = (request.args.get('bssid') or '').strip()
        if not _valid_iface(iface):
            return _bad('Invalid interface')
        try:
            _tx = request.args.get('tx')
            tx = float(_tx) if _tx not in (None, '', 'auto') else None
            ple = float(request.args.get('ple', wifi_analyzer._DEFAULT_PLE))
            rssi_offset = float(request.args.get('rssi_offset', 0) or 0)
            antenna_gain = float(request.args.get('antenna_gain', 0) or 0)
            cable_loss = float(request.args.get('cable_loss', 0) or 0)
            _r0 = request.args.get('rssi0')
            rssi0 = float(_r0) if _r0 not in (None, '', 'auto') else None
            _sig = request.args.get('signal')
            sig = float(_sig) if _sig not in (None, '', 'auto') else None
        except (TypeError, ValueError):
            return _bad('Invalid calibration parameter')
        _log(f"net/wifi/radius {iface} {bssid}")
        cal = dict(tx_dbm=tx, ple=ple, rssi_offset=rssi_offset,
                   antenna_gain=antenna_gain, cable_loss=cable_loss,
                   rssi0_override=rssi0)
        # Prefer the already-known reading the client is displaying (no re-scan,
        # no race with a fresh scan that might not hear the AP this instant).
        if sig is not None:
            def _f(name, cast=float):
                v = request.args.get(name)
                if v in (None, '', 'auto'):
                    return None
                try:
                    return cast(v)
                except (TypeError, ValueError):
                    return None
            fields = {
                "bssid": bssid, "ssid": request.args.get('ssid'),
                "band": request.args.get('band'), "channel": _f('channel', int),
                "freq": _f('freq'), "center_freq": _f('center_freq'),
                "signal": sig, "tx_power_dbm": _f('tx_measured'),
            }
            return jsonify(wifi_analyzer.radius_from_fields(fields, **cal))
        return jsonify(wifi_analyzer.do_radius(iface, bssid, **cal))

    @app.route('/api/net/wifi/calibrate', methods=['GET'])
    def net_wifi_calibrate():
        """Two-point path-loss calibration: solve ple + rssi@1m from two
        (distance_m, rssi) measurements."""
        try:
            r = wifi_analyzer.calibrate_ple(
                request.args.get('d1'), request.args.get('rssi1'),
                request.args.get('d2'), request.args.get('rssi2'))
        except (TypeError, ValueError):
            return _bad('Invalid calibration points')
        return jsonify(r)

    @app.route('/api/net/wifi/heatmap', methods=['GET', 'POST'])
    def net_wifi_heatmap():
        if request.method == 'GET':
            return jsonify(wifi_analyzer.heatmap_get())
        data = request.get_json(silent=True) or {}
        action = data.get('action')
        if action == 'floorplan':
            return jsonify(wifi_analyzer.heatmap_set_floorplan(
                data.get('floorplan'), data.get('bssid'), data.get('ssid')))
        if action == 'clear':
            return jsonify(wifi_analyzer.heatmap_clear())
        if action == 'walls':
            return jsonify(wifi_analyzer.heatmap_set_walls(data.get('walls') or []))
        if action == 'columns':
            return jsonify(wifi_analyzer.heatmap_set_columns(data.get('columns') or []))
        if action == 'predict_ap':
            return jsonify(wifi_analyzer.heatmap_set_predict_ap(data.get('ap')))
        if action == 'predict_aps':
            return jsonify(wifi_analyzer.heatmap_set_predict_aps(data.get('aps') or []))
        if action == 'sample_live':
            iface = (data.get('interface') or 'wlan0').strip()
            if not _valid_iface(iface):
                return _bad('Invalid interface')
            try:
                secs = max(2, min(30, int(data.get('seconds', 5))))
            except (TypeError, ValueError):
                secs = 5
            return jsonify(wifi_analyzer.heatmap_sample_live(
                iface, data.get('x'), data.get('y'), data.get('bssid'),
                active=bool(data.get('active')),
                iperf_server=(data.get('iperf_server') or None),
                url=(data.get('url') or None), seconds=secs))
        if action == 'sample_mesh':
            iface = (data.get('interface') or 'wlan0').strip()
            if not _valid_iface(iface):
                return _bad('Invalid interface')
            try:
                secs = max(2, min(30, int(data.get('seconds', 5))))
            except (TypeError, ValueError):
                secs = 5
            return jsonify(wifi_analyzer.heatmap_sample_mesh_live(
                iface, data.get('x'), data.get('y'), data.get('ssid'),
                active=bool(data.get('active')),
                iperf_server=(data.get('iperf_server') or None),
                url=(data.get('url') or None), seconds=secs))
        if action == 'throughput':
            # One-off active measurement (for a "Test now" button, no sample).
            try:
                secs = max(2, min(30, int(data.get('seconds', 5))))
            except (TypeError, ValueError):
                secs = 5
            return jsonify(wifi_analyzer.measure_throughput(
                iperf_server=(data.get('iperf_server') or None),
                url=(data.get('url') or None), seconds=secs))
        if action == 'sample':
            return jsonify(wifi_analyzer.heatmap_add_sample(
                data.get('x'), data.get('y'), data.get('rssi'),
                data.get('bssid'), data.get('ssid')))
        return _bad('Unknown action')

    @app.route('/api/net/wifi/surveys', methods=['GET', 'POST'])
    def net_wifi_surveys():
        if request.method == 'GET':
            return jsonify(wifi_analyzer.survey_list())
        data = request.get_json(silent=True) or {}
        action = data.get('action')
        name = data.get('name')
        if action == 'save':
            return jsonify(wifi_analyzer.survey_save(name))
        if action == 'load':
            return jsonify(wifi_analyzer.survey_load(name))
        if action == 'delete':
            return jsonify(wifi_analyzer.survey_delete(name))
        return _bad('Unknown action')

    @app.route('/api/net/wifi/selftest', methods=['GET'])
    def net_wifi_selftest():
        _log("net/wifi/selftest")
        return jsonify(wifi_analyzer.selftest())

    @app.route('/api/net/wifi/history', methods=['GET', 'POST'])
    def net_wifi_history():
        if request.method == 'POST':
            _log("net/wifi/history reset")
            return jsonify(wifi_analyzer.db_reset())
        return jsonify({"aps": wifi_analyzer.db_get()})

    # ------------------------------------------------------------------
    # Bluetooth / BLE 2.4 GHz overlay (bt_scanner.py) — device-discovery
    # companion to the Wi-Fi analyzer. Receive-only: discovery, never pairs
    # or connects. Maps BT/BLE energy onto the same 2.4 GHz band.
    # ------------------------------------------------------------------
    @app.route('/api/net/bt/controllers', methods=['GET'])
    def net_bt_controllers():
        _log("net/bt/controllers")
        return jsonify({"controllers": bt_scanner.list_controllers()})

    @app.route('/api/net/bt/scan', methods=['GET'])
    def net_bt_scan():
        ctrl = (request.args.get('controller') or '').strip() or None
        if ctrl is not None and not bt_scanner._valid_controller(ctrl):
            return _bad('Invalid controller')
        try:
            dur = int(request.args.get('duration', bt_scanner._DEFAULT_DURATION))
        except (TypeError, ValueError):
            return _bad('Invalid duration')
        _log(f"net/bt/scan controller={ctrl} {dur}s")
        return jsonify(bt_scanner.do_scan(controller=ctrl, duration=dur))

    @app.route('/api/net/bt/selftest', methods=['GET'])
    def net_bt_selftest():
        _log("net/bt/selftest")
        return jsonify(bt_scanner.selftest())

    # ------------------------------------------------------------------
    # True-RF spectrum / waterfall via a HackRF SDR (sdr_spectrum.py).
    # Measures actual on-air energy (any protocol). Receive-only. The UI
    # gates the Waterfall view on /status.available (device present).
    # ------------------------------------------------------------------
    @app.route('/api/net/sdr/status', methods=['GET'])
    def net_sdr_status():
        _log("net/sdr/status")
        return jsonify(sdr_spectrum.status())

    @app.route('/api/net/sdr/start', methods=['POST'])
    def net_sdr_start():
        data = request.get_json(silent=True) or {}
        band = (data.get('band') or '2.4').strip()
        if band not in sdr_spectrum.BANDS:
            return _bad('Invalid band')
        lna = data.get('lna')
        vga = data.get('vga')
        _log(f"net/sdr/start band={band}")
        return jsonify(sdr_spectrum.start(band=band, lna=lna, vga=vga))

    @app.route('/api/net/sdr/stop', methods=['POST'])
    def net_sdr_stop():
        _log("net/sdr/stop")
        return jsonify(sdr_spectrum.stop())

    @app.route('/api/net/sdr/frames', methods=['GET'])
    def net_sdr_frames():
        try:
            since = int(request.args.get('since', 0))
        except (TypeError, ValueError):
            return _bad('Invalid since')
        return jsonify(sdr_spectrum.get_frames(since=since))

    @app.route('/api/net/sdr/selftest', methods=['GET'])
    def net_sdr_selftest():
        _log("net/sdr/selftest")
        return jsonify(sdr_spectrum.selftest())

    # ------------------------------------------------------------------
    # Zigbee / 802.15.4 overlay via an on-demand HuginnESP sniff
    # (zigbee_scan.py + zigbee_overlay.py). Receive-only. The UI gates the
    # Zigbee toggle on /status.available (a Huginn companion is present).
    # ------------------------------------------------------------------
    @app.route('/api/net/zigbee/status', methods=['GET'])
    def net_zigbee_status():
        _log("net/zigbee/status")
        return jsonify(zigbee_scan.detect())

    @app.route('/api/net/zigbee/scan', methods=['GET'])
    def net_zigbee_scan():
        port = (request.args.get('port') or '').strip() or None
        if port is not None and not zigbee_scan._valid_port(port):
            return _bad('Invalid port')
        try:
            dur = int(request.args.get('duration', zigbee_scan._DEFAULT_DURATION))
        except (TypeError, ValueError):
            return _bad('Invalid duration')
        _log(f"net/zigbee/scan port={port} {dur}s")
        return jsonify(zigbee_scan.scan(port=port, duration=dur))

    @app.route('/api/net/zigbee/selftest', methods=['GET'])
    def net_zigbee_selftest():
        _log("net/zigbee/selftest")
        return jsonify(zigbee_scan.selftest())

    # ------------------------------------------------------------------
    # WiFi Defense — 802.11 frame monitor / WIDS (wifi_defense.py).
    # Detection-only; needs a monitor-mode adapter. Never transmits.
    # ------------------------------------------------------------------
    @app.route('/api/wifidef/interfaces', methods=['GET'])
    def wifidef_interfaces():
        _log("wifidef/interfaces")
        return jsonify(wifi_defense.list_monitor_capable())

    @app.route('/api/wifidef/monitor', methods=['POST'])
    def wifidef_monitor():
        data = request.get_json(silent=True) or {}
        iface = (data.get('interface') or '').strip()
        action = data.get('action')
        if action == 'disable':
            _log("wifidef/monitor disable")
            return jsonify(wifi_defense.disable_monitor())
        if not _valid_iface(iface):
            return _bad('Invalid interface')
        _log(f"wifidef/monitor enable {iface}")
        return jsonify(wifi_defense.enable_monitor(iface))

    @app.route('/api/wifidef/scan', methods=['GET'])
    def wifidef_scan():
        iface = (request.args.get('interface') or '').strip()
        if not _valid_iface(iface):
            return _bad('Invalid interface')
        try:
            secs = int(request.args.get('seconds', 15))
        except (TypeError, ValueError):
            return _bad('Invalid seconds')
        ch = request.args.get('channel')
        try:
            ch = int(ch) if ch not in (None, '', 'auto') else None
        except (TypeError, ValueError):
            return _bad('Invalid channel')
        _log(f"wifidef/scan {iface} {secs}s ch={ch}")
        return jsonify(wifi_defense.do_scan(iface, seconds=secs, channel=ch))

    @app.route('/api/wifidef/baseline', methods=['GET', 'POST'])
    def wifidef_baseline():
        if request.method == 'GET':
            return jsonify({"baseline": wifi_defense.get_baseline()})
        data = request.get_json(silent=True) or {}
        action = data.get('action')
        if action == 'clear':
            _log("wifidef/baseline clear")
            return jsonify({"ok": True, "baseline": wifi_defense.clear_baseline(),
                            "ssids": 0})
        # Trust the AP inventory the client is already showing (no re-capture) —
        # trusts exactly what's on screen and merges into the baseline.
        aps = data.get('aps')
        if isinstance(aps, list) and aps:
            _log(f"wifidef/baseline trust {len(aps)} shown APs")
            return jsonify(wifi_defense.trust_aps(aps))
        iface = (data.get('interface') or '').strip()
        if not _valid_iface(iface):
            return _bad('Invalid interface')
        try:
            secs = int(data.get('seconds', 20))
        except (TypeError, ValueError):
            return _bad('Invalid seconds')
        _log(f"wifidef/baseline learn {iface}")
        return jsonify(wifi_defense.learn_baseline(iface, seconds=secs))

    @app.route('/api/wifidef/airtime', methods=['GET'])
    def wifidef_airtime():
        iface = (request.args.get('interface') or '').strip()
        if not _valid_iface(iface):
            return _bad('Invalid interface')
        try:
            secs = max(3, min(60, int(request.args.get('seconds', 10))))
        except (TypeError, ValueError):
            secs = 10
        ch = request.args.get('channel')
        channel = int(ch) if (ch and ch.isdigit()) else None
        _log(f"wifidef/airtime {iface} ch={channel}")
        result = wifi_defense.do_airtime(iface, seconds=secs, channel=channel)
        # Fuse radio-layer PHY (who is 802.11b, by MAC) with network-layer
        # identity from the connected radio's host inventory (what each MAC is).
        if isinstance(result, dict) and result.get('clients'):
            try:
                _enrich_airtime_identity(result)
            except Exception as exc:                      # never fail the scan
                _log(f"wifidef/airtime identity enrich skipped: {exc}")
        return jsonify(result)

    @app.route('/api/wifidef/isolation', methods=['GET'])
    def wifidef_isolation():
        iface = (request.args.get('interface') or '').strip()
        if not _valid_iface(iface):
            return _bad('Invalid interface')
        try:
            secs = max(5, min(120, int(request.args.get('seconds', 20))))
        except (TypeError, ValueError):
            secs = 20
        ch = request.args.get('channel')
        channel = int(ch) if (ch and ch.isdigit()) else None
        _log(f"wifidef/isolation {iface} ch={channel}")
        return jsonify(wifi_defense.do_isolation(iface, seconds=secs,
                                                 channel=channel))

    @app.route('/api/wifidef/thresholds', methods=['GET', 'POST'])
    def wifidef_thresholds():
        if request.method == 'GET':
            return jsonify(wifi_defense.get_thresholds())
        data = request.get_json(silent=True) or {}
        try:
            return jsonify(wifi_defense.set_thresholds(
                beacon_ssids=data.get('beacon_ssids'),
                beacon_bssids=data.get('beacon_bssids')))
        except (TypeError, ValueError):
            return _bad('Invalid threshold')

    @app.route('/api/wifidef/selftest', methods=['GET'])
    def wifidef_selftest():
        _log("wifidef/selftest")
        return jsonify(wifi_defense.selftest())

    @app.route('/api/wifidef/report', methods=['POST'])
    def wifidef_report():
        """Render the on-screen WIDS capture as a printable incident report.

        Takes the last scan result the client is displaying so the report
        matches the panel exactly and needs no fresh capture."""
        data = request.get_json(silent=True) or {}
        scan = data.get('scan') or {}
        if not isinstance(scan, dict) or 'threat' not in scan:
            return _bad('No capture data — run a WiFi Defense scan first')
        device = (data.get('device') or 'Ragnar').strip()[:64]
        _log("wifidef/report")
        html = report_common.build_defense_report_html(scan, device_name=device)
        return html, 200, {'Content-Type': 'text/html; charset=utf-8'}

    @app.route('/api/net/isp', methods=['GET'])
    def net_isp():
        iface = (request.args.get('interface') or '').strip() or None
        _log(f"net/isp {iface or 'all'}")
        return jsonify(do_isp(interface=iface))

    @app.route('/api/net/vpn-check', methods=['GET'])
    def net_vpn_check():
        iface = (request.args.get('interface') or '').strip() or None
        if iface is not None and not _valid_iface(iface):
            return _bad('Invalid interface')
        _log(f"net/vpn-check {iface or 'default-route'}")
        return jsonify(do_vpn_check(interface=iface))

    @app.route('/api/net/dns', methods=['POST'])
    def net_dns():
        data = request.get_json(silent=True) or {}
        _log("net/dns")
        return jsonify(do_dns_doctor(data.get('name') or data.get('target')))

    @app.route('/api/net/pmtu', methods=['POST'])
    def net_pmtu():
        data = request.get_json(silent=True) or {}
        _log("net/pmtu")
        return jsonify(do_pmtu(data.get('target')))

    @app.route('/api/net/captive-portal', methods=['GET'])
    def net_captive_portal():
        _log("net/captive-portal")
        return jsonify(do_captive_portal())

    @app.route('/api/net/iperf3', methods=['POST'])
    def net_iperf3():
        data = request.get_json(silent=True) or {}
        _log(f"net/iperf3 client {data.get('server')}")
        return jsonify(do_iperf3_client(data.get('server'), data.get('port', 5201),
                                        data.get('duration', 5),
                                        bool(data.get('reverse')), bool(data.get('udp'))))

    @app.route('/api/net/iperf3-server', methods=['POST'])
    def net_iperf3_server():
        data = request.get_json(silent=True) or {}
        action = (data.get('action') or 'status').strip()
        _log(f"net/iperf3-server {action}")
        return jsonify(do_iperf3_server(action))

    @app.route('/api/net/pcap', methods=['POST'])
    def net_pcap():
        _log("net/pcap upload")
        return jsonify(do_pcap_from_upload(request.files.get('file')))

    @app.route('/api/net/pcap/stored', methods=['GET'])
    def net_pcap_stored():
        _log("net/pcap stored list")
        return jsonify(do_pcap_list_stored())

    @app.route('/api/net/pcap/stored/analyze', methods=['POST'])
    def net_pcap_stored_analyze():
        data = request.get_json(silent=True) or {}
        _log("net/pcap stored analyze")
        return jsonify(do_pcap_analyze_path((data.get('path') or '').strip()))

    @app.route('/api/net/pcap/capture', methods=['POST'])
    def net_pcap_capture():
        data = request.get_json(silent=True) or {}
        _log("net/pcap capture")
        return jsonify(do_pcap_capture(
            interface=(data.get('interface') or '').strip() or None,
            seconds=data.get('seconds', 10),
            bpf=(data.get('bpf') or '').strip() or None,
            monitor=bool(data.get('monitor')),
            channel=(data.get('channel') or None)))

    @app.route('/api/net/flows', methods=['GET'])
    def net_flows():
        _log("net/flows")
        return jsonify(do_flow_telemetry(request.args.get('limit', 15)))

    @app.route('/api/net/ptp', methods=['POST'])
    def net_ptp():
        data = request.get_json(silent=True) or {}
        iface = (data.get('interface') or '').strip()
        _log(f"net/ptp {iface}")
        return jsonify(do_ptp_detect(iface, data.get('seconds', 8)))

    @app.route('/api/net/l2-health', methods=['POST'])
    def net_l2_health():
        data = request.get_json(silent=True) or {}
        iface = (data.get('interface') or '').strip()
        _log(f"net/l2-health {iface}")
        return jsonify(do_l2_health(iface, data.get('seconds', 12)))

    @app.route('/api/net/locate-port', methods=['POST'])
    def net_locate_port():
        data = request.get_json(silent=True) or {}
        iface = (data.get('interface') or '').strip()
        method = (data.get('method') or 'flap')
        _log(f"net/locate-port {iface} ({method})")
        return jsonify(do_locate_port(iface, data.get('count', 6),
                                      data.get('on_ms', 800), data.get('off_ms', 800),
                                      bool(data.get('force')), method))

    if logger is not None:
        try:
            logger.info("Network diagnostics routes registered (/api/net/*)")
        except Exception:
            pass
    return app


# --------------------------------------------------------------------------
# Small CLI — currently the IGMP Watch scanner and its self-test, so the
# passive multicast checks can run standalone (cron, SSH, CI) without the web
# app.  Usage:
#     python3 network_diagnostics.py igmp-watch [--iface eth0] [--seconds 12] [--json]
#     python3 network_diagnostics.py igmp-selftest [--json]
# --------------------------------------------------------------------------

def _cli(argv=None):
    import argparse
    p = argparse.ArgumentParser(
        prog='network_diagnostics',
        description='Ragnar passive network diagnostics (CLI subset).')
    sub = p.add_subparsers(dest='cmd')

    w = sub.add_parser('igmp-watch', help='passive IGMP-snooping security scan')
    w.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    w.add_argument('--seconds', '-s', type=int, default=12, help='capture window (4-30)')
    w.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    w.add_argument('--json', action='store_true', help='emit JSON')

    st = sub.add_parser('igmp-selftest', help='self-test the IGMP detectors (no root)')
    st.add_argument('--json', action='store_true', help='emit JSON')

    tw = sub.add_parser('tls-watch', help='passive TLS/QUIC handshake observer')
    tw.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    tw.add_argument('--seconds', '-s', type=int, default=12, help='capture window (4-30)')
    tw.add_argument('--no-quic', action='store_true', help='skip QUIC observation')
    tw.add_argument('--json', action='store_true', help='emit JSON')

    tst = sub.add_parser('tls-selftest', help='self-test the TLS Watch detectors (no root)')
    tst.add_argument('--json', action='store_true', help='emit JSON')

    lw = sub.add_parser('ldap-watch',
                        help='passive LDAP / Active Directory watch (bind/enum/CLDAP)')
    lw.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    lw.add_argument('--seconds', '-s', type=int, default=15, help='capture window (5-60)')
    lw.add_argument('--json', action='store_true', help='emit JSON')

    lst = sub.add_parser('ldap-selftest',
                         help='self-test the LDAP Watch detectors (no root)')
    lst.add_argument('--json', action='store_true', help='emit JSON')

    v6 = sub.add_parser('ipv6-watch', help='passive IPv6 first-hop (RA/DHCPv6) scan')
    v6.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    v6.add_argument('--seconds', '-s', type=int, default=12, help='capture window (4-40)')
    v6.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    v6.add_argument('--json', action='store_true', help='emit JSON')

    v6st = sub.add_parser('ipv6-selftest', help='self-test the IPv6 first-hop detectors (no root)')
    v6st.add_argument('--json', action='store_true', help='emit JSON')

    ndp = sub.add_parser('ndp-watch', help='passive IPv6 Neighbor Discovery spoofing scan')
    ndp.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    ndp.add_argument('--seconds', '-s', type=int, default=12, help='capture window (4-40)')
    ndp.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    ndp.add_argument('--json', action='store_true', help='emit JSON')

    ndpst = sub.add_parser('ndp-selftest', help='self-test the NDP spoofing detectors (no root)')
    ndpst.add_argument('--json', action='store_true', help='emit JSON')

    rg = sub.add_parser('raguard', help='IPv6 RA Guard: audit (and optionally harden) host first-hop posture')
    rg.add_argument('--harden', action='store_true', help='apply + persist the safe sysctls')
    rg.add_argument('--json', action='store_true', help='emit JSON')

    rgst = sub.add_parser('raguard-selftest', help='self-test the RA Guard grader (no root)')
    rgst.add_argument('--json', action='store_true', help='emit JSON')

    nt = sub.add_parser('ntp-watch', help='passive NTP (rogue time-source) scan')
    nt.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    nt.add_argument('--seconds', '-s', type=int, default=15, help='capture window (5-40)')
    nt.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    nt.add_argument('--json', action='store_true', help='emit JSON')

    ntst = sub.add_parser('ntp-selftest', help='self-test the NTP detectors (no root)')
    ntst.add_argument('--json', action='store_true', help='emit JSON')

    ic = sub.add_parser('icmp-watch', help='passive ICMP (redirect/IRDP) L3 scan')
    ic.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    ic.add_argument('--seconds', '-s', type=int, default=12, help='capture window (4-40)')
    ic.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    ic.add_argument('--json', action='store_true', help='emit JSON')

    icst = sub.add_parser('icmp-selftest', help='self-test the ICMP detectors (no root)')
    icst.add_argument('--json', action='store_true', help='emit JSON')

    sn = sub.add_parser('snmp-watch', help='passive SNMP (v1/v2c cleartext) scan')
    sn.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    sn.add_argument('--seconds', '-s', type=int, default=12, help='capture window (4-40)')
    sn.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    sn.add_argument('--json', action='store_true', help='emit JSON')

    snst = sub.add_parser('snmp-selftest', help='self-test the SNMP detectors (no root)')
    snst.add_argument('--json', action='store_true', help='emit JSON')

    tw = sub.add_parser('cert-watch', help='active TLS/certificate hygiene checker')
    tw.add_argument('targets', nargs='*', help='host[:port] target(s) to grade')
    tw.add_argument('--discover', action='store_true',
                    help='passively discover TLS servers on the segment first')
    tw.add_argument('--iface', '-i', default=None, help='interface for discovery')
    tw.add_argument('--seconds', '-s', type=int, default=8, help='discovery window (4-30)')
    tw.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    tw.add_argument('--json', action='store_true', help='emit JSON')

    twst = sub.add_parser('cert-selftest', help='self-test the TLS/cert grader (no root)')
    twst.add_argument('--json', action='store_true', help='emit JSON')

    rl = sub.add_parser('relay-watch', help='passive NTLM-relay + coercion scan')
    rl.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    rl.add_argument('--seconds', '-s', type=int, default=20, help='capture window (5-50)')
    rl.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    rl.add_argument('--json', action='store_true', help='emit JSON')

    rlst = sub.add_parser('relay-selftest', help='self-test the relay/coercion detectors (no root)')
    rlst.add_argument('--json', action='store_true', help='emit JSON')

    sm = sub.add_parser('smb-watch',
                        help='passive SMBv1 + LLMNR/NBT-NS/mDNS poisoning + Kerberos downgrade scan')
    sm.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    sm.add_argument('--seconds', '-s', type=int, default=20, help='capture window (5-50)')
    sm.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    sm.add_argument('--json', action='store_true', help='emit JSON')

    smst = sub.add_parser('smb-selftest', help='self-test the SMB Watch detectors (no root)')
    smst.add_argument('--json', action='store_true', help='emit JSON')

    ii = sub.add_parser('isis-watch', help='passive IS-IS routing-security scan')
    ii.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    ii.add_argument('--seconds', '-s', type=int, default=20, help='capture window (5-50)')
    ii.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    ii.add_argument('--json', action='store_true', help='emit JSON')

    iist = sub.add_parser('isis-selftest', help='self-test the IS-IS detectors (no root)')
    iist.add_argument('--json', action='store_true', help='emit JSON')

    st = sub.add_parser('stp-watch', help='passive STP/BPDU spanning-tree security scan')
    st.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    st.add_argument('--seconds', '-s', type=int, default=20, help='capture window (5-50)')
    st.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    st.add_argument('--json', action='store_true', help='emit JSON')

    stst = sub.add_parser('stp-selftest', help='self-test the STP/BPDU detectors (no root)')
    stst.add_argument('--json', action='store_true', help='emit JSON')

    dt = sub.add_parser('dtp-watch', help='passive DTP / VLAN-hopping scan (Cisco)')
    dt.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    dt.add_argument('--seconds', '-s', type=int, default=30, help='capture window (5-65)')
    dt.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    dt.add_argument('--json', action='store_true', help='emit JSON')

    dtst = sub.add_parser('dtp-selftest', help='self-test the DTP detector (no root)')
    dtst.add_argument('--json', action='store_true', help='emit JSON')

    cdp = sub.add_parser('cdp-watch', help='passive CDP flood/spoof/info-leak scan (Cisco)')
    cdp.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    cdp.add_argument('--seconds', '-s', type=int, default=30, help='capture window (5-65)')
    cdp.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    cdp.add_argument('--json', action='store_true', help='emit JSON')

    cdpst = sub.add_parser('cdp-selftest', help='self-test the CDP detector (no root)')
    cdpst.add_argument('--json', action='store_true', help='emit JSON')

    vtp = sub.add_parser('vtp-watch', help='passive VTP bomb / rogue-server scan (Cisco)')
    vtp.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    vtp.add_argument('--seconds', '-s', type=int, default=30, help='capture window (5-65)')
    vtp.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    vtp.add_argument('--json', action='store_true', help='emit JSON')

    vtpst = sub.add_parser('vtp-selftest', help='self-test the VTP detector (no root)')
    vtpst.add_argument('--json', action='store_true', help='emit JSON')

    eg = sub.add_parser('eigrp-watch', help='passive EIGRP routing-security scan (Cisco)')
    eg.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    eg.add_argument('--seconds', '-s', type=int, default=15, help='capture window (5-40)')
    eg.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    eg.add_argument('--json', action='store_true', help='emit JSON')

    egst = sub.add_parser('eigrp-selftest', help='self-test the EIGRP detectors (no root)')
    egst.add_argument('--json', action='store_true', help='emit JSON')

    fh = sub.add_parser('fhrp-watch',
                        help='passive FHRP hijack scan (HSRP/VRRP/CARP + GLBP AVG & AVF planes)')
    fh.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    fh.add_argument('--seconds', '-s', type=int, default=15, help='capture window (4-40)')
    fh.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    fh.add_argument('--json', action='store_true', help='emit JSON')

    fhst = sub.add_parser('fhrp-selftest', help='self-test the FHRP detectors (no root)')
    fhst.add_argument('--json', action='store_true', help='emit JSON')

    o = sub.add_parser('ospf-watch', help='passive OSPF security scan')
    o.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    o.add_argument('--seconds', '-s', type=int, default=15, help='capture window (5-40)')
    o.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    o.add_argument('--json', action='store_true', help='emit JSON')

    ost = sub.add_parser('ospf-selftest', help='self-test the OSPF detectors (no root)')
    ost.add_argument('--json', action='store_true', help='emit JSON')

    b = sub.add_parser('bgp-watch', help='passive BGP path/security scan')
    b.add_argument('--iface', '-i', default=None, help='interface (default: route)')
    b.add_argument('--seconds', '-s', type=int, default=15, help='capture window (5-40)')
    b.add_argument('--no-learn', action='store_true', help='do not learn/update baseline')
    b.add_argument('--no-enrich', action='store_true', help='skip Team Cymru ASN enrichment (no TCP/43)')
    b.add_argument('--json', action='store_true', help='emit JSON')

    bst = sub.add_parser('bgp-selftest', help='self-test the BGP detectors (no root)')
    bst.add_argument('--json', action='store_true', help='emit JSON')

    args = p.parse_args(argv)
    if args.cmd == 'tls-watch':
        iface = args.iface or _capture_iface()
        r = do_tls_watch(interface=iface, seconds=args.seconds, no_quic=args.no_quic)
        if args.json:
            print(json.dumps(r, indent=2, default=str))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"TLS Watch [{r.get('interface')}] {r.get('seconds')}s: "
                  f"{r['verdict'].upper()}  ({r.get('tls', 0)} TLS, {r.get('quic', 0)} QUIC)")
            for x in r.get('sessions', []):
                print(f"  [{x['proto']}] {x['src']} -> {x['dst']}  {x.get('ja4', '')}")
                if x.get('sni'):
                    print(f"      SNI {x['sni']}  ALPN {x.get('alpn')}")
                for f in x.get('findings', []):
                    print(f"      - {f['severity']} {f['code']}: {f['message']}")
        return 0 if r.get('success') else 1

    if args.cmd == 'tls-selftest':
        r = _tls_selftest()
        if args.json:
            print(json.dumps(r, indent=2, default=str))
        else:
            for sc in r['scenarios']:
                print(f"  [{'PASS' if sc['pass'] else 'FAIL'}] {sc['name']}")
            print(f"  scapy: {'available' if r['scapy']['ran'] else 'absent'}")
            print(f"TLS Watch self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'ldap-watch':
        iface = args.iface or _capture_iface()
        r = do_ldap_watch(interface=iface, seconds=args.seconds)
        if args.json:
            print(json.dumps(r, indent=2, default=str))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            st = r.get('stats', {})
            print(f"LDAP Watch [{r.get('interface')}] {r.get('seconds')}s: "
                  f"{r['verdict'].upper()}  ({st.get('ldap_messages', 0)} msgs, "
                  f"{st.get('binds', 0)} binds, {st.get('searches', 0)} searches, "
                  f"{st.get('cldap', 0)} CLDAP)")
            for f in r.get('findings', []):
                print(f"  - {f['severity']:5} {f['code']}: {f['message']}")
        return 0 if r.get('success') else 1

    if args.cmd == 'ldap-selftest':
        r = _ldap_selftest()
        if args.json:
            print(json.dumps(r, indent=2, default=str))
        else:
            for sc in r['scenarios']:
                print(f"  [{'PASS' if sc['pass'] else 'FAIL'}] {sc['name']}")
            print(f"LDAP Watch self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'igmp-watch':
        r = do_igmp_watch(interface=args.iface, seconds=args.seconds,
                          learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            v = r['verdict'].upper()
            print(f"IGMP Watch [{r['interface']}] {r['seconds']}s: {v}  "
                  f"({r['packets']} msgs, {r['rate_per_s']}/s)")
            if r.get('learned'):
                print("  (baseline learned this run)")
            if r.get('queriers'):
                print(f"  queriers: {', '.join(r['queriers'])}")
            for g in r.get('groups', []):
                flag = ' *NEW*' if g.get('new') else ''
                nm = f" {g['name']}" if g.get('name') else ''
                print(f"  group {g['group']}{nm} [{g['scope']}]"
                      f" <- {', '.join(g['members'])}{flag}")
            for f in r.get('findings', []):
                print(f"  [{f['level']}] {f['text']}")
        return 0 if r.get('success') else 1

    if args.cmd == 'igmp-selftest':
        r = _igmp_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                mark = 'PASS' if s['pass'] else 'FAIL'
                print(f"  [{mark}] {s['name']}: expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"groups={sc.get('groups')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"IGMP self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'ipv6-watch':
        r = do_ipv6_watch(interface=args.iface, seconds=args.seconds,
                          learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"IPv6 First-Hop Watch [{r['interface']}]: {r['verdict'].upper()}  "
                  f"({r['ra_count']} RA @ {r['rate']}/s, {r['dhcp6_count']} DHCPv6)")
            if r.get('learned'):
                print("  (baseline learned this run)")
            for rt in r.get('routers', []):
                tag = '' if rt['baseline'] else ' *ROGUE*'
                dns = f" dns={','.join(rt['rdnss'])}" if rt['rdnss'] else ''
                print(f"  RA router {rt['src']} pref={rt['pref']} "
                      f"life={rt['lifetime']}{dns}{tag}")
            for s in r.get('dhcp6_servers', []):
                tag = '' if s['baseline'] else ' *ROGUE*'
                dns = f" dns={','.join(s['dns'])}" if s['dns'] else ''
                print(f"  DHCPv6 {s['src']} ({'/'.join(s['msgtypes'])}){dns}{tag}")
            for reason in r.get('reasons', []):
                print(f"  - {reason}")
        return 0 if r.get('success') else 1

    if args.cmd == 'ipv6-selftest':
        r = _ipv6_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"prefixes={sc.get('prefixes')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"IPv6 first-hop self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'ndp-watch':
        r = do_ndp_watch(interface=args.iface, seconds=args.seconds,
                         learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"NDP Watch [{r['interface']}]: {r['verdict'].upper()}  "
                  f"({r['na_count']} NA @ {r['rate']}/s, {r['ns_count']} NS, "
                  f"{r['dad_count']} DAD)")
            if r.get('learned'):
                print("  (baseline learned this run)")
            for h in r.get('hosts', []):
                tag = ' *CONFLICT*' if h['conflict'] else ''
                print(f"  {h['ip']} -> {', '.join(h['macs'])}{tag}")
            for reason in r.get('reasons', []):
                print(f"  - {reason}")
        return 0 if r.get('success') else 1

    if args.cmd == 'ndp-selftest':
        r = _ndp_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"tgt={sc.get('tgt')} lladdr={sc.get('lladdr')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"NDP self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'raguard':
        r = do_raguard('harden' if args.harden else 'check')
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            print(f"IPv6 RA Guard: {r['verdict'].upper()}")
            for p in r.get('interfaces', []):
                print(f"  {p['iface']:10} {p['verdict']:14} "
                      f"accept_ra={p['accept_ra']} rtr_pref={p['accept_ra_rtr_pref']} "
                      f"accept_redirects={p['accept_redirects']}")
            for g in r.get('gateways', []):
                print(f"  accepted gateway: {g['gw']} dev {g['dev']}"
                      f"{' (from RA)' if g['from_ra'] else ''}")
            for reason in r.get('reasons', []):
                print(f"  - {reason}")
            ap = r.get('applied')
            if ap:
                print(f"  hardened: set {len(ap['live'])} sysctls, persisted "
                      f"{ap['persisted'] or '(failed)'}")
                for e in ap['errors']:
                    print(f"  ! {e}")
            elif r.get('needs_hardening'):
                print("  run with --harden to close these (accept_redirects=0, "
                      "accept_ra_rtr_pref=0; accept_ra left as-is)")
        return 0 if r.get('success') else 1

    if args.cmd == 'raguard-selftest':
        r = _raguard_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            e = r.get('e2e', {})
            if e.get('ran'):
                print(f"  [{'PASS' if e.get('pass') else 'FAIL'}] live-check: "
                      f"verdict={e.get('verdict')} ifaces={e.get('interfaces')}")
            else:
                print(f"  [skip] live-check: {e.get('reason')}")
            print(f"RA Guard self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'ntp-watch':
        r = do_ntp_watch(interface=args.iface, seconds=args.seconds,
                         learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"NTP Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"({r['server_count']} source(s), {r['packet_count']} pkts @ "
                  f"{r['rate']}/s)")
            if r.get('learned'):
                print("  (baseline learned this run)")
            for s in r.get('servers', []):
                tag = '' if s['baseline'] else ' *ROGUE*'
                off = f" off={s['offset']:+.3f}s" if s['offset'] is not None else ''
                strata = ','.join(str(n) for n in s['strata'])
                extra = (' KoD' if s['kod'] else '') + (' bcast' if s['broadcast'] else '')
                print(f"  {s['src']} stratum={strata} {'/'.join(s['modes'])}"
                      f"{off}{extra}{tag}")
            for reason in r.get('reasons', []):
                print(f"  - {reason}")
        return 0 if r.get('success') else 1

    if args.cmd == 'ntp-selftest':
        r = _ntp_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"stratum={sc.get('stratum')} offset={sc.get('offset')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"NTP self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'icmp-watch':
        r = do_icmp_watch(interface=args.iface, seconds=args.seconds,
                          learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            c = r['counts']
            print(f"ICMP Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"({r['icmp_count']} pkts @ {r['rate']}/s · "
                  f"redir {c['redirect']} echo {c['echo']} irdp {c['irdp']} "
                  f"recon {c['recon']})")
            if r.get('learned'):
                print("  (gateway baseline learned this run)")
            if r.get('gateways'):
                print(f"  trusted gateways: {', '.join(r['gateways'])}")
            for rd in r.get('redirects', []):
                tag = ' *MITM*' if rd['malicious'] else ''
                print(f"  redirect {rd['src']} → {rd['dst']}: {rd['redirected']} "
                      f"via {rd['new_gw']}{tag}")
            for reason in r.get('reasons', []):
                print(f"  - {reason}")
        return 0 if r.get('success') else 1

    if args.cmd == 'icmp-selftest':
        r = _icmp_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"new_gw={sc.get('new_gw')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"ICMP self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'snmp-watch':
        r = do_snmp_watch(interface=args.iface, seconds=args.seconds,
                          learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"SNMP Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"({r['snmp_count']} msgs @ {r['rate']}/s, "
                  f"{'insecure v1/v2c' if r['insecure'] else 'v3-only'})")
            if r.get('learned'):
                print("  (baseline learned this run)")
            for a in r.get('agents', []):
                tag = ' *NEW*' if not a['baseline'] else ''
                sec = ' SECURE' if a['secure'] else ''
                wr = ' WRITE' if a['writes'] else ''
                comm = (' comm=' + ','.join(a['communities'])) if a['communities'] else ''
                print(f"  agent {a['ip']} {'/'.join(a['versions'])}{sec}{wr}{comm}{tag}")
            for c in r.get('communities', []):
                flags = (' DEFAULT' if c['default'] else '') + (' WRITE' if c['writes'] else '')
                print(f"  community \"{c['community']}\" ({'/'.join(c['versions'])}, "
                      f"x{c['count']}){flags}")
            for reason in r.get('reasons', []):
                print(f"  - {reason}")
        return 0 if r.get('success') else 1

    if args.cmd == 'snmp-selftest':
        r = _snmp_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"communities={sc.get('communities')} write={sc.get('write')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"SNMP self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'cert-watch':
        r = do_cert_watch(targets=' '.join(args.targets or []), interface=args.iface,
                         seconds=args.seconds, discover=args.discover,
                         learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"Cert Watch: {r['verdict'].upper()}  "
                  f"({r.get('graded', 0)} graded"
                  f"{', ' + str(r['discovered']) + ' discovered' if r.get('discovered') else ''})")
            for t in r.get('targets', []):
                head = f"  {t['target']}"
                if t.get('sni'):
                    head += f" (SNI {t['sni']})"
                print(f"{head}: {t['verdict'].upper()}")
                if t.get('status') == 'graded':
                    print(f"      subject={t.get('subject')} issuer={t.get('issuer')} "
                          f"{t.get('key')} {t.get('sig_alg')} {t.get('proto')} "
                          f"valid→{t.get('not_after')} ({t.get('days_left')}d)")
                for reason in t.get('reasons', []):
                    print(f"      - {reason}")
            for reason in r.get('reasons', []):
                print(f"  {reason}")
        return 0 if r.get('success') else 1

    if args.cmd == 'cert-selftest':
        r = _cert_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            if r.get('error'):
                print(f"  {r['error']}")
            for s in r.get('scenarios', []):
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            e = r.get('e2e', {})
            if e.get('ran'):
                print(f"  [{'PASS' if e.get('pass') else 'FAIL'}] e2e-local-server: "
                      f"verdict={e.get('verdict')} proto={e.get('proto')}")
            else:
                print(f"  [skip] e2e-local-server: {e.get('reason')}")
            print(f"Cert Watch self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'relay-watch':
        r = do_relay_watch(interface=args.iface, seconds=args.seconds,
                           learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            sg = r.get('signing', {})
            print(f"Relay/Coercion Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"(coercion: {len(r.get('coercion', []))}, relays: {len(r.get('relays', []))}, "
                  f"unsigned servers: {len(sg.get('unsigned', []))})")
            if r.get('learned'):
                print("  (baseline learned this run)")
            for c in r.get('coercion', []):
                print(f"  COERCION {c['technique']} ({c['interface']}): "
                      f"{c['attacker']} -> {c['victim']}")
            for rel in r.get('relays', []):
                print(f"  RELAY challenge {rel['challenge']} from {', '.join(rel['servers'])}")
            for u in sg.get('unsigned', []):
                print(f"  unsigned SMB: {u['ip']}{' (known)' if u['known'] else ''}")
            for rs in r.get('reasons', []):
                print(f"  - {rs}")
        return 0 if r.get('success') else 1

    if args.cmd == 'relay-selftest':
        r = _relay_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy round-trip: "
                      f"{sc.get('scenarios_run')} scenarios")
            else:
                print(f"  [skip] scapy: {sc.get('reason')}")
            print(f"Relay self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'smb-watch':
        r = do_smb_watch(interface=args.iface, seconds=args.seconds,
                         learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            smb = r.get('smb', {})
            nr = r.get('nameres', {})
            krb = r.get('kerberos', {})
            print(f"SMB Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"(SMBv1 servers: {len(smb.get('v1_servers', []))}, "
                  f"SMB2/3 pkts: {smb.get('v2_count', 0)}; "
                  f"name-res responders: {len(nr.get('responders', []))}; "
                  f"Kerberos msgs: {sum((krb.get('counts') or {}).values())})")
            if r.get('learned'):
                print("  (baseline learned this run)")
            for s in smb.get('v1_servers', []):
                print(f"  SMBv1 {s['ip']} [{s['mode']}]{' known' if s['known'] else ''}")
            for rp in nr.get('responders', []):
                hv = ' WPAD!' if rp['highvalue'] else ''
                print(f"  responder {rp['ip']} ({'/'.join(rp['protos'])}){hv} "
                      f"-> {', '.join(rp['names'][:4]) or '(unnamed)'}")
            q = nr.get('queries', {})
            print(f"  queries: LLMNR {q.get('llmnr', 0)}, NBT-NS {q.get('nbtns', 0)}, "
                  f"mDNS {q.get('mdns', 0)}")
            if krb.get('kdcs'):
                kdcs = ', '.join(k['ip'] + (' known' if k['known'] else ' NEW')
                                 for k in krb['kdcs'])
                print(f"  KDCs: {kdcs}"
                      + (f"  realms: {', '.join(krb['realms'])}" if krb.get('realms')
                         else ''))
            for f in krb.get('findings', []):
                et = '/'.join(f.get('etypes') or []) or '-'
                who = f.get('sname') or f.get('principal') or '?'
                print(f"  KRB {f['type']}: {who} [{et}]")
            for rs in r.get('reasons', []):
                print(f"  - {rs}")
        return 0 if r.get('success') else 1

    if args.cmd == 'smb-selftest':
        r = _smb_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy round-trip: "
                      f"{sc.get('scenarios_run')} scenarios")
            else:
                print(f"  [skip] scapy: {sc.get('reason')}")
            print(f"SMB self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'isis-watch':
        r = do_isis_watch(interface=args.iface, seconds=args.seconds,
                          learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"IS-IS Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"({r['packet_count']} PDUs, {r['router_count']} router(s), "
                  f"{r['prefix_count']} prefix(es))")
            if r.get('learned'):
                print("  (baseline learned this run)")
            for rt in r.get('routers', []):
                tag = '' if rt['baseline'] else ' *NEW*'
                name = f"{rt['hostname']} " if rt['hostname'] else ''
                print(f"  router {name}{rt['system_id']} area={','.join(rt['areas']) or '?'}"
                      f" L{'/'.join(str(x) for x in rt['levels']) or '?'}"
                      f" auth={rt['auth']}{tag}")
            for p in r.get('prefixes', []):
                mark = '' if p['status'] in ('known', 'learned') else f" [{p['status']}]"
                print(f"    {p['pfx']} <- {p['origin_name']} (metric {p['metric']}){mark}")
            for rs in r.get('reasons', []):
                print(f"  - {rs}")
        return 0 if r.get('success') else 1

    if args.cmd == 'isis-selftest':
        r = _isis_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"sysid={sc.get('sysid')} prefix={sc.get('prefix')} "
                      f"verdict={sc.get('verdict')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"IS-IS self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'stp-watch':
        r = do_stp_watch(interface=args.iface, seconds=args.seconds,
                         learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"STP Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"({r['packet_count']} BPDUs, {r['bridge_count']} bridge(s), "
                  f"{r['instance_count']} instance(s); {r['tcn_count']} TCN)")
            if r.get('learned'):
                print("  (baseline learned this run)")
            for inst in r.get('instances', []):
                mark = '' if inst['status'] in ('known', 'learned') else f" [{inst['status']}]"
                print(f"  {inst['proto'].upper()} vlan/inst {inst['vlan']}: root "
                      f"{inst['root_prio']}.{inst['root_mac']} via {inst['advertised_by']}{mark}")
            for b in r.get('bridges', []):
                tag = '' if b['baseline'] else ' *NEW*'
                print(f"    bridge {b['mac']} ({b['proto']}){tag}")
            for rs in r.get('reasons', []):
                print(f"  - {rs}")
        return 0 if r.get('success') else 1

    if args.cmd == 'stp-selftest':
        r = _stp_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"root_prio={sc.get('root_prio')} verdict={sc.get('verdict')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"STP self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'dtp-watch':
        r = do_dtp_watch(interface=args.iface, seconds=args.seconds,
                         learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"DTP Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"({r['packet_count']} frame(s), {r['speaker_count']} speaker(s))")
            if r.get('learned'):
                print("  (baseline learned this run)")
            for sp in r.get('speakers', []):
                tag = '' if sp['baseline'] else ' *NEW*'
                print(f"  {sp['src']} status={sp['status']}"
                      f"{' TRUNK-FORMING' if sp['forming'] else ''}{tag}")
            for rs in r.get('reasons', []):
                print(f"  - {rs}")
        return 0 if r.get('success') else 1

    if args.cmd == 'dtp-selftest':
        r = _dtp_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"src={sc.get('src')} status={sc.get('status')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"DTP self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'cdp-watch':
        r = do_cdp_watch(interface=args.iface, seconds=args.seconds,
                         learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"CDP Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"({r['packet_count']} frame(s), {r['speaker_count']} speaker(s))")
            if r.get('learned'):
                print("  (baseline learned this run)")
            for sp in r.get('speakers', []):
                tag = '' if sp['baseline'] else ' *NEW*'
                leak = []
                if sp.get('sw_version'):
                    leak.append(sp['sw_version'][:40])
                if sp.get('native_vlan') is not None:
                    leak.append(f"nativeVLAN={sp['native_vlan']}")
                if sp.get('mgmt_addr'):
                    leak.append(f"mgmt={sp['mgmt_addr']}")
                print(f"  {sp['src']} '{sp.get('device_id') or '?'}' "
                      f"({sp.get('platform') or '?'}){tag}"
                      + (('  [' + '; '.join(leak) + ']') if leak else ''))
            for rs in r.get('reasons', []):
                print(f"  - {rs}")
        return 0 if r.get('success') else 1

    if args.cmd == 'cdp-selftest':
        r = _cdp_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"device_id={sc.get('device_id')} platform={sc.get('platform')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"CDP self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'vtp-watch':
        r = do_vtp_watch(interface=args.iface, seconds=args.seconds,
                         learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"VTP Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"({r['packet_count']} frame(s), {r['domain_count']} domain(s))")
            if r.get('learned'):
                print("  (baseline learned this run)")
            for dm in r.get('domains', []):
                tag = '' if dm['baseline'] else ' *NEW*'
                base = ('' if dm.get('baseline_revision') is None
                        else f" (baseline rev {dm['baseline_revision']})")
                print(f"  domain '{dm['name']}' rev={dm['revision']}{base} "
                      f"updater={','.join(dm['updaters']) or '?'}{tag}")
            for rs in r.get('reasons', []):
                print(f"  - {rs}")
        return 0 if r.get('success') else 1

    if args.cmd == 'vtp-selftest':
        r = _vtp_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"domain={sc.get('domain')} revision={sc.get('revision')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"VTP self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'eigrp-watch':
        r = do_eigrp_watch(interface=args.iface, seconds=args.seconds,
                           learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"EIGRP Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"({r['packet_count']} pkts, {r['router_count']} router(s), "
                  f"{r['prefix_count']} prefix(es))")
            if r.get('learned'):
                print("  (baseline learned this run)")
            for rt in r.get('routers', []):
                tag = '' if rt['baseline'] else ' *NEW*'
                print(f"  router {rt['src']} AS={','.join(str(a) for a in rt['as']) or '?'}"
                      f" auth={'yes' if rt['auth'] else 'NO'}{tag}")
            for p in r.get('prefixes', []):
                mark = '' if p['status'] in ('known', 'learned') else f" [{p['status']}]"
                print(f"    {p['prefix']} via {p['nexthop']} ({p['kind']}){mark}")
            for rs in r.get('reasons', []):
                print(f"  - {rs}")
        return 0 if r.get('success') else 1

    if args.cmd == 'eigrp-selftest':
        r = _eigrp_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"src={sc.get('src')} AS={sc.get('asn')} prefix={sc.get('prefix')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"EIGRP self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'fhrp-watch':
        r = do_fhrp_watch(interface=args.iface, seconds=args.seconds,
                          learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"FHRP Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"({r['packet_count']} pkts, {r['group_count']} group(s))")
            if r.get('learned'):
                print("  (baseline learned this run)")
            for g in r.get('groups', []):
                print(f"  {g['proto'].upper()} group {g['group']} "
                      f"(gw {', '.join(g['vips']) or '?'}, "
                      f"auth {g['authtype'] or 'none'}{' WEAK' if g['auth_weak'] else ''})")
                for sp in g['speakers']:
                    tag = '' if sp['baseline'] else ' *NEW*'
                    print(f"    {sp['src']} prio={sp['priority']}"
                          f"{' ' + ','.join(sp['opcodes']) if sp['opcodes'] else ''}{tag}")
            for fwd in r.get('glbp_forwarders', []):
                print(f"  GLBP forwarder {fwd['group']}/{fwd['forwarder']}")
                for o in fwd['owners']:
                    tag = '' if o['baseline'] else ' *NEW*'
                    print(f"    {o['src']} vMAC {o['vmac']} "
                          f"vf_prio={o['vf_priority']} weight={o['weight']} "
                          f"{'/'.join(o['states']) or '-'}{tag}")
            for rs in r.get('reasons', []):
                print(f"  - {rs}")
        return 0 if r.get('success') else 1

    if args.cmd == 'fhrp-selftest':
        r = _fhrp_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"protos={sc.get('protos')} hsrp_prio={sc.get('hsrp_prio')} "
                      f"vrrp_prio={sc.get('vrrp_prio')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"FHRP self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'ospf-watch':
        r = do_ospf_watch(interface=args.iface, seconds=args.seconds,
                          learn=not args.no_learn)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"OSPF Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"({r['packets']} pkts, {r['hellos']} hello, {r['ls_updates']} LSU)")
            if r.get('note'):
                print(f"  note: {r['note']}")
            if r.get('learned'):
                print("  (baseline learned this run)")
            if r.get('auth_types'):
                print(f"  auth types seen: {r['auth_types']}")
            for rt in r.get('routers', []):
                print(f"  router {rt['router_id']}{' *NEW*' if rt.get('new') else ''}"
                      f" <- {', '.join(rt['sources'])}")
            for a in r.get('advisories', []):
                print(f"  [advisory:{a['severity']}] {a['title']}"
                      f"{' (' + ', '.join(a['refs']) + ')' if a.get('refs') else ''}")
            for f in r.get('findings', []):
                print(f"  [{f['level']}] {f['text']}")
        return 0 if r.get('success') else 1

    if args.cmd == 'ospf-selftest':
        r = _ospf_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"parsed={sc.get('parsed_packets')} auth={sc.get('auth')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"OSPF self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    if args.cmd == 'bgp-watch':
        r = do_bgp_watch(interface=args.iface, seconds=args.seconds,
                         learn=not args.no_learn, enrich=not args.no_enrich)
        if args.json:
            print(json.dumps(r, indent=2))
        elif not r.get('success'):
            print(f"error: {r.get('error')}")
        else:
            print(f"BGP Watch [{r['interface']}] {r['seconds']}s: {r['verdict'].upper()}  "
                  f"({r['messages']} msgs, {r['updates']} UPDATE, {r['prefix_total']} prefixes)")
            if r.get('note'):
                print(f"  note: {r['note']}")
            if r.get('enrich_note'):
                print(f"  {r['enrich_note']}")
            if r.get('learned'):
                print("  (baseline learned this run)")
            if r.get('peers'):
                names = r.get('asn_names') or {}
                ps = ', '.join('AS' + str(a) + (' (' + names[str(a)] + ')' if names.get(str(a)) else '') for a in r['peers'])
                print(f"  peers: {ps} · MD5: {r['md5']}")
            for a in r.get('advisories', []):
                print(f"  [advisory:{a['severity']}] {a['title']}"
                      f"{' (' + ', '.join(a['refs']) + ')' if a.get('refs') else ''}")
            for f in r.get('findings', []):
                print(f"  [{f['level']}] {f['text']}")
        return 0 if r.get('success') else 1

    if args.cmd == 'bgp-selftest':
        r = _bgp_selftest()
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            for s in r['scenarios']:
                print(f"  [{'PASS' if s['pass'] else 'FAIL'}] {s['name']}: "
                      f"expect={s['expect']} got={s['got']}")
            sc = r['scapy']
            if sc.get('ran'):
                print(f"  [{'PASS' if sc.get('pass') else 'FAIL'}] scapy-e2e: "
                      f"parsed={sc.get('parsed_messages')}")
            else:
                print(f"  [skip] scapy-e2e: {sc.get('reason')}")
            print(f"BGP self-test: {'OK' if r['success'] else 'FAILED'}")
        return 0 if r['success'] else 1

    p.print_help()
    return 2


if __name__ == '__main__':
    import sys
    sys.exit(_cli())
