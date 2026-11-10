#!/usr/bin/env python3
"""Real-time host presence for the Network tab.

The Discovered Hosts table used to take its Status from the ``hosts.status``
column. Nothing ever recorded a *failed* probe there, so a host that was seen
once stayed "alive" indefinitely and every row read Online.

This module answers one question, cheaply and continuously: *is this host on
the LAN right now?* It ARP-probes the hosts Ragnar already knows about over a
single raw socket and also listens to every ARP frame on the segment, so a
device that powers on is noticed from its own gratuitous ARP.

Why ARP: a host cannot reach anything on its subnet without answering ARP, so
it is the one probe a firewalled device still replies to. Probes are sent
unicast to the last known MAC because an access point buffers unicast frames
for a sleeping Wi-Fi client, while broadcasts are routinely lost.

A host that misses a reply is not written off on ARP alone: while it is in
doubt it is also pinged (ICMP echo) and ARPed by broadcast, and a reply on any
channel keeps it Online. Hosts already Offline are re-checked more slowly;
their return is normally caught at once from the ARP they broadcast on joining.

Cost: no subprocesses and no disk writes. One 42-byte frame per host per
interval, and the rate drops when no dashboard is open. That is what keeps it
usable on a Pi Zero 2 W.

Presence is deliberately kept in memory and separate from the database's
slow alive/degraded bookkeeping, which decides what the orchestrator scans
and should not flap on a ten-second timescale.
"""

import fcntl
import ipaddress
import logging
import select
import socket
import struct
import threading
import time

logger = logging.getLogger(__name__)

ETH_P_ARP = 0x0806
_SO_BINDTODEVICE = 25
_SOL_RAW = 255
_ICMP_FILTER = 1
_ICMP_ECHO_REPLY = 0
_SIOCGIFADDR = 0x8915
_SIOCGIFNETMASK = 0x891B
_BROADCAST = b'\xff' * 6
_ZERO_MAC = b'\x00' * 6

# interval: how often a host that is answering gets re-probed.
# retry:    how often a host that has stopped answering gets re-probed.
# window:   silence (measured from the first unanswered probe) before Offline.
# min_unanswered: probes that must go unanswered first, so one lost frame or
#                 a stalled loop can never flip a host on its own.
# down_interval: how often a host that is already Offline gets re-probed.
FAST_MODE = {'interval': 2.0, 'retry': 1.0, 'window': 6.0, 'min_unanswered': 4,
             'down_interval': 4.0}
IDLE_MODE = {'interval': 10.0, 'retry': 5.0, 'window': 20.0, 'min_unanswered': 3,
             'down_interval': 20.0}
# A host that has been Offline this long is re-probed three times less often.
LONG_GONE_SECONDS = 600.0

MAX_TARGETS = 1024          # per monitor; keeps a /16 from turning into a flood
TARGET_REFRESH_SECONDS = 15.0
IFACE_REFRESH_SECONDS = 20.0
_TICK = 0.5                 # scheduler resolution


def _mac_bytes(mac):
    """'aa:bb:cc:dd:ee:ff' -> 6 bytes, or None when it is not a usable MAC."""
    if not mac or not isinstance(mac, str):
        return None
    try:
        raw = bytes.fromhex(mac.strip().replace(':', '').replace('-', ''))
    except ValueError:
        return None
    if len(raw) != 6 or raw == _ZERO_MAC or raw == _BROADCAST:
        return None
    return raw


def _mac_str(raw):
    return ':'.join('%02x' % b for b in raw)


def build_arp_request(src_mac, src_ip, target_ip, dst_mac=_BROADCAST):
    """Return an Ethernet+ARP who-has frame (42 bytes)."""
    return (dst_mac + src_mac + b'\x08\x06'
            + struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)
            + src_mac + socket.inet_aton(src_ip)
            + _ZERO_MAC + socket.inet_aton(target_ip))


def _checksum(data):
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return ~total & 0xffff


def build_icmp_echo(sequence, ident=0x5247):
    """Return an 8-byte ICMP echo request."""
    header = struct.pack('!BBHHH', 8, 0, 0, ident, sequence & 0xffff)
    return struct.pack('!BBHHH', 8, 0, _checksum(header), ident, sequence & 0xffff)


def parse_arp(frame):
    """Return (opcode, sender_mac_bytes, sender_ip_str) or None."""
    if len(frame) < 42 or frame[12:14] != b'\x08\x06':
        return None
    htype, ptype, hlen, plen, op = struct.unpack('!HHBBH', frame[14:22])
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        return None
    return op, frame[22:28], socket.inet_ntoa(frame[28:32])


class _Iface:
    """One monitored interface: its socket and addressing."""

    __slots__ = ('name', 'sock', 'icmp', 'mac', 'ip', 'network')

    def __init__(self, name, sock, mac, ip, network, icmp=None):
        self.name = name
        self.sock = sock
        self.icmp = icmp            # raw ICMP socket, or None if unavailable
        self.mac = mac
        self.ip = ip
        self.network = network


class _Host:
    __slots__ = ('ip', 'mac', 'iface', 'online', 'last_seen', 'last_probe',
                 'pending_since', 'unanswered', 'changed_at', 'down_since')

    def __init__(self, ip, mac, iface):
        self.ip = ip
        self.mac = mac              # bytes or None
        self.iface = iface          # interface name
        self.online = None          # None = not determined yet
        self.last_seen = 0.0        # monotonic
        self.last_probe = 0.0
        self.pending_since = 0.0    # first unanswered probe since last_seen
        self.unanswered = 0
        self.changed_at = 0.0       # wall clock of the last online/offline flip
        self.down_since = 0.0       # monotonic time it went Offline


def _open_icmp(name):
    """Raw ICMP socket on ``name`` that only receives echo replies, or None."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE, name.encode()[:15])
        # Kernel-side filter: block every ICMP type except echo reply, so
        # unrelated ICMP never wakes the monitor.
        sock.setsockopt(_SOL_RAW, _ICMP_FILTER,
                        struct.pack('I', ~(1 << _ICMP_ECHO_REPLY) & 0xffffffff))
        sock.setblocking(False)
        return sock
    except OSError as exc:
        logger.debug(f"host presence: no ICMP on {name}: {exc}")
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        return None


def open_iface(name):
    """Open a raw ARP socket on ``name``. Returns an _Iface or None."""
    sock = None
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
        sock.bind((name, 0))
        sock.setblocking(False)
        mac = sock.getsockname()[4]
        packed = struct.pack('256s', name.encode()[:15])
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            ip = socket.inet_ntoa(fcntl.ioctl(probe.fileno(), _SIOCGIFADDR, packed)[20:24])
            mask = socket.inet_ntoa(fcntl.ioctl(probe.fileno(), _SIOCGIFNETMASK, packed)[20:24])
        finally:
            probe.close()
        network = ipaddress.IPv4Network(f'{ip}/{mask}', strict=False)
        if network.is_link_local or network.is_loopback or len(mac) != 6:
            sock.close()
            return None
        return _Iface(name, sock, mac, ip, network, _open_icmp(name))
    except (OSError, ValueError) as exc:
        # No such interface, no IPv4 address yet, or not root. All of these
        # mean "cannot monitor here right now", never a crash.
        logger.debug(f"host presence: cannot open {name}: {exc}")
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        return None


class HostPresenceMonitor:
    """Tracks which known hosts are answering on the LAN right now.

    get_ifaces():  -> iterable of interface names to monitor.
    get_targets(): -> {ip: mac_or_empty} of hosts worth tracking.
    is_fast():     -> True while someone is watching (fast cadence).
    on_change(changes): called with [{'ip', 'status', 'mac', 'ts'}] whenever
                   hosts flip, from the monitor thread.
    """

    def __init__(self, get_ifaces, get_targets, is_fast=None, on_change=None,
                 should_exit=None, opener=open_iface, clock=time.monotonic):
        self._get_ifaces = get_ifaces
        self._get_targets = get_targets
        self._is_fast = is_fast or (lambda: True)
        self._on_change = on_change
        self._should_exit = should_exit or (lambda: False)
        self._opener = opener
        self._clock = clock
        self._lock = threading.Lock()
        self._hosts = {}            # ip -> _Host
        self._by_mac = {}           # mac bytes -> ip, for 0.0.0.0-sender probes
        self._ifaces = {}           # name -> _Iface
        self._last_target_refresh = 0.0
        self._last_iface_refresh = 0.0
        self._thread = None
        self._stop = threading.Event()
        self.running = False
        self.fast_mode = FAST_MODE
        self.idle_mode = IDLE_MODE
        self._icmp_seq = 0
        self.stats = {'probes_sent': 0, 'pings_sent': 0, 'frames_seen': 0,
                      'ping_replies': 0, 'transitions': 0}

    # ------------------------------------------------------------ lifecycle
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self.run, name='host-presence', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def run(self):
        self.running = True
        try:
            while not self._stop.is_set() and not self._should_exit():
                try:
                    self.step()
                except Exception as exc:                        # noqa: BLE001
                    logger.error(f"host presence loop error: {exc}")
                    self._stop.wait(5)
        finally:
            self.running = False
            self._close_ifaces()

    # ----------------------------------------------------------- main step
    def step(self, wait=_TICK):
        """One scheduler tick: refresh inputs, send due probes, read replies."""
        now = self._clock()
        if now - self._last_iface_refresh >= IFACE_REFRESH_SECONDS or not self._ifaces:
            self._refresh_ifaces(now)
        if not self._ifaces:
            # Nothing to monitor (no link / not root). Presence then reports
            # nothing and the API falls back to the database status.
            self._stop.wait(max(wait, 2.0))
            return
        if now - self._last_target_refresh >= TARGET_REFRESH_SECONDS:
            self._refresh_targets(now)
        mode = self.fast_mode if self._is_fast() else self.idle_mode
        self._send_due(now, mode)
        self._listen(wait)
        self._evaluate(self._clock(), mode)

    # --------------------------------------------------------------- inputs
    def _refresh_ifaces(self, now):
        self._last_iface_refresh = now
        try:
            wanted = [n for n in dict.fromkeys(self._get_ifaces() or []) if n]
        except Exception as exc:                                # noqa: BLE001
            logger.debug(f"host presence: iface lookup failed: {exc}")
            wanted = []
        fresh = {}
        for name in wanted:
            opened = self._opener(name)
            if opened is None:
                continue
            old = self._ifaces.get(name)
            if old is not None and old.ip == opened.ip and old.network == opened.network:
                # Unchanged: keep the socket that is already receiving.
                self._close_sock(opened)
                fresh[name] = old
            else:
                fresh[name] = opened
        for name, old in self._ifaces.items():
            if fresh.get(name) is not old:
                self._close_sock(old)
        changed = set(fresh) != set(self._ifaces) or any(
            fresh[n] is not self._ifaces.get(n) for n in fresh)
        self._ifaces = fresh
        if changed:
            # Addressing changed (new network, DHCP renumber): what we knew
            # about the old segment says nothing about this one.
            with self._lock:
                self._hosts.clear()
                self._by_mac.clear()
            self._last_target_refresh = 0.0
            if fresh:
                logger.info("Host presence monitoring on " + ', '.join(
                    f"{i.name} ({i.network})" for i in fresh.values()))

    def _iface_for(self, ip):
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return None
        for iface in self._ifaces.values():
            if addr in iface.network:
                return iface
        return None

    def _refresh_targets(self, now):
        self._last_target_refresh = now
        try:
            targets = self._get_targets() or {}
        except Exception as exc:                                # noqa: BLE001
            logger.debug(f"host presence: target lookup failed: {exc}")
            return
        with self._lock:
            keep = set()
            for ip, mac in targets.items():
                if len(keep) >= MAX_TARGETS:
                    break
                iface = self._iface_for(ip)
                if iface is None or ip == iface.ip:
                    continue
                if ip == str(iface.network.network_address) or ip == str(iface.network.broadcast_address):
                    continue
                keep.add(ip)
                raw = _mac_bytes(mac)
                host = self._hosts.get(ip)
                if host is None:
                    host = self._hosts[ip] = _Host(ip, raw, iface.name)
                elif raw and host.mac is None:
                    host.mac = raw
                host.iface = iface.name
                if host.mac:
                    self._by_mac[host.mac] = ip
            for ip in [k for k in self._hosts if k not in keep]:
                gone = self._hosts.pop(ip)
                if gone.mac and self._by_mac.get(gone.mac) == ip:
                    self._by_mac.pop(gone.mac, None)

    # ------------------------------------------------------------- probing
    def _send_due(self, now, mode):
        with self._lock:
            due = []
            for host in self._hosts.values():
                if host.online is False:
                    gap = mode['down_interval']
                    if now - host.down_since >= LONG_GONE_SECONDS:
                        gap *= 3
                elif host.online and host.unanswered == 0:
                    gap = mode['interval']
                else:
                    gap = mode['retry']
                if now - host.last_probe >= gap - 0.05:
                    due.append(host)
        for host in due:
            iface = self._ifaces.get(host.iface)
            if iface is None:
                continue
            frames = []
            if host.mac:
                frames.append(build_arp_request(iface.mac, iface.ip, host.ip, host.mac))
            if not host.mac:
                broadcast = True            # the only way to reach it
            elif host.online is False:
                # Broadcasts cost every station on a Wi-Fi network airtime,
                # so an Offline host gets one on every third probe only. It
                # still finds a device that came back with a different MAC.
                broadcast = host.unanswered % 3 == 0
            else:
                broadcast = host.unanswered > 0 or host.online is None
            if broadcast:
                frames.append(build_arp_request(iface.mac, iface.ip, host.ip))
            sent = False
            for frame in frames:
                try:
                    iface.sock.send(frame)
                    sent = True
                    self.stats['probes_sent'] += 1
                except OSError as exc:
                    # Interface went down or its queue is full: the probe did
                    # not go out, so it must not count against the host.
                    logger.debug(f"host presence: send on {iface.name} failed: {exc}")
                    self._last_iface_refresh = 0.0
                    break
            if not sent:
                continue
            if host.unanswered and host.online is not False and iface.icmp is not None:
                # In doubt: ask on a second channel before giving up on it.
                self._icmp_seq = (self._icmp_seq + 1) & 0xffff
                try:
                    iface.icmp.sendto(build_icmp_echo(self._icmp_seq), (host.ip, 0))
                    self.stats['pings_sent'] += 1
                except OSError:
                    pass            # no route / neighbour unresolved: no evidence
            with self._lock:
                host.last_probe = now
                if host.unanswered == 0:
                    host.pending_since = now
                host.unanswered += 1

    def _listen(self, wait):
        socks = {i.sock: i for i in self._ifaces.values()}
        pingers = {i.icmp: i for i in self._ifaces.values() if i.icmp is not None}
        deadline = self._clock() + wait
        while socks:
            remaining = deadline - self._clock()
            if remaining <= 0:
                break
            try:
                ready, _, _ = select.select(list(socks) + list(pingers), [], [], remaining)
            except (OSError, ValueError):
                self._last_iface_refresh = 0.0
                break
            if not ready:
                break
            for sock in ready:
                if sock in pingers:
                    if not self._drain_icmp(sock):
                        pingers.pop(sock, None)
                    continue
                iface = socks[sock]
                # Drain what is queued so a busy segment cannot back up.
                for _ in range(256):
                    try:
                        frame = sock.recv(128)
                    except BlockingIOError:
                        break
                    except OSError:
                        self._last_iface_refresh = 0.0
                        socks.pop(sock, None)
                        break
                    self._handle_frame(frame, iface)

    def _drain_icmp(self, sock):
        """Read queued echo replies. Returns False if the socket is dead."""
        for _ in range(256):
            try:
                _packet, addr = sock.recvfrom(128)
            except BlockingIOError:
                return True
            except OSError:
                self._last_iface_refresh = 0.0
                return False
            # The kernel filter only lets echo replies through.
            self.stats['ping_replies'] += 1
            self.observe(addr[0])
        return True

    def _handle_frame(self, frame, iface):
        parsed = parse_arp(frame)
        if parsed is None:
            return
        _op, sender_mac, sender_ip = parsed
        if sender_mac == iface.mac:
            return                      # our own probe looping back
        self.stats['frames_seen'] += 1
        self.observe(sender_ip, sender_mac)

    def observe(self, ip, mac=None):
        """Record proof that ``ip`` (or the host owning ``mac``) is present."""
        change = None
        with self._lock:
            if ip == '0.0.0.0' and mac:
                # DHCP clients ARP-probe from 0.0.0.0 while booting.
                ip = self._by_mac.get(mac, ip)
            host = self._hosts.get(ip)
            if host is None:
                return
            host.last_seen = self._clock()
            host.unanswered = 0
            host.pending_since = 0.0
            if mac and mac != host.mac and mac not in (_ZERO_MAC, _BROADCAST):
                if host.mac and self._by_mac.get(host.mac) == ip:
                    self._by_mac.pop(host.mac, None)
                host.mac = mac
                self._by_mac[mac] = ip
            if host.online is not True:
                host.online = True
                host.changed_at = time.time()
                change = self._change(host)
        if change:
            self._emit([change])

    def _evaluate(self, now, mode):
        changes = []
        with self._lock:
            for host in self._hosts.values():
                if host.online is False or host.unanswered < mode['min_unanswered']:
                    continue
                if now - host.pending_since < mode['window']:
                    continue
                host.online = False
                host.down_since = now
                host.changed_at = time.time()
                changes.append(self._change(host))
        if changes:
            self._emit(changes)

    @staticmethod
    def _change(host):
        return {'ip': host.ip,
                'status': 'up' if host.online else 'down',
                'mac': _mac_str(host.mac) if host.mac else '',
                'ts': host.changed_at}

    def _emit(self, changes):
        self.stats['transitions'] += len(changes)
        if not self._on_change:
            return
        try:
            self._on_change(changes)
        except Exception as exc:                                # noqa: BLE001
            logger.debug(f"host presence: change callback failed: {exc}")

    # -------------------------------------------------------------- readout
    def snapshot(self):
        """{ip: {'status': 'up'|'down', 'seen_ago': seconds|None, 'mac', 'since'}}

        Only hosts whose state has been determined are included; a host that
        is missing here simply has no presence verdict yet.
        """
        now = self._clock()
        out = {}
        with self._lock:
            for ip, host in self._hosts.items():
                if host.online is None:
                    continue
                out[ip] = {
                    'status': 'up' if host.online else 'down',
                    'seen_ago': round(now - host.last_seen, 1) if host.last_seen else None,
                    'mac': _mac_str(host.mac) if host.mac else '',
                    'since': host.changed_at,
                }
        return out

    def info(self):
        with self._lock:
            tracked = len(self._hosts)
            online = sum(1 for h in self._hosts.values() if h.online)
            offline = sum(1 for h in self._hosts.values() if h.online is False)
        fast = bool(self._is_fast())
        mode = self.fast_mode if fast else self.idle_mode
        return {
            'running': self.running and bool(self._ifaces),
            'interfaces': [{'name': i.name, 'network': str(i.network)} for i in self._ifaces.values()],
            'mode': 'fast' if fast else 'idle',
            'probe_interval': mode['interval'],
            # Worst case from power-off to Offline: one interval until the
            # next probe, then the silence window, then one scheduler tick.
            'offline_after': mode['interval'] + mode['window'] + _TICK,
            'tracked': tracked, 'online': online, 'offline': offline,
            'stats': dict(self.stats),
        }

    # -------------------------------------------------------------- cleanup
    @staticmethod
    def _close_sock(iface):
        for sock in (iface.sock, getattr(iface, 'icmp', None)):
            try:
                if sock is not None:
                    sock.close()
            except (OSError, AttributeError):
                pass

    def _close_ifaces(self):
        for iface in self._ifaces.values():
            self._close_sock(iface)
        self._ifaces = {}
