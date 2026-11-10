"""Tests for the real-time host presence monitor (Network tab Status column).

The Discovered Hosts table showed every host as Online because the stored
status only ever recorded successful probes. host_presence.py decides
up/down from live ARP instead. These tests drive its state machine with a
fake clock and fake sockets, so no raw socket or root is needed.

Covers:
- a silent host goes Offline inside the 10 second budget, and not earlier
- one lost reply never flips a host
- any ARP frame from a host brings it back Online immediately, including the
  0.0.0.0-sender probe a booting DHCP client sends
- probes that could not be sent are not counted against the host
- a host in doubt is also pinged, healthy and Offline hosts are not, and a
  ping reply alone keeps a host Online
- Offline hosts are re-probed more slowly, and slower still once long gone
- idle cadence is slower and switching back to fast cannot cause false flips
- an interface address change discards verdicts about the old network
- wifi_interfaces caches the expensive Ethernet scan and reads carrier from
  sysfs without spawning a process
"""

import ipaddress
import socket
from unittest.mock import patch

import pytest

import host_presence as hp

ME_MAC = bytes.fromhex('02aabbccdd01')
HOST_MAC = bytes.fromhex('02aabbccdd02')
ME_IP = '192.168.1.195'


class FakeSock:
    def __init__(self):
        self.sent = []
        self.fail = False

    def send(self, frame):
        if self.fail:
            raise OSError(100, 'Network is down')
        self.sent.append(frame)

    def close(self):
        pass


class FakeIcmp:
    def __init__(self):
        self.pinged = []
        self.fail = False

    def sendto(self, packet, addr):
        if self.fail:
            raise OSError(113, 'No route to host')
        self.pinged.append(addr[0])

    def close(self):
        pass


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make(targets, ifaces=None, fast=True):
    clock = Clock()
    socks = {}
    pingers = {}
    addressing = ifaces or {'wlan0': (ME_IP, '192.168.1.0/24')}

    def opener(name):
        if name not in addressing:
            return None
        ip, net = addressing[name]
        socks.setdefault(name, FakeSock())
        pingers.setdefault(name, FakeIcmp())
        return hp._Iface(name, socks[name], ME_MAC, ip, ipaddress.IPv4Network(net),
                         pingers[name])

    state = {'fast': fast}
    changes = []
    mon = hp.HostPresenceMonitor(
        get_ifaces=lambda: list(addressing), get_targets=lambda: dict(targets),
        is_fast=lambda: state['fast'], on_change=changes.extend,
        opener=opener, clock=clock)
    mon._test = (clock, socks, state, changes, addressing)
    mon._pingers = pingers
    return mon


def tick(mon, seconds=0.5, reply_from=()):
    """Advance the fake clock one scheduler tick without touching select()."""
    clock, _socks, state, _changes, _addr = mon._test
    now = clock()
    if now - mon._last_iface_refresh >= hp.IFACE_REFRESH_SECONDS or not mon._ifaces:
        mon._refresh_ifaces(now)
    if now - mon._last_target_refresh >= hp.TARGET_REFRESH_SECONDS:
        mon._refresh_targets(now)
    mode = mon.fast_mode if state['fast'] else mon.idle_mode
    mon._send_due(now, mode)
    for ip, mac in reply_from:
        mon.observe(ip, mac)
    clock.now += seconds
    mon._evaluate(clock(), mode)


def run(mon, seconds, reply_from=()):
    for _ in range(int(seconds / 0.5)):
        tick(mon, reply_from=reply_from)


HOST = '192.168.1.50'
ALIVE = ((HOST, HOST_MAC),)


def status(mon, ip=HOST):
    return mon.snapshot().get(ip, {}).get('status')


# ---------------------------------------------------------------------------
# frames
# ---------------------------------------------------------------------------

def test_arp_request_round_trips_through_the_parser():
    frame = hp.build_arp_request(ME_MAC, ME_IP, HOST, HOST_MAC)
    assert len(frame) == 42 and frame[:6] == HOST_MAC
    assert frame[38:42] == socket.inet_aton(HOST)
    assert hp.parse_arp(frame) == (1, ME_MAC, ME_IP)


@pytest.mark.parametrize('frame', [b'', b'\x00' * 41, b'\xff' * 12 + b'\x08\x00' + b'\x00' * 40])
def test_parser_rejects_frames_that_are_not_ipv4_arp(frame):
    assert hp.parse_arp(frame) is None


@pytest.mark.parametrize('mac', ['', None, 'Unknown', '00:00:00:00:00:00',
                                 'ff:ff:ff:ff:ff:ff', 'zz:zz:zz:zz:zz:zz', 12])
def test_unusable_macs_are_not_probed_unicast(mac):
    assert hp._mac_bytes(mac) is None


# ---------------------------------------------------------------------------
# going offline
# ---------------------------------------------------------------------------

def test_answering_host_is_online_and_stays_online():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    run(mon, 60, reply_from=ALIVE)
    assert status(mon) == 'up'
    assert [c['status'] for c in mon._test[3]] == ['up']


def test_silent_host_goes_offline_within_ten_seconds_but_not_instantly():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    run(mon, 10, reply_from=ALIVE)
    clock = mon._test[0]
    went_silent = clock()
    offline_at = None
    for _ in range(40):
        tick(mon)
        if status(mon) == 'down':
            offline_at = clock() - went_silent
            break
    assert offline_at is not None, "host never went offline"
    assert 5.0 <= offline_at <= 10.0, offline_at


def test_single_lost_reply_does_not_flip_a_host():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    run(mon, 10, reply_from=ALIVE)
    run(mon, 4)                       # 4 seconds of silence
    assert status(mon) == 'up'
    run(mon, 10, reply_from=ALIVE)
    assert status(mon) == 'up'
    assert [c['status'] for c in mon._test[3]] == ['up']


def test_never_seen_host_gets_an_offline_verdict():
    mon = make({HOST: ''})
    assert status(mon) is None        # no verdict before any probing
    run(mon, 10)
    assert status(mon) == 'down'


def test_unsent_probes_do_not_count_against_the_host():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    run(mon, 10, reply_from=ALIVE)
    mon._test[1]['wlan0'].fail = True     # our own link is down
    run(mon, 15)
    assert status(mon) == 'up'


# ---------------------------------------------------------------------------
# second channel (ICMP) and probe budget
# ---------------------------------------------------------------------------

def test_icmp_echo_has_a_valid_checksum():
    packet = hp.build_icmp_echo(7)
    assert len(packet) == 8 and packet[0] == 8
    assert hp._checksum(packet) == 0


def test_healthy_hosts_are_never_pinged():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    run(mon, 60, reply_from=ALIVE)
    assert mon._pingers['wlan0'].pinged == []


def test_host_in_doubt_is_pinged_before_it_is_declared_offline():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    run(mon, 10, reply_from=ALIVE)
    run(mon, 4)
    assert status(mon) == 'up'
    assert mon._pingers['wlan0'].pinged.count(HOST) >= 2


def test_ping_reply_alone_keeps_an_arp_silent_host_online():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    run(mon, 10, reply_from=ALIVE)
    for _ in range(120):              # a minute with no ARP reply at all
        tick(mon)
        if mon._pingers['wlan0'].pinged:
            mon._pingers['wlan0'].pinged.clear()
            mon.observe(HOST)         # what _drain_icmp does with an echo reply
    assert [c['status'] for c in mon._test[3]] == ['up']


def test_offline_hosts_are_not_pinged():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    run(mon, 12)
    assert status(mon) == 'down'
    mon._pingers['wlan0'].pinged.clear()
    run(mon, 30)
    assert mon._pingers['wlan0'].pinged == []


def test_ping_send_failure_is_harmless():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    mon._refresh_ifaces(mon._test[0]())
    mon._pingers['wlan0'].fail = True
    run(mon, 12)
    assert status(mon) == 'down'


def test_offline_hosts_are_probed_more_slowly_and_long_gone_slower_still():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    run(mon, 12)
    assert status(mon) == 'down'
    sock = mon._test[1]['wlan0']

    def unicast_probes(seconds):
        sock.sent.clear()
        run(mon, seconds)
        return sum(1 for frame in sock.sent if frame[:6] == HOST_MAC)

    recent = unicast_probes(60)
    assert 12 <= recent <= 16                 # every 4 s, not every 2 s
    run(mon, hp.LONG_GONE_SECONDS)
    assert unicast_probes(60) <= recent / 2


# ---------------------------------------------------------------------------
# coming back
# ---------------------------------------------------------------------------

def test_any_frame_brings_a_host_back_immediately():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    run(mon, 10)
    assert status(mon) == 'down'
    mon.observe(HOST, HOST_MAC)
    assert status(mon) == 'up'
    assert mon._test[3][-1]['status'] == 'up'


def test_dhcp_probe_from_zero_address_revives_the_known_mac():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    run(mon, 10)
    assert status(mon) == 'down'
    mon.observe('0.0.0.0', HOST_MAC)
    assert status(mon) == 'up'


def test_offline_host_is_probed_by_broadcast_too():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    run(mon, 10)
    sock = mon._test[1]['wlan0']
    sock.sent.clear()
    run(mon, 24)
    unicast = sum(1 for frame in sock.sent if frame[:6] == HOST_MAC)
    broadcast = sum(1 for frame in sock.sent if frame[:6] == b'\xff' * 6)
    assert unicast >= 5
    assert 1 <= broadcast < unicast       # some, but rationed


def test_host_returning_with_a_new_mac_is_learned():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    run(mon, 10)
    new_mac = bytes.fromhex('02aabbccdd99')
    mon.observe(HOST, new_mac)
    assert mon.snapshot()[HOST]['mac'] == '02:aa:bb:cc:dd:99'


def test_frames_from_unknown_hosts_are_ignored():
    mon = make({HOST: ''})
    tick(mon)
    mon.observe('192.168.1.77', HOST_MAC)
    assert '192.168.1.77' not in mon.snapshot()


# ---------------------------------------------------------------------------
# cadence
# ---------------------------------------------------------------------------

def _probes(mon, seconds, reply_from=ALIVE):
    sock = mon._test[1]['wlan0']
    before = len(sock.sent)
    run(mon, seconds, reply_from=reply_from)
    return len(sock.sent) - before


def test_idle_mode_probes_far_less_often():
    fast = make({HOST: '02:aa:bb:cc:dd:02'})
    run(fast, 10, reply_from=ALIVE)
    idle = make({HOST: '02:aa:bb:cc:dd:02'}, fast=False)
    run(idle, 10, reply_from=ALIVE)
    assert _probes(fast, 60) >= 4 * _probes(idle, 60)


def test_switching_from_idle_to_fast_does_not_flip_live_hosts():
    mon = make({HOST: '02:aa:bb:cc:dd:02'}, fast=False)
    run(mon, 30, reply_from=ALIVE)
    run(mon, 8)                       # quiet stretch, normal in idle mode
    mon._test[2]['fast'] = True       # a dashboard opens
    run(mon, 20, reply_from=ALIVE)
    assert [c['status'] for c in mon._test[3]] == ['up']


def test_first_verdict_is_fast_even_in_idle_mode():
    mon = make({HOST: '02:aa:bb:cc:dd:02', '192.168.1.51': ''}, fast=False)
    run(mon, 9)                       # nothing answers, nobody is watching
    assert status(mon) == 'down' and status(mon, '192.168.1.51') == 'down'


def test_idle_mode_is_slower_to_declare_offline():
    mon = make({HOST: '02:aa:bb:cc:dd:02'}, fast=False)
    run(mon, 30, reply_from=ALIVE)
    run(mon, 12)
    assert status(mon) == 'up'
    run(mon, 30)
    assert status(mon) == 'down'


# ---------------------------------------------------------------------------
# scope
# ---------------------------------------------------------------------------

def test_only_hosts_on_a_monitored_subnet_are_tracked():
    mon = make({HOST: '', '10.0.0.5': '', ME_IP: '', '192.168.1.255': '',
                '192.168.1.0': '', 'not-an-ip': ''})
    run(mon, 10)
    assert set(mon.snapshot()) == {HOST}


def test_removed_targets_are_forgotten():
    targets = {HOST: '', '192.168.1.51': ''}
    mon = make(targets)
    run(mon, 10)
    del targets['192.168.1.51']
    mon._get_targets = lambda: dict(targets)
    run(mon, hp.TARGET_REFRESH_SECONDS + 1)
    assert set(mon.snapshot()) == {HOST}


def test_address_change_discards_old_verdicts():
    mon = make({HOST: '02:aa:bb:cc:dd:02'})
    run(mon, 10, reply_from=ALIVE)
    assert status(mon) == 'up'
    # Same subnet numbering, different address: Ragnar joined another network
    # that happens to reuse 192.168.1.0/24. The old "up" must not carry over.
    mon._test[4]['wlan0'] = ('192.168.1.60', '192.168.1.0/24')
    clock = mon._test[0]
    clock.now += hp.IFACE_REFRESH_SECONDS + 1
    tick(mon)
    assert status(mon) is None
    run(mon, 10)
    assert status(mon) == 'down'


def test_no_interface_means_no_verdicts():
    mon = make({HOST: ''}, ifaces={})
    mon._refresh_ifaces(mon._test[0]())
    assert mon.snapshot() == {} and mon.info()['running'] is False


def test_target_cap_bounds_the_probe_load():
    targets = {str(ipaddress.IPv4Address('10.0.0.1') + i): '' for i in range(hp.MAX_TARGETS + 200)}
    mon = make(targets, ifaces={'eth0': ('10.0.255.254', '10.0.0.0/16')})
    tick(mon)
    assert len(mon._hosts) == hp.MAX_TARGETS


def test_change_callback_errors_do_not_stop_monitoring():
    mon = make({HOST: ''})
    mon._on_change = lambda changes: 1 / 0
    run(mon, 10)
    assert status(mon) == 'down'


# ---------------------------------------------------------------------------
# wifi_interfaces: the status-broadcast CPU fix
# ---------------------------------------------------------------------------

def test_ethernet_scan_is_shared_between_back_to_back_callers():
    import wifi_interfaces as wi
    wi._ethernet_cache.clear()
    result = [{'name': 'eth0', 'connected': True}]
    with patch.object(wi, '_gather_ethernet_interfaces_uncached', return_value=result) as scan:
        first = wi.gather_ethernet_interfaces()
        first[0]['connected'] = False         # callers may mutate their copy
        second = wi.gather_ethernet_interfaces()
        second[0]['connected'] = False
        third = wi.gather_ethernet_interfaces()
        assert scan.call_count == 1
        assert second is not third
        assert third == [{'name': 'eth0', 'connected': True}]
    wi._ethernet_cache.clear()


def test_ethernet_scan_cache_expires():
    import wifi_interfaces as wi
    wi._ethernet_cache.clear()
    with patch.object(wi, '_gather_ethernet_interfaces_uncached', return_value=[]) as scan, \
            patch.object(wi.time, 'monotonic', side_effect=[0.0, 0.0, 10.0, 10.0]):
        wi.gather_ethernet_interfaces()
        wi.gather_ethernet_interfaces()
        assert scan.call_count == 2
    wi._ethernet_cache.clear()


def test_carrier_check_reads_sysfs_without_a_subprocess(tmp_path):
    import wifi_interfaces as wi
    real_open = open

    def fake_open(path, *args, **kwargs):
        if path == '/sys/class/net/eth9/carrier':
            carrier = tmp_path / 'carrier'
            carrier.write_text('1\n')
            return real_open(carrier, *args, **kwargs)
        return real_open(path, *args, **kwargs)

    with patch('builtins.open', side_effect=fake_open), \
            patch.object(wi.subprocess, 'run') as spawned:
        assert wi._check_ethernet_carrier('eth9') is True
        spawned.assert_not_called()
    assert wi._check_ethernet_carrier('no-such-iface0') is False
