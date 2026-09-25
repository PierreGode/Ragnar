"""Shared, thread-safe IGMP state: memberships, queriers, host baseline, and the
group census the data-plane sampler and SNMP poller cross-reference.

Detectors read this read-only; the pipeline mutates it (via apply) only *after*
detectors run, so e.g. querier-change logic compares against the prior querier.
"""

import ipaddress
import threading
import time

LINK_LOCAL = ipaddress.ip_network('224.0.0.0/24')

# Benign well-known groups that are always present and are not the data-plane
# multicast a flood-with-no-members check is about.
BENIGN_GROUPS = {
    '224.0.0.251': 'mDNS', '224.0.0.252': 'LLMNR',
    '239.255.255.250': 'SSDP', '239.255.255.253': 'SLP',
}


def is_multicast(ip):
    try:
        return 224 <= int(ip.split('.')[0]) <= 239
    except (ValueError, AttributeError, IndexError):
        return False


def is_link_local(ip):
    try:
        return ipaddress.ip_address(ip) in LINK_LOCAL
    except ValueError:
        return False


class SharedState:
    def __init__(self):
        self.lock = threading.RLock()
        # group -> mac -> {'version', 'sources': set, 'last_seen'}
        self.memberships = {}
        # ip -> {'mac', 'first_seen', 'last_seen', 'count'}
        self.queriers = {}
        self.hosts = set()               # baseline of seen host MACs
        self.groups = set()              # every group observed
        self._v3_seen = False

    # -- reads (callers hold nothing; short critical sections) ---------------
    def elected_querier(self):
        """Lowest querier IP wins the IS-IS... the IGMP querier election."""
        with self.lock:
            if not self.queriers:
                return None
            return min(self.queriers, key=lambda ip: _ip_key(ip))

    def v3_seen(self):
        with self.lock:
            return self._v3_seen

    def data_groups(self):
        """Groups with at least one member, excluding link-local control and the
        benign always-on service-discovery groups."""
        with self.lock:
            return {g for g, m in self.memberships.items()
                    if m and not is_link_local(g) and g not in BENIGN_GROUPS}

    def group_members(self, group):
        with self.lock:
            return set((self.memberships.get(group) or {}).keys())

    def snapshot(self):
        with self.lock:
            return {
                'groups': sorted(self.groups),
                'data_groups': sorted(self.data_groups()),
                'queriers': sorted(self.queriers, key=_ip_key),
                'elected_querier': self.elected_querier(),
                'host_count': len(self.hosts),
                'membership_count': sum(len(m) for m in self.memberships.values()),
            }

    # -- mutation (pipeline, AFTER detectors) --------------------------------
    def apply(self, msg, now=None):
        if now is None:
            now = time.time()
        with self.lock:
            mac = msg.get('src_mac')
            if mac:
                self.hosts.add(mac)
            if msg.get('version') == 3:
                self._v3_seen = True
            if msg['kind'] == 'query' and msg.get('ip_src') not in (None, '0.0.0.0'):
                q = self.queriers.setdefault(msg['ip_src'],
                                             {'mac': mac, 'first_seen': now,
                                              'last_seen': now, 'count': 0})
                q['last_seen'] = now
                q['count'] += 1
            for rec in _membership_records(msg):
                g, kind, sources = rec
                if not g:
                    continue
                self.groups.add(g)
                if kind == 'report':
                    gm = self.memberships.setdefault(g, {})
                    e = gm.setdefault(mac, {'version': msg.get('version'),
                                            'sources': set(), 'last_seen': now})
                    e['version'] = msg.get('version')
                    e['sources'].update(sources or [])
                    e['last_seen'] = now
                elif kind == 'leave':
                    gm = self.memberships.get(g)
                    if gm:
                        gm.pop(mac, None)
                        if not gm:
                            self.memberships.pop(g, None)


def _ip_key(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 1 << 40


def _membership_records(msg):
    """Yield (group, kind, sources) for the join/leave content of a message —
    one per v3 group record, or the single v1/v2 group."""
    if msg.get('records'):
        for r in msg['records']:
            yield r['group'], r['kind'], r.get('sources') or []
    elif msg['kind'] in ('report', 'leave') and msg.get('group'):
        yield msg['group'], msg['kind'], msg.get('sources') or []
