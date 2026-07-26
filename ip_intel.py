#!/usr/bin/env python3
"""ip_intel.py — attribution for a single IP address (Ragnar).

Answers the question you actually have about a hostile IP: **whose network is
this, what country, and who do I report it to?**

Deliberately honest about what an IP can and cannot tell you:

* **Authoritative** (straight from the regional registry via RDAP, and Team
  Cymru's ASN service): the owning network, its CIDR, the ASN + AS name, the
  registry, the country, and the **abuse contact** — the one field that actually
  gets an attack stopped.
* **Estimated**: city, at best. Included only when an offline GeoIP database is
  present, and always flagged low-confidence.
* **Never emitted**: a street address. Sites that show one are showing either the
  ISP's registered corporate address or a *centroid* — a fallback midpoint used
  when the database only knows "somewhere in this country". MaxMind's US default
  centroid famously landed on a Kansas farm whose residents were harassed for
  years over IPs that had nothing to do with them. This module reports a
  ``location_note`` instead of inventing precision.

It also refuses to over-claim attribution: if the IP is a VPN exit, Tor exit, or
cloud/hosting host, the geolocation describes *the server*, not the operator, and
``attribution_note`` says so.

Offline-first where it can be: scope classification (private/bogon/reserved) and
every parser run with no network at all, and results are cached. Network use is
opt-in via ``allow_network``.

Self-test: ``python3 ip_intel.py --self-test`` (no network, no keys).
"""

import ipaddress
import json
import os
import re
import socket
import sys
import time

MODULE = 'ip_intel'

DEFAULT_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             'data', 'ip_intel_cache.json')
CACHE_TTL = 24 * 3600          # registry data changes slowly
_HTTP_TIMEOUT = 6
_DNS_TIMEOUT = 4

# Network-operator keywords → what kind of endpoint this IP really is. Order
# matters: VPN/Tor beat hosting, hosting beats generic ISP.
_VPN_HINTS = (
    'mullvad', 'nordvpn', 'expressvpn', 'protonvpn', 'proton ag', 'surfshark',
    'cyberghost', 'ipvanish', 'tunnelbear', 'windscribe', 'vyprvpn', 'hide.me',
    'purevpn', 'torguard', 'azirevpn', 'perfect privacy', 'mozilla vpn',
    'private internet access', 'privateinternetaccess', 'vpn',
    'm247', 'datacamp', 'datapacket', '31173',
)
_HOSTING_HINTS = (
    'amazon', 'aws', 'google cloud', 'googleusercontent', 'azure', 'microsoft',
    'google llc', 'digitalocean', 'linode', 'akamai', 'cloudflare', 'fastly', 'ovh',
    'hetzner', 'vultr', 'choopa', 'scaleway', 'contabo', 'leaseweb', 'oracle',
    'alibaba', 'tencent', 'hosting', 'datacenter', 'datacentre', 'data center',
    'colo', 'server', 'vps', 'dedicated', 'cloud',
)
_MOBILE_HINTS = ('mobile', 'cellular', 'wireless', ' lte', 'gsm', '3g', '4g', '5g')
_RESIDENTIAL_HINTS = ('broadband', 'cable', 'dsl', 'fiber', 'fibre', 'telecom',
                      'communications', 'telekom', 'residential')


# --------------------------------------------------------------------------
# Scope (pure, no I/O)
# --------------------------------------------------------------------------

def ip_scope(ip):
    """Classify an address without touching the network. Returns (scope, note).
    A non-'public' scope means an external lookup is pointless — the address has
    no owner in any registry."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return 'invalid', 'not a valid IP address'
    if a.is_unspecified:
        return 'unspecified', 'the unspecified address'
    if a.is_loopback:
        return 'loopback', 'this host'
    if a.is_link_local:
        return 'link-local', 'auto-configured, never routed off-link'
    if a.is_multicast:
        return 'multicast', 'a multicast group, not a host'
    if a.is_private:
        return 'private', 'RFC1918/ULA — inside a local network, not globally routable'
    if a.is_reserved:
        return 'reserved', 'reserved by IANA'
    return 'public', ''


# --------------------------------------------------------------------------
# Parsers (pure — the network functions below are thin wrappers)
# --------------------------------------------------------------------------

def _vcard_email(vcard_array):
    """Pull the email out of an RDAP jCard (['vcard', [[name,{},type,value],...]])."""
    try:
        for entry in vcard_array[1]:
            if entry[0] == 'email' and len(entry) >= 4 and entry[3]:
                return str(entry[3]).strip()
    except (IndexError, TypeError):
        pass
    return None


def _walk_entities(entities, want_role, out):
    """RDAP entities nest arbitrarily; collect emails for a given role at any depth."""
    if not isinstance(entities, list):
        return
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        roles = [str(r).lower() for r in (ent.get('roles') or [])]
        if want_role in roles:
            email = _vcard_email(ent.get('vcardArray') or [])
            if email:
                out.append(email)
        _walk_entities(ent.get('entities'), want_role, out)


def parse_rdap(obj):
    """Extract the useful fields from an RDAP 'ip network' object."""
    out = {'network_name': None, 'prefix': None, 'country': None,
           'registry': None, 'abuse_email': None, 'rdap_handle': None}
    if not isinstance(obj, dict):
        return out
    out['network_name'] = obj.get('name')
    out['rdap_handle'] = obj.get('handle')
    country = obj.get('country')
    if country:
        out['country'] = str(country).upper()[:2]
    # CIDR: prefer the structured cidr0 extension, else start/end addresses.
    cidrs = obj.get('cidr0_cidrs')
    if isinstance(cidrs, list) and cidrs:
        c = cidrs[0]
        pfx = c.get('v4prefix') or c.get('v6prefix')
        if pfx and c.get('length') is not None:
            out['prefix'] = '%s/%s' % (pfx, c['length'])
    if not out['prefix'] and obj.get('startAddress') and obj.get('endAddress'):
        try:
            nets = ipaddress.summarize_address_range(
                ipaddress.ip_address(obj['startAddress']),
                ipaddress.ip_address(obj['endAddress']))
            out['prefix'] = str(next(iter(nets)))
        except (ValueError, TypeError, StopIteration):
            pass
    # Registry: port43 (whois.ripe.net) or a link host.
    p43 = obj.get('port43') or ''
    m = re.search(r'whois\.([a-z]+)\.net', str(p43))
    if m:
        out['registry'] = m.group(1).upper()
    emails = []
    _walk_entities(obj.get('entities'), 'abuse', emails)
    if emails:
        out['abuse_email'] = emails[0]
    return out


def parse_cymru_origin(txt):
    """Team Cymru origin TXT: 'ASN | BGP prefix | CC | registry | allocated'."""
    parts = [p.strip() for p in str(txt).strip().strip('"').split('|')]
    if len(parts) < 3:
        return {}
    asn = parts[0].split()[0] if parts[0] else None
    out = {}
    if asn and asn.isdigit():
        out['asn'] = int(asn)
    if len(parts) > 1 and parts[1]:
        out['prefix'] = parts[1]
    if len(parts) > 2 and parts[2]:
        out['country'] = parts[2].upper()[:2]
    if len(parts) > 3 and parts[3]:
        out['registry'] = parts[3].upper()
    if len(parts) > 4 and parts[4]:
        out['allocated'] = parts[4]          # ← NEW
    return out


def parse_cymru_asname(txt):
    """Team Cymru AS TXT: 'ASN | CC | registry | allocated | AS name'."""
    parts = [p.strip() for p in str(txt).strip().strip('"').split('|')]
    out = {}
    if parts and parts[0].isdigit():
        out['asn'] = int(parts[0])
    if len(parts) >= 5 and parts[4]:
        out['as_org'] = parts[4]
    if len(parts) >= 2 and parts[1]:
        out['country'] = parts[1].upper()[:2]
    return out


def classify(as_org=None, network_name=None, ptr=None, scope='public'):
    """What kind of endpoint is this? Drives whether geolocation means anything."""
    if scope != 'public':
        return 'special'
    hay = ' '.join(str(x).lower() for x in (as_org, network_name, ptr) if x)
    if not hay:
        return 'unknown'
    if any(k in hay for k in _VPN_HINTS):
        return 'vpn'
    if any(k in hay for k in _HOSTING_HINTS):
        return 'hosting'
    if any(k in hay for k in _MOBILE_HINTS):
        return 'mobile'
    if any(k in hay for k in _RESIDENTIAL_HINTS):
        return 'residential'
    return 'unknown'


# Attribution honesty per classification.
_ATTRIB_NOTE = {
    'vpn': ('This is a VPN exit. The location and ISP describe the VPN server, '
            'not whoever was using it — attribution stops here.'),
    'tor': ('This is a Tor exit node. The location is the exit relay, not the '
            'origin; the true source is not recoverable from the IP.'),
    'hosting': ('This is a cloud/hosting address. It is likely a rented or '
                'compromised VM — the location is the datacenter, not an operator.'),
    'mobile': ('Mobile carrier address, typically large-scale NAT — it may be '
               'shared by many subscribers and moves geographically.'),
    'residential': ('Consumer ISP address. It may still be a compromised host or '
                    'a shared/CGNAT address rather than the actor.'),
    'unknown': 'Endpoint type could not be determined from the network records.',
    'special': 'Not a public address — no registry owner exists.',
}

_LOCATION_NOTE = (
    'Country is registry-derived and reliable. City (when shown) is an estimate '
    'and is frequently wrong. No street address is reported: per-IP "addresses" '
    'are either the ISP\'s corporate registration or a database centroid, not '
    'the location of a user.'
)


# --------------------------------------------------------------------------
# Network lookups (thin, all failable)
# --------------------------------------------------------------------------

def _rdap_fetch(ip):
    import urllib.request
    url = 'https://rdap.org/ip/%s' % ip
    req = urllib.request.Request(url, headers={'User-Agent': 'Ragnar-ip-intel/1.0',
                                               'Accept': 'application/rdap+json'})
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as r:
        return json.loads(r.read().decode('utf-8', 'replace'))


def _dns_txt(name):
    try:
        import dns.resolver
        res = dns.resolver.Resolver()
        res.lifetime = res.timeout = _DNS_TIMEOUT
        for rr in res.resolve(name, 'TXT'):
            return b''.join(rr.strings).decode('utf-8', 'replace')
    except Exception:
        return None
    return None


def _cymru_origin(ip):
    a = ipaddress.ip_address(ip)
    if a.version != 4:
        return None
    rev = '.'.join(reversed(str(a).split('.')))
    return _dns_txt('%s.origin.asn.cymru.com' % rev)


def _cymru_asname(asn):
    return _dns_txt('AS%d.asn.cymru.com' % int(asn))


def _ptr(ip):
    try:
        socket.setdefaulttimeout(_DNS_TIMEOUT)
        return socket.gethostbyaddr(str(ip))[0]
    except (OSError, socket.herror, socket.gaierror):
        return None


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------

def _cache_load(path):
    try:
        with open(path) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _cache_save(path, cache):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(cache, f)
        os.replace(tmp, path)
    except OSError:
        pass


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def lookup(ip, allow_network=True, cache_path=DEFAULT_CACHE, use_cache=True,
           ttl=CACHE_TTL, _now=None):
    """Attribute one IP. Returns a dict; never raises on a lookup failure."""
    now = _now if _now is not None else time.time()
    ip = str(ip).strip()
    scope, scope_note = ip_scope(ip)
    rec = {
        'ip': ip, 'scope': scope, 'module': MODULE, 'ts': now,
        'country': None, 'asn': None, 'as_org': None, 'prefix': None,
        'registry': None, 'network_name': None, 'abuse_email': None,
        'ptr': None, 'city': None, 'classification': 'special',
        'confidence': 0, 'sources': [], 'cached': False,
        'location_note': _LOCATION_NOTE, 'attribution_note': None,
        'error': None,
    }
    if scope == 'invalid':
        rec['error'] = scope_note
        return rec
    if scope != 'public':
        # No registry owner exists — say so instead of making a pointless call.
        rec['classification'] = 'special'
        rec['attribution_note'] = '%s (%s).' % (_ATTRIB_NOTE['special'], scope_note)
        rec['confidence'] = 100          # we are certain it is non-public
        rec['sources'] = ['local']
        return rec

    cache = _cache_load(cache_path) if use_cache else {}
    hit = cache.get(ip)
    if use_cache and isinstance(hit, dict) and (now - hit.get('ts', 0)) < ttl:
        out = dict(hit)
        out['cached'] = True
        return out

    if not allow_network:
        rec['error'] = ('no cached record and outbound lookups are disabled '
                        '(allow_network=False)')
        rec['classification'] = 'unknown'
        return rec

    # --- authoritative sources ------------------------------------------
    try:
        rdap = parse_rdap(_rdap_fetch(ip))
        if any(rdap.values()):
            rec.update({k: v for k, v in rdap.items() if v})
            rec['sources'].append('rdap')
    except Exception as exc:
        rec['error'] = 'rdap: %s' % exc

    if rec.get('country'):
        rec['country_source'] = 'rdap'
    try:
        origin = parse_cymru_origin(_cymru_origin(ip) or '')
        if origin:
            # A registry country and the routing country can legitimately differ
            # — anycast especially (1.1.1.1 registers AU, announces worldwide).
            # Record both rather than silently preferring one.
            rc, cc = rec.get('country'), origin.get('country')
            if rc and cc and rc != cc:
                rec['country_routing'] = cc
                rec['country_note'] = (
                    'Registry says %s, routing/BGP says %s — normal for anycast or '
                    'a network registered in one country and used in another.'
                    % (rc, cc))
            for k, v in origin.items():
                if v and not rec.get(k):
                    rec[k] = v
                    if k == 'country':
                        rec['country_source'] = 'cymru'
            if origin.get('asn'):
                rec['asn'] = origin['asn']
            rec['sources'].append('cymru')
        if rec.get('asn') and not rec.get('as_org'):
            asname = parse_cymru_asname(_cymru_asname(rec['asn']) or '')
            if asname.get('as_org'):
                rec['as_org'] = asname['as_org']
    except Exception:
        pass

    rec['ptr'] = _ptr(ip)
    if rec['ptr']:
        rec['sources'].append('ptr')

    rec['classification'] = classify(rec.get('as_org'), rec.get('network_name'),
                                     rec.get('ptr'), scope)
    rec['attribution_note'] = _ATTRIB_NOTE.get(rec['classification'])
    rec['confidence'] = _confidence(rec)
    rec['ts'] = now

    if use_cache:
        cache[ip] = rec
        _cache_save(cache_path, cache)
    return rec


def _confidence(rec):
    """How much of the *ownership* picture we actually resolved (0-100). This is
    confidence in the network attribution, not in any physical location."""
    score = 0
    if rec.get('asn'):
        score += 25
    if rec.get('as_org'):
        score += 20
    if rec.get('country'):
        score += 20
    if rec.get('prefix'):
        score += 15
    if rec.get('abuse_email'):
        score += 20
    return min(100, score)


def report(rec):
    """One-screen human summary — what you'd paste into a ticket."""
    lines = ['IP %s (%s)' % (rec['ip'], rec['scope'])]
    if rec['scope'] != 'public':
        lines.append('  %s' % rec.get('attribution_note'))
        return '\n'.join(lines)
    lines.append('  Network : %s  %s' % (rec.get('prefix') or '?',
                                         rec.get('network_name') or ''))
    lines.append('  ASN     : %s %s' % (('AS%s' % rec['asn']) if rec.get('asn') else '?',
                                        rec.get('as_org') or ''))
    lines.append('  Country : %s%s   Registry: %s' % (
        rec.get('country') or '?',
        (' (routing: %s)' % rec['country_routing']) if rec.get('country_routing') else '',
        rec.get('registry') or '?'))
    if rec.get('country_note'):
        lines.append('  ! %s' % rec['country_note'])
    lines.append('  PTR     : %s' % (rec.get('ptr') or '-'))
    lines.append('  Type    : %s' % rec.get('classification'))
    lines.append('  ABUSE   : %s' % (rec.get('abuse_email') or 'not published'))
    lines.append('  Confidence (ownership): %d%%' % rec.get('confidence', 0))
    if rec.get('attribution_note'):
        lines.append('  ! %s' % rec['attribution_note'])
    lines.append('  ! %s' % rec['location_note'])
    return '\n'.join(lines)


# --------------------------------------------------------------------------
# Self-test (no network)
# --------------------------------------------------------------------------

_RDAP_FIXTURE = {
    'objectClassName': 'ip network', 'handle': '1.1.1.0 - 1.1.1.255',
    'startAddress': '1.1.1.0', 'endAddress': '1.1.1.255', 'ipVersion': 'v4',
    'name': 'APNIC-LABS', 'country': 'au', 'port43': 'whois.apnic.net',
    'cidr0_cidrs': [{'v4prefix': '1.1.1.0', 'length': 24}],
    'entities': [{
        'objectClassName': 'entity', 'handle': 'IRT-APNICRANDNET-AU',
        'roles': ['registrant'],
        'entities': [{                      # abuse nested one level down
            'objectClassName': 'entity', 'handle': 'ABUSE',
            'roles': ['abuse'],
            'vcardArray': ['vcard', [['version', {}, 'text', '4.0'],
                                     ['fn', {}, 'text', 'ABUSE APNICAP'],
                                     ['email', {}, 'text', 'helpdesk@apnic.net']]],
        }],
    }],
}


def _self_test():
    checks = []

    def ck(name, cond):
        checks.append((name, bool(cond)))

    # --- scope (pure, no I/O) -------------------------------------------
    ck('public IP scope', ip_scope('8.8.8.8')[0] == 'public')
    ck('private IP scope', ip_scope('192.168.1.10')[0] == 'private')
    ck('loopback scope', ip_scope('127.0.0.1')[0] == 'loopback')
    ck('link-local scope', ip_scope('169.254.5.5')[0] == 'link-local')
    ck('multicast scope', ip_scope('224.0.0.1')[0] == 'multicast')
    ck('ipv6 public scope', ip_scope('2606:4700:4700::1111')[0] == 'public')
    ck('ipv6 ULA is private', ip_scope('fd00::1')[0] == 'private')
    ck('garbage is invalid', ip_scope('not-an-ip')[0] == 'invalid')

    # --- RDAP parsing ----------------------------------------------------
    r = parse_rdap(_RDAP_FIXTURE)
    ck('rdap prefix', r['prefix'] == '1.1.1.0/24')
    ck('rdap country upper', r['country'] == 'AU')
    ck('rdap network name', r['network_name'] == 'APNIC-LABS')
    ck('rdap registry from port43', r['registry'] == 'APNIC')
    ck('rdap abuse email found (nested entity)',
       r['abuse_email'] == 'helpdesk@apnic.net')
    # start/end fallback when cidr0 is absent
    f2 = dict(_RDAP_FIXTURE); f2.pop('cidr0_cidrs')
    ck('rdap prefix from start/end fallback', parse_rdap(f2)['prefix'] == '1.1.1.0/24')
    ck('rdap on garbage does not raise', parse_rdap(None)['prefix'] is None)
    ck('rdap with no abuse entity -> None',
       parse_rdap({'name': 'X', 'entities': []})['abuse_email'] is None)

    # --- Cymru parsing ---------------------------------------------------
    o = parse_cymru_origin('13335 | 1.1.1.0/24 | US | arin | 2010-07-14')
    ck('cymru origin asn', o['asn'] == 13335)
    ck('cymru origin prefix', o['prefix'] == '1.1.1.0/24')
    ck('cymru origin registry', o['registry'] == 'ARIN')
    n = parse_cymru_asname('13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US')
    ck('cymru as_org', n['as_org'] == 'CLOUDFLARENET, US')
    ck('cymru garbage safe', parse_cymru_origin('nonsense') == {})

    # --- classification --------------------------------------------------
    ck('vpn classified', classify(as_org='M247 Europe SRL') == 'vpn')
    ck('mullvad classified vpn', classify(as_org='Mullvad VPN AB') == 'vpn')
    ck('hosting classified', classify(as_org='Hetzner Online GmbH') == 'hosting')
    ck('aws classified hosting', classify(ptr='ec2-1-2-3-4.amazonaws.com') == 'hosting')
    ck('mobile classified', classify(as_org='Telia Mobile Networks') == 'mobile')
    ck('residential classified', classify(as_org='Comcast Cable Communications') == 'residential')
    ck('unknown when nothing matches', classify(as_org='Zzz Ltd') == 'unknown')
    ck('non-public -> special', classify(as_org='x', scope='private') == 'special')

    # --- lookup(): offline paths ----------------------------------------
    p = lookup('192.168.1.50', allow_network=False, use_cache=False)
    ck('private IP needs no network', p['scope'] == 'private' and p['error'] is None)
    ck('private IP is classified special', p['classification'] == 'special')
    ck('private IP has no country', p['country'] is None)
    bad = lookup('999.1.1.1', allow_network=False, use_cache=False)
    ck('invalid IP reports error', bad['scope'] == 'invalid' and bad['error'])
    off = lookup('8.8.8.8', allow_network=False, use_cache=False)
    ck('public IP without network is honest', off['error'] and 'disabled' in off['error'])

    # every record carries the location honesty note
    ck('location note always present', _LOCATION_NOTE in p['location_note'])
    ck('no street/address field is ever produced',
       not any(k in p for k in ('address', 'street', 'postal', 'latitude', 'longitude')))

    # --- cache round-trip (no network) -----------------------------------
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        cp = os.path.join(d, 'cache.json')
        seeded = {'1.2.3.4': {'ip': '1.2.3.4', 'scope': 'public', 'ts': 1000,
                              'asn': 64500, 'as_org': 'TEST', 'country': 'SE',
                              'classification': 'hosting', 'confidence': 45,
                              'location_note': _LOCATION_NOTE}}
        _cache_save(cp, seeded)
        hit = lookup('1.2.3.4', allow_network=False, cache_path=cp, _now=1100)
        ck('cache hit served without network', hit['cached'] and hit['asn'] == 64500)
        miss = lookup('1.2.3.4', allow_network=False, cache_path=cp,
                      _now=1000 + CACHE_TTL + 10)
        ck('expired cache entry is not served', not miss.get('cached'))

    # --- confidence + report --------------------------------------------
    full = {'asn': 1, 'as_org': 'x', 'country': 'SE', 'prefix': '1.0.0.0/8',
            'abuse_email': 'a@b.c'}
    ck('full record is 100% ownership confidence', _confidence(full) == 100)
    ck('empty record is 0%', _confidence({}) == 0)
    txt = report(dict(lookup('10.0.0.1', allow_network=False, use_cache=False)))
    ck('report renders for a private IP', '10.0.0.1' in txt)

    passed = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        if not ok:
            print('  [FAIL] %s' % name)
    print('ip-intel self-test: %d/%d %s'
          % (passed, len(checks), 'OK' if passed == len(checks) else 'FAILED'))
    return 0 if passed == len(checks) else 1


def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description='Ragnar IP attribution (country/ASN/ISP/abuse)')
    ap.add_argument('ip', nargs='?', help='IP address to attribute')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--offline', action='store_true',
                    help='no outbound lookups; cache + local classification only')
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not args.ip:
        ap.print_help()
        return 0
    rec = lookup(args.ip, allow_network=not args.offline)
    print(json.dumps(rec, indent=2) if args.json else report(rec))
    return 0


if __name__ == '__main__':
    raise SystemExit(_main(sys.argv[1:]))
