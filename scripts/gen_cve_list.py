#!/usr/bin/env python3
"""Regenerate docs/CVE.md — the unified CVE index for Ragnar's detectors.

Scans the detector code for CVE IDs, attributes each one to the detector that
names it (by file, or by enclosing function / constant inside
network_diagnostics.py) and classifies it:

  detected   — at least one detector identifies it from traffic on the wire
  context    — named for patch guidance / related context only (posture
               advisories, reference tables, shared-shape context)
  active     — an ACTIVE check in the BLE pentest action (it transmits)
  ui         — named only in a web card's prose

Run from the repo root after porting a module:  python3 scripts/gen_cve_list.py
"""
import collections
import os
import re
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'docs', 'CVE.md')
CVE_RE = re.compile(r'CVE-(\d{4})-(\d{4,})')

# Whole-file owners.
FILE_OWNERS = {
    'tls_watch.py': 'TLS Watch',
    'ssh_watch.py': 'SSH Watch',
    'telnet_watch.py': 'Telnet Watch',
    'telnet_watch_selftest.py': 'Telnet Watch',
    'rpcwatch.py': 'RPC / NetLogon Watch',
    'bfdwatch.py': 'BFD Watch',
    'ptpwatch.py': 'PTP Watch',
    'ldap_watch.py': 'LDAP Watch',
    'lacpwatch.py': 'LACP Watch',
    'ftpwatch.py': 'FTP Watch',
    'smtpwatch.py': 'SMTP Watch',
    'sr_mplswatch.py': 'SR-MPLS Watch',
    'python/snmp_cve.py': 'SNMP Watch',
    'python/dellguard.py': 'Dell Guard',
    'python/dellguard_conformance.py': 'Dell Guard',
    'actions/ble_pentest.py': 'BLE Pentest (active)',
}
FILE_PREFIX_OWNERS = {'python/dns_doctor_passive/': 'DNS Watch'}
# Files that only mention CVEs already owned elsewhere (labels, help text).
MENTION_ONLY = {'webapp_modern.py', 'watchtower.py', 'web/scripts/ragnar_modern.js',
                'web/index_modern.html'}

# network_diagnostics.py: enclosing def / constant -> detector (first prefix match).
ND_PREFIXES = [
    ('_cli', None),
    ('_BGP_ADVISORIES', 'BGP Path Watch'), ('_OSPF_ADVISORIES', 'OSPF Watch'),
    ('_arista', 'Arista Guard'), ('_ARISTA', 'Arista Guard'), ('do_arista', 'Arista Guard'),
    ('_aruba', 'Aruba Guard'), ('_ARUBA', 'Aruba Guard'),
    ('_arp', 'ARP Watch'),
    ('_cdp', 'CDP Watch'), ('_CDP', 'CDP Watch'),
    ('_cisco', 'Cisco Guard'), ('_CISCO', 'Cisco Guard'), ('_ikev2', 'Cisco Guard'),
    ('_dhcpv6', 'Cisco Guard'), ('_ipv6_rh0', 'Cisco Guard'), ('_vxlan', 'Cisco Guard'),
    ('_VXLAN', 'Cisco Guard'), ('_GUARD_IP6', 'Cisco Guard'),
    ('_juniper', 'Juniper Guard'), ('_JUNIPER', 'Juniper Guard'),
    ('_comware', 'Comware Guard'), ('do_comware', 'Comware Guard'),
    ('_mikrotik', 'MikroTik Guard'), ('_MIKROTIK', 'MikroTik Guard'),
    ('_dell', 'Dell Guard'),
    ('_IPSEC', 'IPsec / IKE Watch'), ('_ipsec', 'IPsec / IKE Watch'),
    ('_krb', 'SMB / Kerberos Watch'), ('_KRB', 'SMB / Kerberos Watch'),
    ('_smb', 'SMB / Kerberos Watch'), ('_SMB', 'SMB / Kerberos Watch'),
    ('do_smb', 'SMB / Kerberos Watch'),
    ('_ND_OPT', 'ICMP Watch'), ('_icmp', 'ICMP Watch'), ('_decode_icmp6', 'ICMP Watch'),
    ('do_icmp', 'ICMP Watch'), ('_raguard', 'ICMP Watch'),
    ('_NTP', 'NTP Watch'), ('_ntp', 'NTP Watch'), ('_parse_ntp', 'NTP Watch'),
    ('_parse_autokey', 'NTP Watch'),
    ('_EIGRP', 'EIGRP Watch'), ('_eigrp', 'EIGRP Watch'),
    ('_isis', 'IS-IS Watch'),
    ('_igmp', 'IGMP / MLD Watch'), ('_parse_igmp', 'IGMP / MLD Watch'),
    ('_decode_mld', 'IGMP / MLD Watch'),
    ('_dhcp', 'DHCP Guardian'), ('do_dhcp', 'DHCP Guardian'),
    ('_dns_dnssec', 'DNS Doctor (active)'), ('_dns_selftest', 'DNS Doctor (active)'),
    ('do_dns_doctor', 'DNS Doctor (active)'), ('do_dns_watch', 'DNS Watch'),
    ('_snmp', 'SNMP Watch'),
    ('_FTP', 'FTP Watch'), ('_ftp', 'FTP Watch'), ('do_ftp', 'FTP Watch'),
    ('_SMTP', 'SMTP Watch'), ('_smtp', 'SMTP Watch'), ('do_smtp', 'SMTP Watch'),
    ('_RELAY', 'Relay / Coercion Watch'), ('_relay', 'Relay / Coercion Watch'),
    ('_parse_relay', 'Relay / Coercion Watch'), ('do_relay', 'Relay / Coercion Watch'),
    ('_ND_DNSSL', 'ICMP Watch'), ('_ISIS', 'IS-IS Watch'), ('_CFM', 'Cisco Guard'),
    ('_CAPWAP', 'Cisco Guard'), ('_COMWARE', 'Comware Guard'), ('_DNS_PASSIVE', 'DNS Watch'),
    ('_TCPDUMP_HEX_RE', 'Trailing-data / Etherleak'),
    ('_stp_selftest', 'Trailing-data / Etherleak'), ('_apply_trailing', 'Trailing-data / Etherleak'),
]
# CVEs named inside a detector's finding text for comparison only — e.g. the
# OpenSSH scp bug named as the "twin" of the netkit rcp CVE Telnet Watch detects.
CONTEXT_CVES = {'CVE-2019-6111'}
# Per-CVE owner overrides where a shared helper names another vendor's CVE.
CVE_OWNER_OVERRIDE = {'CVE-2021-0254': 'Juniper Guard'}
# Owners (or owner+CVE) whose mention is context/reference, not a detection.
CONTEXT_OWNERS = {'BGP Path Watch:advisory', 'OSPF Watch:advisory', 'SR-MPLS Watch:reference',
                  'ARP Watch'}

# Curated attack / bug names. Only well-established names go here; anything not
# listed shows the detector alone rather than a guessed label.
NAMES = {
    'CVE-2002-20001': 'D(HE)at', 'CVE-2022-40735': 'D(HE)at', 'CVE-2024-41996': 'D(HE)at',
    'CVE-2003-0001': 'Etherleak',
    'CVE-1999-0113': 'rlogin -froot auth bypass', 'CVE-1999-0185': 'r-services ftp-data trust bounce',
    'CVE-2007-0882': 'Solaris in.telnetd -f auth bypass', 'CVE-2011-4862': 'telnetd encrypt_keyid overflow',
    'CVE-2019-6111': 'OpenSSH scp file overwrite', 'CVE-2019-7282': 'netkit rcp dot-name',
    'CVE-2019-7283': 'netkit rcp unrequested file', 'CVE-2022-39028': 'inetutils telnetd EC/EL crash', 'CVE-2005-4436': 'EIGRP K-value / Goodbye reset',
    'CVE-2005-4437': 'EIGRP missing authentication', 'CVE-2006-5051': 'OpenSSH signal-handler race',
    'CVE-2008-0960': 'SNMPv3 USM HMAC truncation', 'CVE-2013-2566': 'RC4 biases',
    'CVE-2013-5211': 'NTP monlist amplification', 'CVE-2014-0160': 'Heartbleed',
    'CVE-2014-9295': 'NTP Autokey crypto_recv overflow', 'CVE-2015-2808': 'Bar Mitzvah (RC4)',
    'CVE-2018-6789': 'Exim AUTH base64 overflow',
    'CVE-2019-10149': 'Exim ${...} expansion RCE',
    'CVE-2019-15846': 'Exim SNI/cert-DN RCE',
    'CVE-2019-16928': 'Exim overlong EHLO overflow',
    'CVE-2015-3306': 'ProFTPD mod_copy pre-auth copy',
    'CVE-2019-12815': 'ProFTPD mod_copy Limit bypass',
    'CVE-2023-51713': 'ProFTPD make_ftp_cmd OOB read',
    'CVE-2015-4000': 'Logjam', 'CVE-2015-5434': 'MPLS VRF hopping (Comware)',
    'CVE-2015-8087': 'MPLS VRF hopping (Huawei)', 'CVE-2015-7704': "NTP Kiss-o'-Death spoof",
    'CVE-2015-7705': "NTP Kiss-o'-Death spoof", 'CVE-2015-7871': 'NTP crypto-NAK auth bypass',
    'CVE-2016-2183': 'SWEET32', 'CVE-2016-8610': 'SSL Death Alert',
    'CVE-2017-0144': 'EternalBlue', 'CVE-2017-0781': 'BlueBorne', 'CVE-2017-0782': 'BlueBorne',
    'CVE-2017-20149': 'Chimay-Red', 'CVE-2018-0732': 'Oversized DH prime (client DoS)',
    'CVE-2018-1111': 'DynoRoot', 'CVE-2018-14847': 'Winbox arbitrary file read',
    'CVE-2019-5608': 'Fragmented IGMP/MLD membership', 'CVE-2020-0796': 'SMBGhost',
    'CVE-2020-1472': 'Zerologon', 'CVE-2020-3110': 'CDPwn', 'CVE-2020-3111': 'CDPwn',
    'CVE-2020-3118': 'CDPwn', 'CVE-2020-3119': 'CDPwn', 'CVE-2020-3120': 'CDPwn',
    'CVE-2020-8616': 'NXNSAttack', 'CVE-2020-11868': 'NTP zero-origin sync block',
    'CVE-2020-12243': 'OpenLDAP nested-filter DoS', 'CVE-2020-16898': 'Bad Neighbor',
    'CVE-2020-16899': 'RA DNSSL DoS', 'CVE-2020-25583': 'RA DNSSL DoS (rtsold)',
    'CVE-2020-25705': 'SAD DNS', 'CVE-2021-1587': 'NX-OS NGOAM DoS',
    'CVE-2021-0254': 'Junos overlayd VXLAN RCE', 'CVE-2021-1675': 'PrintNightmare',
    'CVE-2021-34527': 'PrintNightmare', 'CVE-2021-1678': 'Print spooler RPC relay (IRemoteWinSpool)',
    'CVE-2021-36942': 'PetitPotam', 'CVE-2021-31166': 'HTTP.sys Accept-Encoding',
    'CVE-2022-21907': 'HTTP.sys Accept-Encoding', 'CVE-2021-25220': 'MaginotDNS',
    'CVE-2022-26809': 'RPC runtime bind_ack underflow', 'CVE-2022-26925': 'PetitPotam-class LSA coercion',
    'CVE-2022-33647': 'Kerberos RC4-MD4 downgrade', 'CVE-2022-33679': 'Kerberos RC4-MD4 downgrade',
    'CVE-2023-48795': 'Terrapin', 'CVE-2023-50387': 'KeyTrap', 'CVE-2023-50868': 'NSEC3 CPU exhaustion',
    'CVE-2024-3596': 'BlastRADIUS', 'CVE-2024-3661': 'TunnelVision', 'CVE-2024-6387': 'regreSSHion',
    'CVE-2024-30388': 'LACP malformed-PDU flap', 'CVE-2024-33655': 'DNSBomb',
    'CVE-2024-43532': 'RemoteRegistry NTLM relay', 'CVE-2024-49112': 'LDAPNightmare',
    'CVE-2024-49113': 'LDAPNightmare', 'CVE-2025-20315': 'CAPWAP malformed header',
    'CVE-2025-20700': 'Airoha RACE', 'CVE-2025-20701': 'Airoha RACE', 'CVE-2025-20702': 'Airoha RACE',
    'CVE-2025-22474': 'Dell OS10 SSRF', 'CVE-2025-33073': 'SMB reflective relay',
    'CVE-2025-36911': 'WhisperPair', 'CVE-2025-38741': 'Duplicate SSH host key',
    'CVE-2025-40778': 'Unsolicited-RR cache poisoning', 'CVE-2025-40780': 'Weak port/ID PRNG',
    'CVE-2025-68615': 'snmptrapd overflow', 'CVE-2026-19033': 'Unsigned multi-message XFR',
    'CVE-2026-20074': 'IS-IS multi-instance exposure', 'CVE-2026-20222': 'EIGRP update flood',
    'CVE-2026-24061': 'inetutils telnetd auth bypass', 'CVE-2026-81642': 'DNS compression-pointer loop',
}


def tracked_files():
    out = subprocess.run(['git', 'ls-files', '*.py', '*.js', '*.html'], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout.split()
    # Never scan this script: its NAMES table would count as a detector.
    return [p for p in out if p != 'scripts/gen_cve_list.py']


def nd_owner(name):
    for pre, det in ND_PREFIXES:
        if name.startswith(pre):
            return det
    return 'network_diagnostics'


DEF_RE = re.compile(r'(?:def |class )(\w+)|(_[A-Z][A-Z0-9_]+)\s*=')


def next_owners(lines):
    """For each line index, the name of the next top-level def/constant."""
    out, nxt = [None] * len(lines), None
    for i in range(len(lines) - 1, -1, -1):
        m = DEF_RE.match(lines[i])
        if m:
            nxt = m.group(1) or m.group(2)
        out[i] = nxt
    return out


def module_docstring_end(lines):
    """Index of the line closing the module docstring (0 if there is none)."""
    for i, l in enumerate(lines[:5]):
        for q in ('"""', "'''"):
            if l.lstrip().startswith(q):
                if l.count(q) >= 2:
                    return i + 1
                for j in range(i + 1, len(lines)):
                    if q in lines[j]:
                        return j + 1
    return 0


def sr_reference_span(lines):
    """(start, end) line indexes of the CVE_REFERENCES dict literal."""
    for i, l in enumerate(lines):
        if l.startswith('CVE_REFERENCES'):
            for j in range(i + 1, len(lines)):
                if lines[j].startswith('}'):
                    return i, j
    return -1, -1


def html_card(lines, i):
    for j in range(i, -1, -1):
        m = re.search(r'<h3[^>]*>([^<]+)', lines[j])
        if m:
            return m.group(1).strip()
    return 'Web UI'


def collect():
    owners = collections.defaultdict(set)     # cve -> {(detector, status)}
    mentions = collections.defaultdict(list)  # cve -> [line text]
    for path in tracked_files():
        full = os.path.join(ROOT, path)
        try:
            lines = open(full, encoding='utf-8', errors='replace').read().split('\n')
        except OSError:
            continue
        if not any(CVE_RE.search(l) for l in lines):
            continue
        sr_a, sr_b = sr_reference_span(lines) if path == 'sr_mplswatch.py' else (-1, -1)
        owner = None
        nxt = next_owners(lines) if path == 'network_diagnostics.py' else []
        doc_end = module_docstring_end(lines)
        for i, l in enumerate(lines):
            if path == 'network_diagnostics.py':
                m = DEF_RE.match(l)
                if m:
                    owner = m.group(1) or m.group(2)
                # A top-level comment is the banner of the NEXT definition.
                cur = nxt[i] if l.startswith('#') else owner
            for m in CVE_RE.finditer(l):
                cve = m.group(0)
                mentions[cve].append(l)
                if path in MENTION_ONLY:
                    if path == 'web/index_modern.html':
                        owners[cve].add((html_card(lines, i), 'ui'))
                    continue
                if path == 'network_diagnostics.py':
                    det = nd_owner(cur or '')
                    if det is None:
                        continue
                    status = 'context' if det in CONTEXT_OWNERS else 'detected'
                    if cur in ('_BGP_ADVISORIES', '_OSPF_ADVISORIES'):
                        status = 'context'
                elif path in FILE_OWNERS:
                    det = FILE_OWNERS[path]
                    status = 'active' if path.startswith('actions/') else 'detected'
                    # Module-docstring scope notes and reference tables name
                    # CVEs without detecting them.
                    if sr_a <= i <= sr_b or i < doc_end:
                        status = 'context' if status == 'detected' else status
                else:
                    det = next((d for p, d in FILE_PREFIX_OWNERS.items()
                                if path.startswith(p)), path)
                    status = 'detected'
                det = CVE_OWNER_OVERRIDE.get(cve, det)
                if cve in CONTEXT_CVES and status == 'detected':
                    status = 'context'
                owners[cve].add((det, status))
    return owners, mentions


def classify(pairs):
    code = [(d, s) for d, s in pairs if s != 'ui']
    if any(s == 'detected' for _, s in code):
        return 'detected', sorted({d for d, s in code if s == 'detected'}), \
            sorted({d for d, s in code if s == 'context'} - {d for d, s in code if s == 'detected'})
    if any(s == 'active' for _, s in code):
        return 'active', sorted({d for d, _ in code}), []
    if code:
        return 'context', sorted({d for d, _ in code}), []
    return 'ui', sorted({d for d, _ in pairs}), []


def main():
    owners, mentions = collect()
    rows = []
    for cve, pairs in owners.items():
        status, dets, ctx = classify(pairs)
        y, n = CVE_RE.match(cve).groups()
        rows.append((int(y), int(n), cve, status, dets, ctx, NAMES.get(cve, '')))
    rows.sort()
    counts = collections.Counter(r[3] for r in rows)
    by_year = collections.Counter(r[0] for r in rows)
    by_det = collections.defaultdict(list)
    for r in rows:
        for d in r[4]:
            by_det[d].append(r[2])
        for d in r[5]:
            by_det[d].append(r[2])

    status_label = {'detected': 'detected', 'context': 'context only',
                    'active': 'active check', 'ui': 'card text only'}
    o = []
    w = o.append
    w('# CVE Index')
    w('')
    w('Every CVE ID named anywhere in Ragnar\'s detector code, in one list: which detector')
    w('names it and whether it is **detected** from traffic on the wire or named as '
      '**context** only.')
    w('The research behind these detections is credited in [CREDITS.md](CREDITS.md); how each')
    w('detector works is in [nettools.md](nettools.md).')
    w('')
    w('> **Generated file.** Regenerate after porting a module:')
    w('> `python3 scripts/gen_cve_list.py`. Do not edit by hand.')
    w('')
    w('## Summary')
    w('')
    w(f'- **{len(rows)}** distinct CVE IDs')
    w(f'- **{counts["detected"]}** detected: a passive detector identifies the CVE\'s '
      'signature, exposure or exploit shape from traffic already on the wire')
    w(f'- **{counts["context"]}** context only: posture advisories and reference tables for '
      'byte-level parser bugs the text-based watchers cannot reconstruct, plus related CVEs '
      'attached to a shared attack shape (named for patch guidance, not identified per-CVE)')
    if counts['active']:
        w(f'- **{counts["active"]}** active check: probed by the BLE Pentest action, which '
          'transmits (not part of the passive suite)')
    if counts['ui']:
        w(f'- **{counts["ui"]}** card text only: named in a detector card\'s description as '
          'related context, not detected')
    w(f'- Range **{rows[0][2]}** → **{max(rows, key=lambda r: (r[0], r[1]))[2]}**')
    w('')
    w('| Year | CVEs |')
    w('|---|---|')
    for y in sorted(by_year):
        w(f'| {y} | {by_year[y]} |')
    w('')
    w('## By detector')
    w('')
    w('| Detector | CVEs |')
    w('|---|---|')
    for d in sorted(by_det, key=str.lower):
        w(f'| {d} | {len(by_det[d])} |')
    w('')
    w('## All CVEs')
    w('')
    w('*Name* is the well-known attack or bug name where one exists. *Status* is the strongest '
      'evidence class across all detectors.')
    w('')
    w('| CVE | Name | Status | Detector(s) | Also named as context by |')
    w('|---|---|---|---|---|')
    for y, n, cve, status, dets, ctx, name in rows:
        link = f'[{cve}](https://nvd.nist.gov/vuln/detail/{cve})'
        w(f'| {link} | {name} | {status_label[status]} | {", ".join(dets) or "—"} | '
          f'{", ".join(ctx) or "—"} |')
    w('')
    with open(OUT, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(o))
    print(f'wrote {OUT}: {len(rows)} CVEs', dict(counts))


if __name__ == '__main__':
    main()
