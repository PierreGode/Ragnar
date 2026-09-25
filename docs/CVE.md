# CVE Index

Every CVE ID named anywhere in Ragnar's detector code, in one list: which detector
names it and whether it is **detected** from traffic on the wire or named as **context** only.
The research behind these detections is credited in [CREDITS.md](CREDITS.md); how each
detector works is in [nettools.md](nettools.md).

> **Generated file.** Regenerate after porting a module:
> `python3 scripts/gen_cve_list.py`. Do not edit by hand.

## Summary

- **258** distinct CVE IDs
- **218** detected: a passive detector identifies the CVE's signature, exposure or exploit shape from traffic already on the wire
- **31** context only: posture advisories and reference tables for byte-level parser bugs the text-based watchers cannot reconstruct, plus related CVEs attached to a shared attack shape (named for patch guidance, not identified per-CVE)
- **6** active check: probed by the BLE Pentest action, which transmits (not part of the passive suite)
- **3** card text only: named in a detector card's description as related context, not detected
- Range **CVE-1999-0113** → **CVE-2026-81736**

| Year | CVEs |
|---|---|
| 1999 | 2 |
| 2002 | 2 |
| 2003 | 1 |
| 2005 | 2 |
| 2006 | 1 |
| 2007 | 1 |
| 2008 | 2 |
| 2011 | 1 |
| 2013 | 3 |
| 2014 | 6 |
| 2015 | 9 |
| 2016 | 5 |
| 2017 | 6 |
| 2018 | 8 |
| 2019 | 11 |
| 2020 | 15 |
| 2021 | 14 |
| 2022 | 19 |
| 2023 | 36 |
| 2024 | 47 |
| 2025 | 33 |
| 2026 | 34 |

## By detector

| Detector | CVEs |
|---|---|
| Arista Guard | 9 |
| ARP Watch | 4 |
| Aruba Guard | 42 |
| BFD Watch | 5 |
| BGP Path Watch | 13 |
| BLE Pentest (active) | 6 |
| CDP Watch | 5 |
| Cisco Guard | 15 |
| Comware Guard | 2 |
| Dell Guard | 2 |
| DHCP Guardian | 2 |
| DNS Doctor (active) | 2 |
| DNS Watch | 26 |
| EIGRP Watch | 3 |
| FTP Watch | 3 |
| ICMP Watch | 3 |
| IGMP / MLD Watch | 3 |
| IPsec / IKE Watch | 5 |
| IS-IS Watch | 2 |
| Juniper Guard | 9 |
| LACP Watch | 1 |
| LDAP Watch | 3 |
| MikroTik Guard | 14 |
| NTP Watch | 12 |
| OSPF Watch | 9 |
| PTP Watch | 4 |
| Relay / Coercion Watch | 2 |
| RPC / NetLogon Watch | 10 |
| SMB / Kerberos Watch | 5 |
| SMTP Watch | 4 |
| SNMP Watch | 5 |
| SR-MPLS Watch | 17 |
| SSH Watch | 11 |
| Telnet Watch | 10 |
| TLS Watch | 11 |
| Trailing-data / Etherleak | 1 |

## All CVEs

*Name* is the well-known attack or bug name where one exists. *Status* is the strongest evidence class across all detectors.

| CVE | Name | Status | Detector(s) | Also named as context by |
|---|---|---|---|---|
| [CVE-1999-0113](https://nvd.nist.gov/vuln/detail/CVE-1999-0113) | rlogin -froot auth bypass | detected | Telnet Watch | — |
| [CVE-1999-0185](https://nvd.nist.gov/vuln/detail/CVE-1999-0185) | r-services ftp-data trust bounce | detected | Telnet Watch | — |
| [CVE-2002-1623](https://nvd.nist.gov/vuln/detail/CVE-2002-1623) |  | detected | IPsec / IKE Watch | — |
| [CVE-2002-20001](https://nvd.nist.gov/vuln/detail/CVE-2002-20001) | D(HE)at | detected | SSH Watch, TLS Watch | — |
| [CVE-2003-0001](https://nvd.nist.gov/vuln/detail/CVE-2003-0001) | Etherleak | detected | Trailing-data / Etherleak | — |
| [CVE-2005-4436](https://nvd.nist.gov/vuln/detail/CVE-2005-4436) | EIGRP K-value / Goodbye reset | detected | EIGRP Watch | — |
| [CVE-2005-4437](https://nvd.nist.gov/vuln/detail/CVE-2005-4437) | EIGRP missing authentication | detected | EIGRP Watch | — |
| [CVE-2006-5051](https://nvd.nist.gov/vuln/detail/CVE-2006-5051) | OpenSSH signal-handler race | detected | SSH Watch | — |
| [CVE-2007-0882](https://nvd.nist.gov/vuln/detail/CVE-2007-0882) | Solaris in.telnetd -f auth bypass | detected | Telnet Watch | — |
| [CVE-2008-0960](https://nvd.nist.gov/vuln/detail/CVE-2008-0960) | SNMPv3 USM HMAC truncation | detected | SNMP Watch | — |
| [CVE-2008-4109](https://nvd.nist.gov/vuln/detail/CVE-2008-4109) |  | detected | SSH Watch | — |
| [CVE-2011-4862](https://nvd.nist.gov/vuln/detail/CVE-2011-4862) | telnetd encrypt_keyid overflow | detected | Telnet Watch | — |
| [CVE-2013-2566](https://nvd.nist.gov/vuln/detail/CVE-2013-2566) | RC4 biases | detected | TLS Watch | — |
| [CVE-2013-4796](https://nvd.nist.gov/vuln/detail/CVE-2013-4796) |  | context only | BFD Watch | — |
| [CVE-2013-5211](https://nvd.nist.gov/vuln/detail/CVE-2013-5211) | NTP monlist amplification | detected | NTP Watch | — |
| [CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160) | Heartbleed | detected | TLS Watch | — |
| [CVE-2014-7271](https://nvd.nist.gov/vuln/detail/CVE-2014-7271) |  | detected | SR-MPLS Watch | — |
| [CVE-2014-9295](https://nvd.nist.gov/vuln/detail/CVE-2014-9295) | NTP Autokey crypto_recv overflow | detected | NTP Watch | — |
| [CVE-2014-9298](https://nvd.nist.gov/vuln/detail/CVE-2014-9298) |  | detected | NTP Watch | — |
| [CVE-2014-9750](https://nvd.nist.gov/vuln/detail/CVE-2014-9750) |  | detected | NTP Watch | — |
| [CVE-2014-9751](https://nvd.nist.gov/vuln/detail/CVE-2014-9751) |  | detected | NTP Watch | — |
| [CVE-2015-2808](https://nvd.nist.gov/vuln/detail/CVE-2015-2808) | Bar Mitzvah (RC4) | detected | TLS Watch | — |
| [CVE-2015-3306](https://nvd.nist.gov/vuln/detail/CVE-2015-3306) | ProFTPD mod_copy pre-auth copy | detected | FTP Watch | — |
| [CVE-2015-4000](https://nvd.nist.gov/vuln/detail/CVE-2015-4000) | Logjam | detected | IPsec / IKE Watch | — |
| [CVE-2015-5434](https://nvd.nist.gov/vuln/detail/CVE-2015-5434) | MPLS VRF hopping (Comware) | detected | Comware Guard | SR-MPLS Watch, SSH Watch |
| [CVE-2015-7704](https://nvd.nist.gov/vuln/detail/CVE-2015-7704) | NTP Kiss-o'-Death spoof | detected | NTP Watch | — |
| [CVE-2015-7705](https://nvd.nist.gov/vuln/detail/CVE-2015-7705) | NTP Kiss-o'-Death spoof | detected | NTP Watch | — |
| [CVE-2015-7871](https://nvd.nist.gov/vuln/detail/CVE-2015-7871) | NTP crypto-NAK auth bypass | detected | NTP Watch | — |
| [CVE-2015-8087](https://nvd.nist.gov/vuln/detail/CVE-2015-8087) | MPLS VRF hopping (Huawei) | detected | Comware Guard | SR-MPLS Watch |
| [CVE-2015-8138](https://nvd.nist.gov/vuln/detail/CVE-2015-8138) |  | detected | NTP Watch | — |
| [CVE-2016-1547](https://nvd.nist.gov/vuln/detail/CVE-2016-1547) |  | card text only | NTP Watch | — |
| [CVE-2016-2108](https://nvd.nist.gov/vuln/detail/CVE-2016-2108) |  | detected | TLS Watch | — |
| [CVE-2016-2183](https://nvd.nist.gov/vuln/detail/CVE-2016-2183) | SWEET32 | detected | IPsec / IKE Watch, SSH Watch, TLS Watch | — |
| [CVE-2016-7431](https://nvd.nist.gov/vuln/detail/CVE-2016-7431) |  | detected | NTP Watch | — |
| [CVE-2016-8610](https://nvd.nist.gov/vuln/detail/CVE-2016-8610) | SSL Death Alert | detected | TLS Watch | — |
| [CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144) | EternalBlue | detected | SMB / Kerberos Watch | — |
| [CVE-2017-0781](https://nvd.nist.gov/vuln/detail/CVE-2017-0781) | BlueBorne | active check | BLE Pentest (active) | — |
| [CVE-2017-0782](https://nvd.nist.gov/vuln/detail/CVE-2017-0782) | BlueBorne | active check | BLE Pentest (active) | — |
| [CVE-2017-3731](https://nvd.nist.gov/vuln/detail/CVE-2017-3731) |  | detected | TLS Watch | — |
| [CVE-2017-6736](https://nvd.nist.gov/vuln/detail/CVE-2017-6736) |  | detected | SNMP Watch | — |
| [CVE-2017-20149](https://nvd.nist.gov/vuln/detail/CVE-2017-20149) | Chimay-Red | detected | MikroTik Guard | — |
| [CVE-2018-0063](https://nvd.nist.gov/vuln/detail/CVE-2018-0063) |  | context only | ARP Watch | — |
| [CVE-2018-0155](https://nvd.nist.gov/vuln/detail/CVE-2018-0155) |  | detected | BFD Watch | — |
| [CVE-2018-0732](https://nvd.nist.gov/vuln/detail/CVE-2018-0732) | Oversized DH prime (client DoS) | detected | TLS Watch | — |
| [CVE-2018-1111](https://nvd.nist.gov/vuln/detail/CVE-2018-1111) | DynoRoot | detected | DHCP Guardian | — |
| [CVE-2018-5389](https://nvd.nist.gov/vuln/detail/CVE-2018-5389) |  | detected | IPsec / IKE Watch | — |
| [CVE-2018-6789](https://nvd.nist.gov/vuln/detail/CVE-2018-6789) | Exim AUTH base64 overflow | detected | SMTP Watch | — |
| [CVE-2018-7445](https://nvd.nist.gov/vuln/detail/CVE-2018-7445) |  | detected | MikroTik Guard | — |
| [CVE-2018-14847](https://nvd.nist.gov/vuln/detail/CVE-2018-14847) | Winbox arbitrary file read | detected | MikroTik Guard | — |
| [CVE-2019-0033](https://nvd.nist.gov/vuln/detail/CVE-2019-0033) |  | context only | ARP Watch | — |
| [CVE-2019-3977](https://nvd.nist.gov/vuln/detail/CVE-2019-3977) |  | detected | MikroTik Guard | — |
| [CVE-2019-3979](https://nvd.nist.gov/vuln/detail/CVE-2019-3979) |  | detected | MikroTik Guard | — |
| [CVE-2019-5608](https://nvd.nist.gov/vuln/detail/CVE-2019-5608) | Fragmented IGMP/MLD membership | detected | IGMP / MLD Watch | — |
| [CVE-2019-6111](https://nvd.nist.gov/vuln/detail/CVE-2019-6111) | OpenSSH scp file overwrite | context only | Telnet Watch | — |
| [CVE-2019-7282](https://nvd.nist.gov/vuln/detail/CVE-2019-7282) | netkit rcp dot-name | detected | Telnet Watch | — |
| [CVE-2019-7283](https://nvd.nist.gov/vuln/detail/CVE-2019-7283) | netkit rcp unrequested file | detected | Telnet Watch | — |
| [CVE-2019-10149](https://nvd.nist.gov/vuln/detail/CVE-2019-10149) | Exim ${...} expansion RCE | detected | SMTP Watch | — |
| [CVE-2019-12815](https://nvd.nist.gov/vuln/detail/CVE-2019-12815) | ProFTPD mod_copy Limit bypass | detected | FTP Watch | — |
| [CVE-2019-15846](https://nvd.nist.gov/vuln/detail/CVE-2019-15846) | Exim SNI/cert-DN RCE | detected | SMTP Watch | — |
| [CVE-2019-16928](https://nvd.nist.gov/vuln/detail/CVE-2019-16928) | Exim overlong EHLO overflow | detected | SMTP Watch | — |
| [CVE-2020-0796](https://nvd.nist.gov/vuln/detail/CVE-2020-0796) | SMBGhost | detected | SMB / Kerberos Watch | — |
| [CVE-2020-1472](https://nvd.nist.gov/vuln/detail/CVE-2020-1472) | Zerologon | detected | RPC / NetLogon Watch | — |
| [CVE-2020-3110](https://nvd.nist.gov/vuln/detail/CVE-2020-3110) | CDPwn | detected | CDP Watch | — |
| [CVE-2020-3111](https://nvd.nist.gov/vuln/detail/CVE-2020-3111) | CDPwn | detected | CDP Watch | — |
| [CVE-2020-3118](https://nvd.nist.gov/vuln/detail/CVE-2020-3118) | CDPwn | detected | CDP Watch | — |
| [CVE-2020-3119](https://nvd.nist.gov/vuln/detail/CVE-2020-3119) | CDPwn | detected | CDP Watch | — |
| [CVE-2020-3120](https://nvd.nist.gov/vuln/detail/CVE-2020-3120) | CDPwn | detected | CDP Watch | — |
| [CVE-2020-8616](https://nvd.nist.gov/vuln/detail/CVE-2020-8616) | NXNSAttack | detected | DNS Watch | — |
| [CVE-2020-11868](https://nvd.nist.gov/vuln/detail/CVE-2020-11868) | NTP zero-origin sync block | detected | NTP Watch | — |
| [CVE-2020-12243](https://nvd.nist.gov/vuln/detail/CVE-2020-12243) | OpenLDAP nested-filter DoS | detected | LDAP Watch | — |
| [CVE-2020-16898](https://nvd.nist.gov/vuln/detail/CVE-2020-16898) | Bad Neighbor | detected | ICMP Watch | — |
| [CVE-2020-16899](https://nvd.nist.gov/vuln/detail/CVE-2020-16899) | RA DNSSL DoS | detected | ICMP Watch | — |
| [CVE-2020-22845](https://nvd.nist.gov/vuln/detail/CVE-2020-22845) |  | detected | MikroTik Guard | — |
| [CVE-2020-25583](https://nvd.nist.gov/vuln/detail/CVE-2020-25583) | RA DNSSL DoS (rtsold) | detected | ICMP Watch | — |
| [CVE-2020-25705](https://nvd.nist.gov/vuln/detail/CVE-2020-25705) | SAD DNS | detected | DNS Watch | — |
| [CVE-2021-0216](https://nvd.nist.gov/vuln/detail/CVE-2021-0216) |  | context only | ARP Watch | — |
| [CVE-2021-0254](https://nvd.nist.gov/vuln/detail/CVE-2021-0254) | Junos overlayd VXLAN RCE | detected | Juniper Guard | — |
| [CVE-2021-0292](https://nvd.nist.gov/vuln/detail/CVE-2021-0292) |  | context only | ARP Watch | — |
| [CVE-2021-1587](https://nvd.nist.gov/vuln/detail/CVE-2021-1587) | NX-OS NGOAM DoS | detected | Cisco Guard | — |
| [CVE-2021-1675](https://nvd.nist.gov/vuln/detail/CVE-2021-1675) | PrintNightmare | detected | RPC / NetLogon Watch | — |
| [CVE-2021-1678](https://nvd.nist.gov/vuln/detail/CVE-2021-1678) | Print spooler RPC relay (IRemoteWinSpool) | detected | RPC / NetLogon Watch | — |
| [CVE-2021-3570](https://nvd.nist.gov/vuln/detail/CVE-2021-3570) |  | detected | PTP Watch | — |
| [CVE-2021-3571](https://nvd.nist.gov/vuln/detail/CVE-2021-3571) |  | detected | PTP Watch | — |
| [CVE-2021-25220](https://nvd.nist.gov/vuln/detail/CVE-2021-25220) | MaginotDNS | detected | DNS Watch | — |
| [CVE-2021-28510](https://nvd.nist.gov/vuln/detail/CVE-2021-28510) |  | detected | PTP Watch | — |
| [CVE-2021-31166](https://nvd.nist.gov/vuln/detail/CVE-2021-31166) | HTTP.sys Accept-Encoding | detected | RPC / NetLogon Watch | — |
| [CVE-2021-34527](https://nvd.nist.gov/vuln/detail/CVE-2021-34527) | PrintNightmare | detected | RPC / NetLogon Watch | — |
| [CVE-2021-36942](https://nvd.nist.gov/vuln/detail/CVE-2021-36942) | PetitPotam | detected | RPC / NetLogon Watch, Relay / Coercion Watch | — |
| [CVE-2021-41987](https://nvd.nist.gov/vuln/detail/CVE-2021-41987) |  | detected | MikroTik Guard | — |
| [CVE-2022-21907](https://nvd.nist.gov/vuln/detail/CVE-2022-21907) | HTTP.sys Accept-Encoding | detected | RPC / NetLogon Watch | — |
| [CVE-2022-24805](https://nvd.nist.gov/vuln/detail/CVE-2022-24805) |  | detected | SNMP Watch | — |
| [CVE-2022-24807](https://nvd.nist.gov/vuln/detail/CVE-2022-24807) |  | detected | SNMP Watch | — |
| [CVE-2022-26125](https://nvd.nist.gov/vuln/detail/CVE-2022-26125) |  | context only | SR-MPLS Watch | — |
| [CVE-2022-26126](https://nvd.nist.gov/vuln/detail/CVE-2022-26126) |  | context only | SR-MPLS Watch | — |
| [CVE-2022-26809](https://nvd.nist.gov/vuln/detail/CVE-2022-26809) | RPC runtime bind_ack underflow | detected | RPC / NetLogon Watch | — |
| [CVE-2022-26925](https://nvd.nist.gov/vuln/detail/CVE-2022-26925) | PetitPotam-class LSA coercion | detected | RPC / NetLogon Watch, Relay / Coercion Watch | — |
| [CVE-2022-33647](https://nvd.nist.gov/vuln/detail/CVE-2022-33647) | Kerberos RC4-MD4 downgrade | detected | SMB / Kerberos Watch | — |
| [CVE-2022-33679](https://nvd.nist.gov/vuln/detail/CVE-2022-33679) | Kerberos RC4-MD4 downgrade | detected | SMB / Kerberos Watch | — |
| [CVE-2022-37885](https://nvd.nist.gov/vuln/detail/CVE-2022-37885) |  | detected | Aruba Guard | — |
| [CVE-2022-37886](https://nvd.nist.gov/vuln/detail/CVE-2022-37886) |  | detected | Aruba Guard | — |
| [CVE-2022-37887](https://nvd.nist.gov/vuln/detail/CVE-2022-37887) |  | detected | Aruba Guard | — |
| [CVE-2022-37888](https://nvd.nist.gov/vuln/detail/CVE-2022-37888) |  | detected | Aruba Guard | — |
| [CVE-2022-37889](https://nvd.nist.gov/vuln/detail/CVE-2022-37889) |  | detected | Aruba Guard | — |
| [CVE-2022-39028](https://nvd.nist.gov/vuln/detail/CVE-2022-39028) | inetutils telnetd EC/EL crash | detected | Telnet Watch | — |
| [CVE-2022-40302](https://nvd.nist.gov/vuln/detail/CVE-2022-40302) |  | context only | BGP Path Watch | — |
| [CVE-2022-40735](https://nvd.nist.gov/vuln/detail/CVE-2022-40735) | D(HE)at | detected | IPsec / IKE Watch, SSH Watch, TLS Watch | — |
| [CVE-2022-43681](https://nvd.nist.gov/vuln/detail/CVE-2022-43681) |  | context only | BGP Path Watch | — |
| [CVE-2022-45313](https://nvd.nist.gov/vuln/detail/CVE-2022-45313) |  | detected | MikroTik Guard | — |
| [CVE-2023-20049](https://nvd.nist.gov/vuln/detail/CVE-2023-20049) |  | detected | BFD Watch | — |
| [CVE-2023-20159](https://nvd.nist.gov/vuln/detail/CVE-2023-20159) |  | detected | Cisco Guard | — |
| [CVE-2023-20160](https://nvd.nist.gov/vuln/detail/CVE-2023-20160) |  | detected | Cisco Guard | — |
| [CVE-2023-20161](https://nvd.nist.gov/vuln/detail/CVE-2023-20161) |  | detected | Cisco Guard | — |
| [CVE-2023-20189](https://nvd.nist.gov/vuln/detail/CVE-2023-20189) |  | detected | Cisco Guard | — |
| [CVE-2023-22747](https://nvd.nist.gov/vuln/detail/CVE-2023-22747) |  | detected | Aruba Guard | — |
| [CVE-2023-22748](https://nvd.nist.gov/vuln/detail/CVE-2023-22748) |  | detected | Aruba Guard | — |
| [CVE-2023-22749](https://nvd.nist.gov/vuln/detail/CVE-2023-22749) |  | detected | Aruba Guard | — |
| [CVE-2023-22750](https://nvd.nist.gov/vuln/detail/CVE-2023-22750) |  | detected | Aruba Guard | — |
| [CVE-2023-22751](https://nvd.nist.gov/vuln/detail/CVE-2023-22751) |  | detected | Aruba Guard | — |
| [CVE-2023-22752](https://nvd.nist.gov/vuln/detail/CVE-2023-22752) |  | detected | Aruba Guard | — |
| [CVE-2023-22779](https://nvd.nist.gov/vuln/detail/CVE-2023-22779) |  | detected | Aruba Guard | — |
| [CVE-2023-22780](https://nvd.nist.gov/vuln/detail/CVE-2023-22780) |  | detected | Aruba Guard | — |
| [CVE-2023-22781](https://nvd.nist.gov/vuln/detail/CVE-2023-22781) |  | detected | Aruba Guard | — |
| [CVE-2023-22782](https://nvd.nist.gov/vuln/detail/CVE-2023-22782) |  | detected | Aruba Guard | — |
| [CVE-2023-22783](https://nvd.nist.gov/vuln/detail/CVE-2023-22783) |  | detected | Aruba Guard | — |
| [CVE-2023-22784](https://nvd.nist.gov/vuln/detail/CVE-2023-22784) |  | detected | Aruba Guard | — |
| [CVE-2023-22785](https://nvd.nist.gov/vuln/detail/CVE-2023-22785) |  | detected | Aruba Guard | — |
| [CVE-2023-22786](https://nvd.nist.gov/vuln/detail/CVE-2023-22786) |  | detected | Aruba Guard | — |
| [CVE-2023-22787](https://nvd.nist.gov/vuln/detail/CVE-2023-22787) |  | detected | Aruba Guard | — |
| [CVE-2023-31490](https://nvd.nist.gov/vuln/detail/CVE-2023-31490) |  | detected | SR-MPLS Watch | — |
| [CVE-2023-32154](https://nvd.nist.gov/vuln/detail/CVE-2023-32154) |  | detected | MikroTik Guard | — |
| [CVE-2023-36844](https://nvd.nist.gov/vuln/detail/CVE-2023-36844) |  | detected | Juniper Guard | — |
| [CVE-2023-36845](https://nvd.nist.gov/vuln/detail/CVE-2023-36845) |  | detected | Juniper Guard | — |
| [CVE-2023-36846](https://nvd.nist.gov/vuln/detail/CVE-2023-36846) |  | detected | Juniper Guard | — |
| [CVE-2023-36847](https://nvd.nist.gov/vuln/detail/CVE-2023-36847) |  | detected | Juniper Guard | — |
| [CVE-2023-38802](https://nvd.nist.gov/vuln/detail/CVE-2023-38802) |  | context only | BGP Path Watch | — |
| [CVE-2023-41358](https://nvd.nist.gov/vuln/detail/CVE-2023-41358) |  | context only | BGP Path Watch | — |
| [CVE-2023-44204](https://nvd.nist.gov/vuln/detail/CVE-2023-44204) |  | context only | SR-MPLS Watch | — |
| [CVE-2023-47234](https://nvd.nist.gov/vuln/detail/CVE-2023-47234) |  | context only | BGP Path Watch | — |
| [CVE-2023-47235](https://nvd.nist.gov/vuln/detail/CVE-2023-47235) |  | context only | BGP Path Watch | — |
| [CVE-2023-47310](https://nvd.nist.gov/vuln/detail/CVE-2023-47310) |  | detected | MikroTik Guard | — |
| [CVE-2023-48795](https://nvd.nist.gov/vuln/detail/CVE-2023-48795) | Terrapin | detected | SSH Watch | — |
| [CVE-2023-50387](https://nvd.nist.gov/vuln/detail/CVE-2023-50387) | KeyTrap | detected | DNS Doctor (active), DNS Watch | — |
| [CVE-2023-50868](https://nvd.nist.gov/vuln/detail/CVE-2023-50868) | NSEC3 CPU exhaustion | detected | DNS Doctor (active), DNS Watch | — |
| [CVE-2023-51713](https://nvd.nist.gov/vuln/detail/CVE-2023-51713) | ProFTPD make_ftp_cmd OOB read | detected | FTP Watch | — |
| [CVE-2024-3596](https://nvd.nist.gov/vuln/detail/CVE-2024-3596) | BlastRADIUS | detected | Arista Guard | — |
| [CVE-2024-3661](https://nvd.nist.gov/vuln/detail/CVE-2024-3661) | TunnelVision | detected | DHCP Guardian | — |
| [CVE-2024-5872](https://nvd.nist.gov/vuln/detail/CVE-2024-5872) |  | detected | Arista Guard | — |
| [CVE-2024-6387](https://nvd.nist.gov/vuln/detail/CVE-2024-6387) | regreSSHion | detected | Arista Guard, SSH Watch | — |
| [CVE-2024-6409](https://nvd.nist.gov/vuln/detail/CVE-2024-6409) |  | detected | Arista Guard | — |
| [CVE-2024-20259](https://nvd.nist.gov/vuln/detail/CVE-2024-20259) |  | detected | Cisco Guard | — |
| [CVE-2024-20307](https://nvd.nist.gov/vuln/detail/CVE-2024-20307) |  | detected | Cisco Guard | — |
| [CVE-2024-20308](https://nvd.nist.gov/vuln/detail/CVE-2024-20308) |  | detected | Cisco Guard | — |
| [CVE-2024-20399](https://nvd.nist.gov/vuln/detail/CVE-2024-20399) |  | detected | Cisco Guard | — |
| [CVE-2024-20406](https://nvd.nist.gov/vuln/detail/CVE-2024-20406) |  | detected | IS-IS Watch | — |
| [CVE-2024-20434](https://nvd.nist.gov/vuln/detail/CVE-2024-20434) |  | detected | Cisco Guard | — |
| [CVE-2024-21593](https://nvd.nist.gov/vuln/detail/CVE-2024-21593) |  | context only | SR-MPLS Watch | — |
| [CVE-2024-26304](https://nvd.nist.gov/vuln/detail/CVE-2024-26304) |  | detected | Aruba Guard | — |
| [CVE-2024-26305](https://nvd.nist.gov/vuln/detail/CVE-2024-26305) |  | detected | Aruba Guard | — |
| [CVE-2024-27913](https://nvd.nist.gov/vuln/detail/CVE-2024-27913) |  | context only | OSPF Watch, SR-MPLS Watch | — |
| [CVE-2024-30388](https://nvd.nist.gov/vuln/detail/CVE-2024-30388) | LACP malformed-PDU flap | detected | LACP Watch | — |
| [CVE-2024-30395](https://nvd.nist.gov/vuln/detail/CVE-2024-30395) |  | context only | BGP Path Watch | — |
| [CVE-2024-31466](https://nvd.nist.gov/vuln/detail/CVE-2024-31466) |  | detected | Aruba Guard | — |
| [CVE-2024-31467](https://nvd.nist.gov/vuln/detail/CVE-2024-31467) |  | detected | Aruba Guard | — |
| [CVE-2024-31468](https://nvd.nist.gov/vuln/detail/CVE-2024-31468) |  | detected | Aruba Guard | — |
| [CVE-2024-31469](https://nvd.nist.gov/vuln/detail/CVE-2024-31469) |  | detected | Aruba Guard | — |
| [CVE-2024-31470](https://nvd.nist.gov/vuln/detail/CVE-2024-31470) |  | detected | Aruba Guard | — |
| [CVE-2024-31471](https://nvd.nist.gov/vuln/detail/CVE-2024-31471) |  | detected | Aruba Guard | — |
| [CVE-2024-31472](https://nvd.nist.gov/vuln/detail/CVE-2024-31472) |  | detected | Aruba Guard | — |
| [CVE-2024-31473](https://nvd.nist.gov/vuln/detail/CVE-2024-31473) |  | detected | Aruba Guard | — |
| [CVE-2024-31474](https://nvd.nist.gov/vuln/detail/CVE-2024-31474) |  | detected | Aruba Guard | — |
| [CVE-2024-31475](https://nvd.nist.gov/vuln/detail/CVE-2024-31475) |  | detected | Aruba Guard | — |
| [CVE-2024-31948](https://nvd.nist.gov/vuln/detail/CVE-2024-31948) |  | detected | SR-MPLS Watch | BGP Path Watch |
| [CVE-2024-31949](https://nvd.nist.gov/vuln/detail/CVE-2024-31949) |  | context only | SR-MPLS Watch | — |
| [CVE-2024-31950](https://nvd.nist.gov/vuln/detail/CVE-2024-31950) |  | detected | SR-MPLS Watch | OSPF Watch |
| [CVE-2024-31951](https://nvd.nist.gov/vuln/detail/CVE-2024-31951) |  | detected | SR-MPLS Watch | OSPF Watch |
| [CVE-2024-33511](https://nvd.nist.gov/vuln/detail/CVE-2024-33511) |  | detected | Aruba Guard | — |
| [CVE-2024-33512](https://nvd.nist.gov/vuln/detail/CVE-2024-33512) |  | detected | Aruba Guard | — |
| [CVE-2024-33655](https://nvd.nist.gov/vuln/detail/CVE-2024-33655) | DNSBomb | detected | DNS Watch | — |
| [CVE-2024-41996](https://nvd.nist.gov/vuln/detail/CVE-2024-41996) | D(HE)at | detected | SSH Watch, TLS Watch | — |
| [CVE-2024-42393](https://nvd.nist.gov/vuln/detail/CVE-2024-42393) |  | detected | Aruba Guard | — |
| [CVE-2024-42394](https://nvd.nist.gov/vuln/detail/CVE-2024-42394) |  | detected | Aruba Guard | — |
| [CVE-2024-42395](https://nvd.nist.gov/vuln/detail/CVE-2024-42395) |  | detected | Aruba Guard | — |
| [CVE-2024-42505](https://nvd.nist.gov/vuln/detail/CVE-2024-42505) |  | detected | Aruba Guard | — |
| [CVE-2024-42506](https://nvd.nist.gov/vuln/detail/CVE-2024-42506) |  | detected | Aruba Guard | — |
| [CVE-2024-42507](https://nvd.nist.gov/vuln/detail/CVE-2024-42507) |  | detected | Aruba Guard | — |
| [CVE-2024-42509](https://nvd.nist.gov/vuln/detail/CVE-2024-42509) |  | detected | Aruba Guard | — |
| [CVE-2024-42861](https://nvd.nist.gov/vuln/detail/CVE-2024-42861) |  | detected | PTP Watch | — |
| [CVE-2024-43532](https://nvd.nist.gov/vuln/detail/CVE-2024-43532) | RemoteRegistry NTLM relay | detected | RPC / NetLogon Watch | — |
| [CVE-2024-47460](https://nvd.nist.gov/vuln/detail/CVE-2024-47460) |  | detected | Aruba Guard | — |
| [CVE-2024-49112](https://nvd.nist.gov/vuln/detail/CVE-2024-49112) | LDAPNightmare | detected | LDAP Watch | — |
| [CVE-2024-49113](https://nvd.nist.gov/vuln/detail/CVE-2024-49113) | LDAPNightmare | detected | LDAP Watch | — |
| [CVE-2025-0936](https://nvd.nist.gov/vuln/detail/CVE-2025-0936) |  | detected | Arista Guard | — |
| [CVE-2025-1259](https://nvd.nist.gov/vuln/detail/CVE-2025-1259) |  | detected | Arista Guard | — |
| [CVE-2025-1260](https://nvd.nist.gov/vuln/detail/CVE-2025-1260) |  | detected | Arista Guard | — |
| [CVE-2025-5089](https://nvd.nist.gov/vuln/detail/CVE-2025-5089) |  | detected | Arista Guard | — |
| [CVE-2025-8677](https://nvd.nist.gov/vuln/detail/CVE-2025-8677) |  | detected | DNS Watch | — |
| [CVE-2025-10948](https://nvd.nist.gov/vuln/detail/CVE-2025-10948) |  | detected | MikroTik Guard | — |
| [CVE-2025-20164](https://nvd.nist.gov/vuln/detail/CVE-2025-20164) |  | detected | Cisco Guard | — |
| [CVE-2025-20241](https://nvd.nist.gov/vuln/detail/CVE-2025-20241) |  | detected | Cisco Guard | — |
| [CVE-2025-20312](https://nvd.nist.gov/vuln/detail/CVE-2025-20312) |  | detected | Cisco Guard | — |
| [CVE-2025-20315](https://nvd.nist.gov/vuln/detail/CVE-2025-20315) | CAPWAP malformed header | detected | Cisco Guard | — |
| [CVE-2025-20352](https://nvd.nist.gov/vuln/detail/CVE-2025-20352) |  | detected | Cisco Guard | — |
| [CVE-2025-20700](https://nvd.nist.gov/vuln/detail/CVE-2025-20700) | Airoha RACE | active check | BLE Pentest (active) | — |
| [CVE-2025-20701](https://nvd.nist.gov/vuln/detail/CVE-2025-20701) | Airoha RACE | active check | BLE Pentest (active) | — |
| [CVE-2025-20702](https://nvd.nist.gov/vuln/detail/CVE-2025-20702) | Airoha RACE | active check | BLE Pentest (active) | — |
| [CVE-2025-21595](https://nvd.nist.gov/vuln/detail/CVE-2025-21595) |  | card text only | Juniper Guard | — |
| [CVE-2025-22474](https://nvd.nist.gov/vuln/detail/CVE-2025-22474) | Dell OS10 SSRF | detected | Dell Guard | — |
| [CVE-2025-33073](https://nvd.nist.gov/vuln/detail/CVE-2025-33073) | SMB reflective relay | detected | SMB / Kerberos Watch | — |
| [CVE-2025-36911](https://nvd.nist.gov/vuln/detail/CVE-2025-36911) | WhisperPair | active check | BLE Pentest (active) | — |
| [CVE-2025-38741](https://nvd.nist.gov/vuln/detail/CVE-2025-38741) | Duplicate SSH host key | detected | Dell Guard, SSH Watch | — |
| [CVE-2025-40778](https://nvd.nist.gov/vuln/detail/CVE-2025-40778) | Unsolicited-RR cache poisoning | detected | DNS Watch | — |
| [CVE-2025-40780](https://nvd.nist.gov/vuln/detail/CVE-2025-40780) | Weak port/ID PRNG | detected | DNS Watch | — |
| [CVE-2025-44954](https://nvd.nist.gov/vuln/detail/CVE-2025-44954) |  | detected | SSH Watch | — |
| [CVE-2025-50681](https://nvd.nist.gov/vuln/detail/CVE-2025-50681) |  | detected | IGMP / MLD Watch | — |
| [CVE-2025-59978](https://nvd.nist.gov/vuln/detail/CVE-2025-59978) |  | detected | Juniper Guard | — |
| [CVE-2025-61099](https://nvd.nist.gov/vuln/detail/CVE-2025-61099) |  | context only | OSPF Watch | — |
| [CVE-2025-61101](https://nvd.nist.gov/vuln/detail/CVE-2025-61101) |  | context only | SR-MPLS Watch | — |
| [CVE-2025-61103](https://nvd.nist.gov/vuln/detail/CVE-2025-61103) |  | context only | OSPF Watch, SR-MPLS Watch | — |
| [CVE-2025-61104](https://nvd.nist.gov/vuln/detail/CVE-2025-61104) |  | context only | OSPF Watch | — |
| [CVE-2025-61105](https://nvd.nist.gov/vuln/detail/CVE-2025-61105) |  | context only | OSPF Watch | — |
| [CVE-2025-61106](https://nvd.nist.gov/vuln/detail/CVE-2025-61106) |  | context only | OSPF Watch, SR-MPLS Watch | — |
| [CVE-2025-61107](https://nvd.nist.gov/vuln/detail/CVE-2025-61107) |  | context only | OSPF Watch, SR-MPLS Watch | — |
| [CVE-2025-61481](https://nvd.nist.gov/vuln/detail/CVE-2025-61481) |  | detected | MikroTik Guard | — |
| [CVE-2025-68615](https://nvd.nist.gov/vuln/detail/CVE-2025-68615) | snmptrapd overflow | detected | SNMP Watch | — |
| [CVE-2026-2291](https://nvd.nist.gov/vuln/detail/CVE-2026-2291) |  | detected | DNS Watch | — |
| [CVE-2026-4890](https://nvd.nist.gov/vuln/detail/CVE-2026-4890) |  | detected | DNS Watch | — |
| [CVE-2026-4891](https://nvd.nist.gov/vuln/detail/CVE-2026-4891) |  | detected | DNS Watch | — |
| [CVE-2026-5172](https://nvd.nist.gov/vuln/detail/CVE-2026-5172) |  | detected | DNS Watch | — |
| [CVE-2026-7473](https://nvd.nist.gov/vuln/detail/CVE-2026-7473) |  | detected | Arista Guard | — |
| [CVE-2026-7668](https://nvd.nist.gov/vuln/detail/CVE-2026-7668) |  | detected | MikroTik Guard | — |
| [CVE-2026-10723](https://nvd.nist.gov/vuln/detail/CVE-2026-10723) |  | detected | DNS Watch | — |
| [CVE-2026-11721](https://nvd.nist.gov/vuln/detail/CVE-2026-11721) |  | detected | DNS Watch | — |
| [CVE-2026-13204](https://nvd.nist.gov/vuln/detail/CVE-2026-13204) |  | detected | DNS Watch | — |
| [CVE-2026-13321](https://nvd.nist.gov/vuln/detail/CVE-2026-13321) |  | detected | DNS Watch | — |
| [CVE-2026-19033](https://nvd.nist.gov/vuln/detail/CVE-2026-19033) | Unsigned multi-message XFR | detected | DNS Watch | — |
| [CVE-2026-19668](https://nvd.nist.gov/vuln/detail/CVE-2026-19668) |  | detected | DNS Watch | — |
| [CVE-2026-20074](https://nvd.nist.gov/vuln/detail/CVE-2026-20074) | IS-IS multi-instance exposure | detected | IS-IS Watch | — |
| [CVE-2026-20222](https://nvd.nist.gov/vuln/detail/CVE-2026-20222) | EIGRP update flood | detected | EIGRP Watch | — |
| [CVE-2026-21902](https://nvd.nist.gov/vuln/detail/CVE-2026-21902) |  | detected | Juniper Guard | — |
| [CVE-2026-24061](https://nvd.nist.gov/vuln/detail/CVE-2026-24061) | inetutils telnetd auth bypass | detected | Telnet Watch | — |
| [CVE-2026-32746](https://nvd.nist.gov/vuln/detail/CVE-2026-32746) |  | detected | Telnet Watch | — |
| [CVE-2026-33781](https://nvd.nist.gov/vuln/detail/CVE-2026-33781) |  | card text only | Juniper Guard | — |
| [CVE-2026-33800](https://nvd.nist.gov/vuln/detail/CVE-2026-33800) |  | detected | BFD Watch | — |
| [CVE-2026-37457](https://nvd.nist.gov/vuln/detail/CVE-2026-37457) |  | context only | BGP Path Watch | — |
| [CVE-2026-37458](https://nvd.nist.gov/vuln/detail/CVE-2026-37458) |  | context only | BGP Path Watch | — |
| [CVE-2026-37459](https://nvd.nist.gov/vuln/detail/CVE-2026-37459) |  | context only | BGP Path Watch | — |
| [CVE-2026-37461](https://nvd.nist.gov/vuln/detail/CVE-2026-37461) |  | context only | BGP Path Watch | — |
| [CVE-2026-37462](https://nvd.nist.gov/vuln/detail/CVE-2026-37462) |  | context only | BGP Path Watch | — |
| [CVE-2026-42944](https://nvd.nist.gov/vuln/detail/CVE-2026-42944) |  | detected | DNS Watch | — |
| [CVE-2026-52688](https://nvd.nist.gov/vuln/detail/CVE-2026-52688) |  | detected | DNS Watch | — |
| [CVE-2026-53275](https://nvd.nist.gov/vuln/detail/CVE-2026-53275) |  | detected | IGMP / MLD Watch | — |
| [CVE-2026-67281](https://nvd.nist.gov/vuln/detail/CVE-2026-67281) |  | detected | MikroTik Guard | — |
| [CVE-2026-73458](https://nvd.nist.gov/vuln/detail/CVE-2026-73458) |  | detected | BFD Watch | — |
| [CVE-2026-75029](https://nvd.nist.gov/vuln/detail/CVE-2026-75029) |  | detected | DNS Watch | — |
| [CVE-2026-76163](https://nvd.nist.gov/vuln/detail/CVE-2026-76163) |  | detected | DNS Watch | — |
| [CVE-2026-81563](https://nvd.nist.gov/vuln/detail/CVE-2026-81563) |  | detected | DNS Watch | — |
| [CVE-2026-81642](https://nvd.nist.gov/vuln/detail/CVE-2026-81642) | DNS compression-pointer loop | detected | DNS Watch | — |
| [CVE-2026-81736](https://nvd.nist.gov/vuln/detail/CVE-2026-81736) |  | detected | DNS Watch | — |
