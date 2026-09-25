# Credits & Attribution

Ragnar is supported by people's work. This file records, in more detail than the
[README credits table](../README.md#-credits--attribution), the people whose research and
engineering make Ragnar possible.

## Solarflere — the CVE research behind the passive detection suite

Every CVE that Ragnar's passive watchers and vendor guards can detect was identified,
researched and curated by **[Solarflere](https://www.instagram.com/solarflere)**, who
co-authors the [Authority Verification](nettools.md) suite (Diagnostics, Switch &
L2/L3, Interfaces). Ragnar turns that research into detectors — the vulnerability corpus
behind them is Solarflere's work.

### By the numbers

- **216 CVEs detected from the wire.** 256 distinct CVE IDs are named across Ragnar's
  code; 216 of them a passive detector actually identifies. The rest are named, not detected:
  30 as context (the four Juniper ARP control-plane CVEs attached to a shared request-rate
  shape, the SR-MPLS `CVE_REFERENCES` table, and the BGP / OSPF **malformed-attribute posture
  advisories** — byte-level parser CVEs the passive text watchers name for patch guidance but
  cannot reconstruct on the wire), 3 in card prose as related context, and 6 **active** BLE
  checks in the BLE Pentest action. Every one is listed, with its detector and status, in the
  generated **[CVE Index](CVE.md)**.
- **28 years of coverage** — from **CVE-1999-0113** (the rlogin `-froot` bypass) to
  **CVE-2026-81736**.
- **Two CISA KEV entries** join the corpus with SMTP Watch (CVE-2019-10149, CVE-2018-6789).
- Weighted to the current threat wave (all named IDs): **36 CVEs from 2023, 47 from 2024, 33 from 2025, and
  34 from 2026.**
- Spanning **~40 passive detectors** from L2 to L7 plus the timing- and forwarding-plane
  watchers (BFD, PTP, SR-MPLS) and the **IPsec/IKE** key-exchange posture detector, **six
  in-app vendor CVE guards** (Cisco, Juniper, Arista, Comware, MikroTik, Aruba) and **Dell
  Guard** as a standalone daemon.
- **Cross-protocol crypto-attack coverage** — the same cryptographic weaknesses are named
  everywhere they appear: **SWEET32** (CVE-2016-2183) in TLS, SSH and IKE; **D(HE)at**
  (CVE-2002-20001 / CVE-2022-40735 / CVE-2024-41996) across TLS, SSH and IPsec; and
  **Logjam / weak-DH** (CVE-2015-4000) in IKE.
- **DNS / DNSSEC** — a passive DNS-response detector for **KeyTrap** (CVE-2023-50387),
  **NSEC3** DoS (CVE-2023-50868), **NXNSAttack** (CVE-2020-8616), **MaginotDNS**
  cache-poisoning (CVE-2021-25220), **DNSBomb** (CVE-2024-33655) and **SAD DNS**
  (CVE-2020-25705), plus KeyTrap/NSEC3 posture folded into the active DNS Doctor. **DNS
  Watch v5** adds 20 more, all read from the wire: malformed-record parser bugs —
  compression-pointer loops (CVE-2026-81642 Unbound, CVE-2026-2291 / CVE-2026-5172 dnsmasq)
  and malformed DNSKEY rdata (CVE-2025-8677 BIND, CVE-2026-4890 / CVE-2026-4891 dnsmasq);
  DNSSEC structural integrity — RRSIG label overrun (CVE-2026-11721 / CVE-2026-52688), NSEC
  chain escape (CVE-2026-13321), NSEC3 apex-hash impersonation (CVE-2026-10723) and
  NSEC/NSEC3 coexistence (CVE-2026-13204); protocol abuse — SVCB AliasMode fan-out
  (CVE-2026-81563 / CVE-2026-81736), duplicated EDNS options (CVE-2026-42944), duplicate-RR
  floods (CVE-2026-75029) and TKEY queries (CVE-2026-76163); an unsigned multi-message zone
  transfer (CVE-2026-19033); and three CVEs named on existing detections — excessive key-tag
  matching (CVE-2026-19668), unsolicited-RR acceptance (CVE-2025-40778) and the weak
  source-port/query-ID PRNG (CVE-2025-40780).
- **SNMP / multicast / time-plane** — the in-app **SNMP Watch** now reads raw BER off the
  wire for **USM HMAC truncation** (CVE-2008-0960), **Cisco SNMP RCE** (CVE-2017-6736..6744,
  CISA KEV), **snmptrapd overflow** (CVE-2025-68615) and **net-snmp VACM malformed-OID**
  (CVE-2022-24805/24807/24809/24810); **IGMP/MLD Watch** flags malformed multicast control —
  fragmented membership (CVE-2019-5608), invalid group-record type (CVE-2025-50681) and
  query source-count overrun (CVE-2026-53275), both address families; and **NTP Watch** names
  monlist amplification (CVE-2013-5211), spoofed Kiss-o'-Death (CVE-2015-7704/7705),
  loopback-source ACL bypass (CVE-2014-9298/9751) and the zero-origin sync block
  (CVE-2020-11868).
- **TLS record layer & timing plane** — **TLS Watch** adds **Heartbleed** (CVE-2014-0160,
  the cleartext heartbeat over-read shape) and the **oversized DH prime** client-DoS
  (CVE-2018-0732, read from the ServerKeyExchange); **PTP Watch** adds a CVE-attributed
  class for the timing plane — linuxptp **forwarding over-read** (CVE-2021-3570) and
  **one-step Sync length abuse** (CVE-2021-3571), the gPTP **peer-delay requester flood**
  (CVE-2024-42861) and the Arista EOS **invalid-TLV agent restart** (CVE-2021-28510).
- **Windows attack surface & ARP control plane** — the in-app **SMB / Kerberos Watch** now
  names **SMBGhost** (CVE-2020-0796 — both the SMB 3.1.1 compression-negotiation exposure
  and the compression-transform 32-bit-overflow exploit), the **EternalBlue** TRANS2
  SESSION_SETUP primitive (CVE-2017-0144), **RC4-MD4** Kerberos downgrade injection
  (CVE-2022-33679 / CVE-2022-33647 — etype -128 offered, granted, or advertised in a
  KRB-ERROR PA-ETYPE-INFO2) and the **reflective-relay** primitive (CVE-2025-33073 —
  client == server, or a marshalled CREDENTIAL_TARGET_INFORMATION blob in a name/SPN); the
  vendored **RPC / NetLogon Watch** adds **PrintNightmare** (CVE-2021-1675 / CVE-2021-34527,
  spoolss RpcAddPrinterDriver over `\pipe\spoolss`), the **HTTP.sys** Accept-Encoding bug
  (CVE-2021-31166 / CVE-2022-21907), the **RPC-runtime bind_ack underflow** (CVE-2022-26809),
  **PetitPotam-class LSA anonymous coercion** (CVE-2022-26925) and the **RemoteRegistry
  NTLM-relay fallback** (CVE-2024-43532); and **ARP Watch** gains a passive ARP-frame capture
  that flags request rate/breadth and gratuitous floods — the shared shape behind the Juniper
  ARP control-plane DoS family (CVE-2018-0063 / CVE-2019-0033 / CVE-2021-0216 / CVE-2021-0292),
  attached as related context, not a per-CVE identification.
- **Forwarding & failover plane** — **BFD Watch** adds an **auth-bypass teardown**
  (CVE-2026-73458, Arista EOS, CWE-303 — a Down whose auth type/key-id departs from the
  session's established profile), a **micro-BFD flap storm** (CVE-2026-33800, Juniper MX
  PFEMAN/FPC crash) and names **CVE-2023-20049** (Cisco IOS XR BFD hardware-offload crash) on
  its malformed/truncated-header codes alongside CVE-2018-0155; **SR-MPLS Watch** adds an
  **unvalidated Segment-Routing TLV-length overrun** (`SRM-SR-TLV-OVERRUN`) that names the
  SR control-plane parser CVEs it actually catches on the wire — BGP Prefix-SID
  (CVE-2023-31490 / CVE-2024-31948) and OSPF SR opaque-LSA (CVE-2024-31950 / CVE-2024-31951)
  — with a further `CVE_REFERENCES` table recording the SR-plane CVEs that are disputed or
  owned by the BGP/IS-IS/OSPF watchers rather than claimed here.

- **LAN / directory / first-hop wave** — **LACP Watch** correlates a malformed LACPDU
  with a member flap into `LACP-MALFORMED-INDUCED-FLAP` (CVE-2024-30388 class, effect not
  signature); **LDAP Watch** adds the OpenLDAP nested-filter slapd crash (CVE-2020-12243)
  as `filter-nest-dos`; **DHCP Guardian** adds a passive DHCP-option scan for **TunnelVision**
  (CVE-2024-3661, option 121/249 covering the default route — VPN decloaking) and
  **DynoRoot-class** command injection (CVE-2018-1111, shell metacharacters in a text
  option); and the in-app **ICMPv6 RA** parser adds the DNSSL-option DoS (CVE-2020-16899
  Windows / CVE-2020-25583 FreeBSD rtsold) alongside the existing Bad Neighbor
  (CVE-2020-16898). The two Microsoft DHCP heap-overflow CVEs (CVE-2026-50518 /
  CVE-2026-56159) are deferred — no published trigger, so no passive signature exists yet.

- **Routing / IGP wave** — **EIGRP Watch** names three CVEs on shapes it already detects:
  the K-value / Goodbye adjacency-reset (CVE-2005-4436), weak/absent authentication
  (CVE-2005-4437) and an unauthenticated Update-class flood (CVE-2026-20222, Cisco
  ASA/FTD). **IS-IS Watch** adds two IOS XR feature-exposure detections read from the wire:
  multi-instance IS-IS via the Instance-Identifier TLV #7 (CVE-2026-20074) and
  SR/Flex-Algo signalling via Router-Capability TLV #242 sub-TLVs (CVE-2024-20406);
  CVE-2024-20312 is excluded (no passive signature). **BGP Path Watch** and **OSPF Watch**
  name their v4 malformed-attribute / opaque-LSA CVE corpora as posture advisories — FRR /
  GoBGP / Juniper byte-level parser bugs (BGP: CVE-2022-40302/43681, CVE-2023-41358/47234/
  47235, CVE-2024-30395, CVE-2026-37457/37458/37459/37461/37462; OSPF: CVE-2025-61099/61103/
  61104/61106) — because the passive text watchers cannot reconstruct the malformed bytes;
  the OSPF SR opaque-LSA overruns (CVE-2024-31950/31951) are byte-level detected by SR-MPLS
  Watch, and the standalone BGP tap does the byte-level BGP detection.

- **SR / MPLS control plane, now OSPFv3** — **SR-MPLS Watch** extends its byte-level SR
  TLV-overrun detector (`SRM-SR-TLV-OVERRUN`) to **OSPFv3 Segment Routing** (RFC 5340 /
  RFC 8362 extended LSAs / RFC 8666 SR) alongside MPLS, SRv6 and OSPFv2-SR — so an
  overrunning OSPFv3 Prefix-SID / Adj-SID / Router-Information sub-TLV is caught on the
  IPv6 wire (the RI path names CVE-2024-31950; the FRR ospf6d crash CVEs
  CVE-2025-61101 / -61103 / -61106 / -61107 are recorded in `CVE_REFERENCES` as
  reference-only, their receiver-side `debug` precondition being unobservable passively).
  Separately, the in-app **OSPF Watch** adds an OSPFv3 **Instance-ID anomaly** detection
  (a rogue parallel-instance / spoofing tell, read from the tcpdump `Instance N` token).

- **Cleartext application protocols** — **FTP Watch** reads the FTP control channel for the
  ProFTPD CVEs that are actually visible there: **mod_copy** `SITE CPFR`/`CPTO` issued before
  authentication (**CVE-2015-3306**) or by an anonymous/ordinary session
  (**CVE-2019-12815**) — a server-side copy needing no data connection, with the server's own
  `350`/`250` replies confirming acceptance and completion — and the **quoted command verb**
  that drives `make_ftp_cmd` into a one-byte out-of-bounds read (**CVE-2023-51713**),
  ungated because no legitimate FTP verb opens with a quote. Banner version ranges are
  capped at low confidence and reported as "verify this server", never as a vulnerable
  verdict; vsftpd and Pure-FTPd are explicitly out of scope because nothing in them is
  passively detectable at the bar this suite sets. **SMTP Watch** is the same idea for
  **Exim**: the `${...}` string expansion in a `MAIL FROM` / `RCPT TO` address
  (**CVE-2019-10149**, CISA KEV — raised to *payload queued* when the server itself answers
  2xx to the tainted recipient), a backslash or NUL in a TLS SNI or a TLS 1.2
  client-certificate DN (**CVE-2019-15846**), an EHLO/HELO line past the RFC 5321 512-octet cap — the
  `string_vformat` heap overflow (**CVE-2019-16928**), keyed on the non-conformant length
  rather than a proof-of-concept string — and an AUTH base64 token of length 4n+3, the
  `b64decode` over-consume (**CVE-2018-6789**, CISA KEV). All three rules are ungated and
  near-zero false-positive by construction, and Exim's three- and four-component version
  numbers are compared in full so a patched 4.90.1 is never read as 4.90.

- **Cleartext remote-login plane** — **Telnet Watch v5** extends the telnetd coverage to
  the **encrypt key-id heap overflow** (CVE-2011-4862, exploited in the wild 2011), the
  pre-auth **EC/EL NULL-dereference** and its inetd crash loop (CVE-2022-39028) and the
  Solaris `in.telnetd -f` twin (CVE-2007-0882), and adds the **r-services** on their own
  engines: the rlogin/rsh **`-froot`** injection (CVE-1999-0113), the **ftp-data
  source-port trust bounce** (CVE-1999-0185) and netkit **rcp** abuse by a malicious server
  (CVE-2019-7282 / CVE-2019-7283), plus rexec cleartext credentials and `.rhosts` trust —
  the same `login -f` auth-bypass shape traced across twenty-seven years of Unix remote login.

_(Counts reflect the detector code as of September 2026 and grow as new modules land.)_

### What makes these detections different

- **100% passive — detection-only.** Ragnar never transmits, probes, scans or authenticates.
  Every CVE above is caught by observing traffic that is already on the wire. In the
  standalone daemons this is enforced twice over: an AST guard that rejects any
  transmit-shaped call in the module itself, and the kernel
  (`RestrictAddressFamilies` + `IPAddressDeny=any`), so the process cannot open an IP socket
  even if the code were changed.
- **Structural anomaly bounds, not exploit signatures.** Thresholds are measured against real
  traffic rather than copied from a published proof-of-concept, so variants and evasion
  attempts are still caught — and several detections are zero-false-positive by construction
  (a labelled MPLS frame on a customer port simply should not exist).
- **Three honest evidence classes.** Every finding is *posture* (a version/platform
  fingerprint screened against the catalog — always "verify **this** device," never a
  vulnerable/not-vulnerable verdict), *exposure* (an enabling condition visible on the wire)
  or *attack* (an exploitation primitive observed in transit).
- **Runs on a Raspberry Pi Zero 2 W.** Everything is built to a resource floor that cheap,
  low-power hardware can sustain.
- **Privacy by design.** Credential material is never logged — for example, RADIUS
  Proxy-State is compared by digest and the values are discarded.

Every classifier is validated offline by the 42-suite **Detector Self-Test**, which runs each
detector against crafted attack captures with no root and no live traffic.

Thank you, Solarflere. 🙏
