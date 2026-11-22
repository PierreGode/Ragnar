"""
Finding-code registry for DNS Doctor's PASSIVE tier.

Single source of truth for codes, names, severities and confidence
tiers. Every detector constructs findings through finding() rather
than hand-rolling a dict, so severity and confidence cannot drift
between call sites. readme_verify.py asserts the README's tables
stay in sync with this dict.

WHY A SEPARATE CODE PREFIX (DNSD- not DNS-): DNS Doctor's existing
ACTIVE tier owns DNS-001..DNS-102 -- probe-based checks that generate
their own queries. This tier is capture-based and transmits nothing.
Sharing a prefix would make "DNS-0xx" ambiguous about whether the
module spoke on the wire to produce it, which is exactly the property
an operator needs to know at a glance. Separate prefix, separate
registry, no collisions.

Code ranges by detector class:
  001-009  structural record analysis (KeyTrap, NXNSAttack, MaginotDNS,
           TuDoor, compression pointers, DNSKEY rdata)
  010-019  parameter / posture checks (NSEC3 iterations, algorithm downgrade)
  020-029  behavioural flood detection (DNSBomb, NSEC3 encloser, water torture)
  030-039  response integrity (SAD DNS)
  040-049  DNSSEC structural integrity (RRSIG labels, NSEC/NSEC3 chain)
  050-059  protocol abuse (SVCB alias fan-out, EDNS options, duplicate RRs, TKEY)
  060-069  zone transfer: TSIG coverage, completed-transfer disclosure,
           RFC 5936 / RFC 1995 structure, undefined transport
  070-079  mDNS (RFC 6762 / DNS-SD): Matter+Thread census and fingerprint,
           scope violations, commissioning-window posture
  080-089  DDNS (RFC 2136 opcode 5): dynamic-update posture
  090-099  rDNS (PTR): private reverse leak, ip6.arpa tree enumeration
  100-109  DNS-SD over unicast: service-type enumeration, PTR fan-out
  110-119  LLMNR (RFC 4795): deprecated-protocol posture, scope, WPAD
  120-129  NBNS / NBT-NS (RFC 1001/1002): posture, WPAD, NBSTAT recon
  130-139  encrypted-DNS transport (DoT/DoQ/DDR): resolver bypass
  140-149  TSIG / SIG(0) posture: weak algorithm, replay window
  150-159  SPF parser (libspf2): macro-expansion and compile-budget
           overflow shapes in TXT records

CONFIDENCE is separate from SEVERITY on purpose (LESSON T): severity
says how bad it would be if real, confidence says how sure the wire
evidence is. A LOW-confidence finding is never allowed to carry a
critical severity.
"""

# confidence -> the highest severity that confidence tier may carry.
# Enforced by _validate() at import time.
CONFIDENCE_SEVERITY_CAP = {
    "high":   "critical",
    "medium": "warning",
    "low":    "notice",
}

_SEVERITY_ORDER = {"notice": 0, "warning": 1, "critical": 2}

FINDINGS = {
    # --- structural record analysis -------------------------------
    "DNSD-001": {
        "name": "KEYTRAP_DNSKEY_COLLISION", "severity": "critical", "confidence": "high",
        "cve": "CVE-2023-50387, CVE-2026-19668", "klass": "structural", "stateful": False,
        "desc": "Multiple DNSKEY records share one key tag -- the KeyTrap colliding-key-tag signature, which forces a validator into quadratic signature verification",
    },
    "DNSD-002": {
        "name": "KEYTRAP_RRSIG_BURST", "severity": "critical", "confidence": "high",
        "cve": "CVE-2023-50387", "klass": "structural", "stateful": False,
        "desc": "One RRset carries an abnormal number of RRSIGs -- the other half of the KeyTrap work-amplification pair",
    },
    "DNSD-003": {
        "name": "KEYTRAP_CRYPTO_FAILURES", "severity": "critical", "confidence": "high",
        "cve": "CVE-2023-50387", "klass": "structural", "stateful": False,
        "desc": "DNSKEY and RRSIG counts together imply a validator must attempt an excessive number of signature verifications for one response",
    },
    "DNSD-004": {
        "name": "NXNSATTACK_DELEGATION_OVERFLOW", "severity": "warning", "confidence": "medium",
        "cve": "CVE-2020-8616", "klass": "structural", "stateful": False,
        "desc": "Referral carries many NS records with no glue, and the NS targets are out of bailiwick -- the NXNSAttack referral-amplification shape",
    },
    "DNSD-005": {
        "name": "NXNSATTACK_BURST_CORRELATION", "severity": "critical", "confidence": "high",
        "cve": "CVE-2020-8616", "klass": "structural", "stateful": True,
        "desc": "Several glueless out-of-bailiwick referrals for one zone inside a short window -- referral amplification in progress, not a single odd response",
    },
    "DNSD-006": {
        "name": "MAGINOTDNS_OUT_OF_BAILIWICK", "severity": "critical", "confidence": "high",
        "cve": "attack class: CVE-2021-25220, CVE-2025-40778", "klass": "structural", "stateful": False,
        "desc": "Response carries an authority or additional record outside the queried zone's bailiwick that is NOT accounted for by this response's own delegation glue or CNAME/DNAME chain -- cache-poisoning record injection. Records that ARE so accounted are reported as DNSD-170 instead. The cve field names the ATTACK CLASS this shape belongs to, not a claim that the responder is running a vulnerable build: this detector is purely structural and has no version awareness",
    },
    "DNSD-007": {
        "name": "TUDOOR_MALFORMED_PACKET", "severity": "notice", "confidence": "low",
        "cve": "TuDoor (CVE-2024 cluster)", "klass": "structural", "stateful": False,
        "desc": "DNS response is structurally malformed (truncated record, bad rdlength, illegal name encoding) -- informational; malformed responses are common on real networks",
    },

    # --- parameter / posture --------------------------------------
    "DNSD-010": {
        "name": "NSEC3_ITERATION_RFC_VIOLATION", "severity": "warning", "confidence": "high",
        "cve": "CVE-2023-50868", "klass": "posture", "stateful": False,
        "desc": "NSEC3 iteration count is above the RFC 9276 ceiling of 0 -- extra iterations are pure validator CPU cost with no security benefit",
    },
    "DNSD-011": {
        "name": "DNSSEC_ALGO_UNSUPPORTED", "severity": "warning", "confidence": "medium",
        "cve": None, "klass": "posture", "stateful": False,
        "desc": "Response is signed with a DNSSEC algorithm the validator cannot verify, AD is clear, and no SERVFAIL was returned -- a silent validation downgrade",
    },

    # --- behavioural flood (baseline-dependent) -------------------
    "DNSD-020": {
        "name": "DNSBOMB_SHORT_TTL_BURST", "severity": "warning", "confidence": "medium",
        "cve": "CVE-2024-33655", "klass": "behavioural", "stateful": True,
        "desc": "Short-TTL answers for one zone arriving far above that zone's learned rate -- the DNSBomb pulsing-amplification accumulation phase",
    },
    "DNSD-021": {
        "name": "NSEC3_ENCLOSER_ATTACK", "severity": "warning", "confidence": "medium",
        "cve": "CVE-2023-50868", "klass": "behavioural", "stateful": True,
        "desc": "High NSEC3 iteration count combined with many NSEC3 RRs per response and a random-subdomain query flood -- the closest-encloser CPU-exhaustion pattern",
    },
    "DNSD-022": {
        "name": "WATER_TORTURE_FLOOD", "severity": "warning", "confidence": "medium",
        "cve": None, "klass": "behavioural", "stateful": True,
        "desc": "Random-subdomain NXDOMAIN rate for one zone far above its learned baseline -- pseudo-random subdomain (water torture) attack",
    },

    # --- response integrity ---------------------------------------
    "DNSD-030": {
        "name": "SAD_DNS_DUPLICATE_CONFLICT", "severity": "critical", "confidence": "high",
        "cve": "CVE-2020-25705", "klass": "integrity", "stateful": True,
        "desc": "Two responses to one outstanding query carry conflicting answers -- a forged response raced the legitimate one",
    },
    "DNSD-031": {
        "name": "SAD_DNS_SOURCE_PORT_ENTROPY_LOW", "severity": "warning", "confidence": "medium",
        "cve": "CVE-2020-25705, CVE-2025-40780", "klass": "integrity", "stateful": True,
        "desc": "Outbound query source ports show low entropy -- port prediction is easier than it should be. Raised from low to medium: CVE-2025-40780 is a weak PRNG for BOTH source port and query ID, which makes observed low entropy evidence of a defective resolver rather than merely a tuning preference",
    },

    # --- structural, continued ------------------------------------
    "DNSD-008": {
        "name": "COMPRESSION_POINTER_ANOMALY", "severity": "critical", "confidence": "high",
        "cve": "CVE-2026-81642, CVE-2026-2291, CVE-2026-5172", "klass": "structural", "stateful": False,
        "desc": "A name compression pointer loops, points forward, or points into a resource record's RDATA -- the shape behind the Unbound DNSKEY-owner-pointer RCE and two dnsmasq extract_name/extract_addresses memory bugs",
    },
    "DNSD-009": {
        "name": "DNSKEY_MALFORMED", "severity": "critical", "confidence": "high",
        "cve": "CVE-2025-8677, CVE-2026-4890, CVE-2026-4891", "klass": "structural", "stateful": False,
        "desc": "DNSKEY rdata is structurally invalid (bad protocol byte, empty or truncated key, revoked-and-SEP contradiction) -- drives CPU exhaustion in BIND and an infinite loop plus a heap over-read in dnsmasq",
    },

    # --- DNSSEC structural integrity (040-049) --------------------
    "DNSD-040": {
        "name": "RRSIG_LABEL_COUNT_MISMATCH", "severity": "critical", "confidence": "high",
        "cve": "CVE-2026-11721, CVE-2026-52688", "klass": "dnssec-integrity", "stateful": False,
        "desc": "An RRSIG's labels field claims MORE labels than its owner name actually has, which RFC 4034 forbids -- a validator computing the signed name from it reads past the name",
    },
    "DNSD-041": {
        "name": "NSEC_NEXT_OUT_OF_ZONE", "severity": "critical", "confidence": "high",
        "cve": "CVE-2026-13321", "klass": "dnssec-integrity", "stateful": False,
        "desc": "An NSEC record's next-domain name points outside the zone it belongs to -- the NSEC chain is supposed to be closed within the zone, so this walks a validator out of it",
    },
    "DNSD-042": {
        "name": "NSEC3_APEX_HASH_IMPERSONATION", "severity": "warning", "confidence": "medium",
        "cve": "CVE-2026-10723", "klass": "dnssec-integrity", "stateful": False,
        "desc": "An NSEC3 record's owner name sits outside the queried zone, claiming to be an apex hash of a parent -- DNSSEC validation bypass by parent impersonation (CWE-345)",
    },
    "DNSD-043": {
        "name": "NSEC_NSEC3_COEXISTENCE", "severity": "warning", "confidence": "high",
        "cve": "CVE-2026-13204", "klass": "dnssec-integrity", "stateful": False,
        "desc": "One response carries both NSEC and NSEC3 denial records for the same zone while RRSIGs cover only one of the two types -- the unsigned half is attacker-substitutable",
    },

    "DNSD-044": {
        "name": "SIG_RDATA_ALLOC_WRAP", "severity": "critical", "confidence": "high",
        "cve": "CVE-2020-1350", "klass": "dnssec-integrity", "stateful": False,
        "desc": "A SIG or RRSIG record's uncompressed signer-name length plus 0x14 plus its signature length reaches 65536 or more -- SIGRed: Windows DNS truncates that sum to 16 bits, allocates the wrapped value and then memcpy's the full data into it",
    },

    # --- protocol abuse (050-059) ---------------------------------
    "DNSD-050": {
        "name": "SVCB_ALIASMODE_ABUSE", "severity": "warning", "confidence": "medium",
        "cve": "CVE-2026-81563, CVE-2026-81736", "klass": "protocol-abuse", "stateful": False,
        "desc": "An SVCB/HTTPS AliasMode record fans out to an excessive number of ServiceMode records in one response -- drives a qpcache leak and forces CPU on subsequent root queries",
    },
    "DNSD-051": {
        "name": "EDNS_OPTION_DUPLICATION", "severity": "warning", "confidence": "high",
        "cve": "CVE-2026-42944", "klass": "protocol-abuse", "stateful": False,
        "desc": "The EDNS0 OPT record repeats an option code (NSID, cookie or padding) that may appear at most once -- the duplication itself is the denial-of-service primitive",
    },
    "DNSD-052": {
        "name": "DUPLICATE_RR_FLOOD", "severity": "warning", "confidence": "medium",
        "cve": "CVE-2026-75029", "klass": "protocol-abuse", "stateful": False,
        "desc": "One response repeats identical SOA, CNAME or DNAME records many times -- each copy is stored separately and bloats the negative cache",
    },
    "DNSD-053": {
        "name": "TKEY_QUERY_ANOMALY", "severity": "warning", "confidence": "medium",
        "cve": "CVE-2026-76163, CVE-2020-8625, CVE-2021-25216", "klass": "protocol-abuse", "stateful": False,
        "desc": "A TKEY query was observed, or a TKEY record carries a structurally impossible SPNEGO token (a DER length claiming more bytes than the token holds) -- the second shape is the precondition for the BIND GSSAPI buffer overflow. Both are ATTEMPTS: neither the named.conf options block nor tkey-gssapi-keytab is visible from the wire, so correlate with your own BIND version and config",
    },

    "DNSD-054": {
        "name": "TSIG_RDATA_MALFORMED", "severity": "warning", "confidence": "high",
        "cve": "CVE-2020-8622", "klass": "protocol-abuse", "stateful": False,
        "desc": "A TSIG record's internal length fields contradict its rdlength (MAC size or other-data overruns, or trailing bytes remain) -- BIND asserts and exits while verifying a TSIG it could not fully read. No correct signer emits this shape",
    },

    # --- zone transfer integrity (060-069) ------------------------
    "DNSD-060": {
        "name": "XFR_TSIG_ABSENT_MULTIMESSAGE", "severity": "critical", "confidence": "high",
        "cve": "CVE-2026-19033", "klass": "transfer", "stateful": True,
        "desc": "A multi-message TCP zone transfer completed with unsigned intermediate messages and no final TSIG -- a secondary applying this has already served unrolled-back data (RFC 8945). Detects the COMPLETED attack, not an attempt",
    },

    "DNSD-061": {
        "name": "XFR_COMPLETED_TO_UNEXPECTED_CLIENT", "severity": "critical", "confidence": "high",
        "cve": None, "klass": "transfer", "stateful": True,
        "desc": "A zone transfer COMPLETED to a client outside the operator-supplied list of permitted secondaries -- the whole zone has already been handed over, so this reports a finished disclosure rather than an attempt. Requires that configuration and is silent without it",
    },
    "DNSD-062": {
        "name": "IXFR_SOA_OWNER_NOT_APEX", "severity": "warning", "confidence": "high",
        "cve": "CVE-2021-25214", "klass": "transfer", "stateful": False,
        "desc": "An IXFR stream carries an SOA record whose owner name is not the transferred zone's apex. Per ISC this makes the receiving BIND delete the zone's own SOA, and named then terminates on the next refresh query for that zone. IXFR legitimately contains MANY SOA records -- the RFC 1995 example has six -- so the owner name is the discriminator, never the count",
    },
    "DNSD-063": {
        "name": "AXFR_STRUCTURE_VIOLATION", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "transfer", "stateful": True,
        "desc": "An AXFR stream breaks RFC 5936 s2.2: an intermediate message carries an SOA, the first message does not begin with the zone's apex SOA, or an SOA owner is not the apex. AXFR-ONLY by construction -- RFC 1995 uses SOA records as IXFR delta markers, so applying this rule to IXFR would fire on every conforming incremental transfer",
    },
    "DNSD-064": {
        "name": "AXFR_OVER_UDP", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "transfer", "stateful": False,
        "desc": "An AXFR query arrived over UDP. RFC 5936 s4.2: 'AXFR sessions over UDP transport are not defined' -- no conforming client sends this, and it is the shape of a reconnaissance or amplification probe. AXFR-ONLY: RFC 1995 s2 explicitly PERMITS IXFR over UDP, so including IXFR here would report conforming traffic",
    },

    # --- mDNS tier (070-079) --------------------------------------
    # Two legs, deliberately separate concerns:
    #   census   (070-073) -- what Matter/Thread exists on this LAN
    #   scope    (074-076) -- RFC 6762 transport-rule violations
    #
    # BOUNDARY WITH smbwatch: smbwatch already owns LLMNR/NBT-NS/mDNS
    # name POISONING (Responder/Inveigh). This tier never judges
    # whether an mDNS answer is legitimate -- only whether it is
    # in scope, and what services exist. Both modules see the same
    # packets; only one reports spoofing, so there is no double report.
    "DNSD-070": {
        "name": "MDNS_MATTER_NODE", "severity": "notice", "confidence": "high",
        "cve": None, "klass": "mdns", "stateful": True,
        "desc": "A Matter operational node is present on this LAN (DNS-SD _matter._tcp). Census only -- never an alarm; Ragnar otherwise has no visibility that Matter exists at all",
    },
    "DNSD-071": {
        "name": "MDNS_MATTER_COMMISSIONABLE", "severity": "notice", "confidence": "high",
        "cve": None, "klass": "mdns", "stateful": True,
        "desc": "A Matter device is advertising itself as commissionable (_matterc._udp) -- it is in setup mode and open to pairing right now, which is a transient window rather than a steady state",
    },
    "DNSD-072": {
        "name": "MDNS_MATTER_COMMISSIONER", "severity": "notice", "confidence": "high",
        "cve": None, "klass": "mdns", "stateful": True,
        "desc": "A Matter commissioner (_matterd._udp) is present -- a controller or hub capable of onboarding devices onto the fabric",
    },
    "DNSD-073": {
        "name": "MDNS_THREAD_BORDER_ROUTER", "severity": "notice", "confidence": "high",
        "cve": None, "klass": "mdns", "stateful": True,
        "desc": "A Thread border router is advertising _meshcop._udp -- wired evidence of a Thread mesh behind it, visible on the IP side without any 802.15.4 radio",
    },
    "DNSD-074": {
        "name": "MDNS_TTL_SCOPE_VIOLATION", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "mdns", "stateful": False,
        "desc": "An mDNS packet arrived with IP TTL / hop limit other than 255, which RFC 6762 s11 forbids -- it either crossed a router or was not generated as link-local traffic. The config-free leg of the VU#550620 scope-violation family",
    },
    "DNSD-075": {
        "name": "MDNS_OFF_LINK_SOURCE", "severity": "warning", "confidence": "high",
        "cve": "CVE-2015-2809, CVE-2017-6520, CVE-2015-1892", "klass": "mdns", "stateful": False,
        "desc": "An mDNS packet arrived from a source outside the configured local prefixes -- mDNS is link-local by definition, so an off-link source means the service is reachable beyond its intended scope",
    },
    "DNSD-076": {
        "name": "MDNS_OFF_LINK_UNICAST_RESPONSE", "severity": "critical", "confidence": "high",
        "cve": "CVE-2015-2809, CVE-2017-6520, CVE-2015-1892", "klass": "mdns", "stateful": False,
        "desc": "An mDNS responder answered to an off-link unicast destination (CERT VU#550620) -- it is an open reflector: DDoS amplification fuel and an information leak of every service it advertises",
    },

    "DNSD-077": {
        "name": "MDNS_MATTER_COMMISSIONING_WINDOW_OPEN", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "mdns", "stateful": True,
        "desc": "A Matter device's own TXT record reports a non-zero CM (commissioning mode) -- it states that its pairing window is open right now, so anything on this link can attempt to commission it. Stronger than DNSD-071, which only infers setup mode from the service type being advertised at all",
    },
    "DNSD-078": {
        "name": "MDNS_THREAD_BORDER_AGENT_EPHEMERAL", "severity": "notice", "confidence": "high",
        "cve": None, "klass": "mdns", "stateful": True,
        "desc": "A Thread border agent is advertising the ephemeral-key commissioning service (_meshcop-e._udp) -- an epskc endpoint alongside the ordinary PSKc one. Census only: reported as presence because this tier could not establish from the wire whether the endpoint is advertised continuously or only while a session is live",
    },
    "DNSD-079": {
        "name": "MDNS_ZWAVE_ZIP_PRESENT", "severity": "notice", "confidence": "high",
        "cve": None, "klass": "mdns", "stateful": True,
        "desc": "A Z-Wave Z/IP Gateway is advertising _z-wave._udp on this LAN. Silicon Labs' Z/IP Gateway announces every Z-Wave node and endpoint over mDNS (IANA registers the service on UDP 4123, DTLS on 41230), so the announcement is wired evidence of a Z-Wave mesh behind the gateway, visible on the IP side without any 800-900 MHz radio. Carries a fingerprint from the announcement: device type, home ID, endpoint, product ID and security-class hex. It does NOT carry a user-set device name -- Z-Wave node names live in the controller inside the encrypted Z/IP tunnel (DTLS 41230), not on the wire. Census only -- never an alarm; like the Matter and Thread census codes, it reports presence rather than a vulnerability",
    },

    # --- DDNS tier (080-089) --------------------------------------
    # RFC 2136 UPDATE, opcode 5. Both posture codes report an OUTCOME
    # read off the server's own answer, not an attempt: "someone tried
    # an unsigned update" is noise, "the server accepted one" is a
    # vulnerable zone. That is why both are high confidence.
    #
    # OPCODE ROUTING: an UPDATE reuses all four section counts with
    # different meanings, so UPDATE messages are routed away from the
    # QUERY detectors exactly as mDNS is routed away by port. See
    # engine.handle_frame.
    "DNSD-080": {
        "name": "DDNS_UNSIGNED_UPDATE_ACCEPTED", "severity": "critical", "confidence": "high",
        "cve": None, "klass": "ddns", "stateful": True,
        "desc": "An RFC 2136 UPDATE carrying no TSIG and no SIG(0) was answered NOERROR, so the zone accepts unauthenticated dynamic updates. An IP-address ACL produces exactly this and is itself the finding: a UDP source address is forgeable, so the zone is writable by anyone who can spoof one",
    },
    "DNSD-081": {
        "name": "DDNS_TSIG_BYPASS_ACCEPTED", "severity": "critical", "confidence": "high",
        "cve": "CVE-2017-3143", "klass": "ddns", "stateful": True,
        "desc": "A dynamic update was answered NOERROR while the TSIG in the exchange reports BADSIG/BADKEY/BADTIME, or carries an empty or illegally truncated MAC -- signature verification did not succeed and the update was applied anyway. A completed authentication bypass, not an attempt",
    },
    "DNSD-082": {
        "name": "DDNS_UPDATE_FROM_UNEXPECTED_SOURCE", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "ddns", "stateful": False,
        "desc": "A dynamic update arrived from a source outside the operator-supplied list of permitted updater prefixes. Requires that configuration and is silent without it -- a learned allowlist would arm itself from whatever the sensor happened to see first",
    },

    # --- rDNS tier (090-099) --------------------------------------
    "DNSD-090": {
        "name": "PTR_PRIVATE_LEAK", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "rdns", "stateful": False,
        "desc": "A reverse lookup for RFC 1918, CGNAT 100.64/10, link-local, ULA fd00::/8 or fe80::/10 space was addressed to a resolver outside the configured internal prefixes -- internal topology leaking to the public DNS (and to the AS112 sinks that answer it)",
    },
    "DNSD-091": {
        "name": "IP6_ARPA_WALK", "severity": "warning", "confidence": "medium",
        "cve": None, "klass": "rdns", "stateful": True,
        "desc": "One source issued many distinct ip6.arpa queries sharing a long leading nibble prefix inside one window -- reverse-tree enumeration, which turns RFC 8020's NXDOMAIN-versus-empty-non-terminal distinction into an IPv6 host-discovery oracle. The common-prefix requirement is what separates it from bulk reverse lookups",
    },

    # --- DNS-SD over unicast (100-109) ----------------------------
    "DNSD-100": {
        "name": "DNSSD_SERVICE_ENUMERATION", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "dns-sd", "stateful": True,
        "desc": "A PTR query for _services._dns-sd._udp against a real zone over unicast DNS (RFC 6763 s9) -- this enumerates EVERY service type published in that zone in one question. Restricted to unicast: the same query on .local is ordinary Bonjour browsing that any laptop does on joining a network",
    },
    "DNSD-101": {
        "name": "DNSSD_PTR_FANOUT", "severity": "warning", "confidence": "medium",
        "cve": None, "klass": "dns-sd", "stateful": False,
        "desc": "One DNS-SD PTR response enumerates an excessive number of service instances -- both an amplification vector (a small question, a large answer) and the shape of a successful enumeration being answered",
    },

    # --- LLMNR (110-119) ------------------------------------------
    # NO CVE TIER. The LLMNR weaknesses that matter are protocol
    # DESIGN, not implementation bugs, and a CVE search turned up no
    # qualifying LLMNR-specific set. Posture only -- same honest
    # verdict as the rDNS leg.
    #
    # BOUNDARY WITH smbwatch: smbwatch owns LLMNR/NBT-NS name
    # POISONING (Responder/Inveigh). This tier never judges whether an
    # LLMNR answer is legitimate -- only that the protocol is in use,
    # that transport rules were broken, and what is being asked for.
    "DNSD-110": {
        "name": "LLMNR_IN_USE", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "llmnr", "stateful": True,
        "desc": "LLMNR traffic was observed on UDP/TCP 5355. LLMNR has no authentication by design and Microsoft recommends disabling it, so its presence is attack surface with no legitimate requirement on a managed network -- the finding is that it is on at all, not that any one packet is bad",
    },
    "DNSD-111": {
        "name": "LLMNR_WRONG_MULTICAST_GROUP", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "llmnr", "stateful": False,
        "desc": "An LLMNR query arrived addressed to a multicast group other than 224.0.0.252 or ff02::1:3, which RFC 4795 s2 says a responder MUST silently discard -- a conforming sender never produces this, so it is a malformed stack or an attempt to reach responders that do not check",
    },
    "DNSD-112": {
        "name": "LLMNR_WPAD_QUERY", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "llmnr", "stateful": True,
        "desc": "A host asked for WPAD over LLMNR, so it is configured to accept a web-proxy configuration from whoever answers first on the link. The vulnerable state is the query, which this sees; the poisoned answer is smbwatch's half",
    },

    # --- NBNS / NBT-NS (120-129) ----------------------------------
    "DNSD-120": {
        "name": "NBNS_IN_USE", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "nbns", "stateful": True,
        "desc": "NetBIOS Name Service traffic was observed on UDP 137. NBT-NS is older and more thoroughly deprecated than LLMNR, unauthenticated by design, and present on a modern network only through legacy configuration",
    },
    "DNSD-121": {
        "name": "NBNS_WPAD_QUERY", "severity": "warning", "confidence": "high",
        "cve": "CVE-2016-3213, CVE-2016-3236", "klass": "nbns", "stateful": True,
        "desc": "A host asked for the WPAD name over NBNS. This is the precondition for the MS16-077 WPAD fallback flaw (CVE-2016-3213, CVSS 8.8), which is exploited 'via NetBIOS name responses' -- a host still emitting this query will take its proxy configuration from the first responder on the link",
    },
    "DNSD-122": {
        "name": "NBNS_NBSTAT_ENUMERATION", "severity": "warning", "confidence": "medium",
        "cve": None, "klass": "nbns", "stateful": True,
        "desc": "Repeated NBSTAT (node status) queries from one source -- NBSTAT returns a host's full NetBIOS name table and its MAC address, so a sweep of them is host and domain-role enumeration",
    },

    # --- encrypted-DNS transport (130-139) ------------------------
    # The README previously called DoT/DoH an honest zero, and half of
    # that stands: nothing INSIDE an encrypted transport is parseable
    # and never will be. What is detectable is the transport itself,
    # which is a different and genuinely operational question for
    # anyone running their own resolvers -- these bypass the logging,
    # RPZ and filtering that resolver provides.
    "DNSD-130": {
        "name": "DNS_OVER_TLS_OBSERVED", "severity": "notice", "confidence": "high",
        "cve": None, "klass": "encrypted-transport", "stateful": True,
        "desc": "A DNS-over-TLS session (TCP 853, RFC 7858) was observed. Census only: reported once per client/server pair, with whether the server sits inside the configured own-resolver prefixes, because DoT to your own resolver is good practice and DoT past it is a bypass",
    },
    "DNSD-131": {
        "name": "DNS_OVER_QUIC_OBSERVED", "severity": "notice", "confidence": "high",
        "cve": None, "klass": "encrypted-transport", "stateful": True,
        "desc": "A DNS-over-QUIC session (UDP 853, RFC 9250) was observed, confirmed by a QUIC long header rather than by port alone. Census only, same reasoning as DoT",
    },
    "DNSD-132": {
        "name": "ENCRYPTED_DNS_DISCOVERY", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "encrypted-transport", "stateful": True,
        "desc": "A client issued an SVCB query for a DDR/DNR discovery name (RFC 9462 _dns.resolver.arpa, or RFC 9463 _dns.<resolver>) -- it is probing to upgrade itself off cleartext DNS. Visible here because the probe itself travels in cleartext on port 53",
    },
    "DNSD-133": {
        "name": "DOH_ENDPOINT_RESOLUTION", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "encrypted-transport", "stateful": True,
        "desc": "A cleartext query resolved the hostname of a known public DoH resolver -- the step that precedes an encrypted session this sensor will not be able to read. Carries a correlation record (client, hostname, answer addresses) for tlswatch to join a later TLS session against, because DoH on 443 is identifiable only from the SNI and this module does not parse TLS",
    },

    # --- TSIG / SIG(0) posture (140-149) --------------------------
    "DNSD-140": {
        "name": "TSIG_WEAK_ALGORITHM", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "tsig-posture", "stateful": False,
        "desc": "A TSIG used hmac-md5 or hmac-sha1, both deprecated for new deployments by RFC 8945 s5.2. The key itself is unobservable, so this reports the algorithm in use and nothing about the key's strength",
    },
    "DNSD-141": {
        "name": "TSIG_EXCESSIVE_FUDGE", "severity": "warning", "confidence": "high",
        "cve": None, "klass": "tsig-posture", "stateful": False,
        "desc": "A TSIG's fudge field is far above the 300 seconds RFC 8945 s5.2.1 recommends -- the fudge IS the replay window, so a large one means a captured signed message stays replayable for that long",
    },
    "DNSD-142": {
        "name": "SIG0_IN_USE", "severity": "notice", "confidence": "high",
        "cve": None, "klass": "tsig-posture", "stateful": True,
        "desc": "A SIG(0) transaction signature was observed (RFC 2931). SIG(0) was largely abandoned in favour of TSIG and brings public-key management into the transaction path; its presence is worth knowing about rather than alarming over",
    },

    # --- SPF parser / libspf2 (150-159) ---------------------------
    # Four CVEs, all reached by feeding libspf2 a crafted record -- and
    # an SPF record is a DNS TXT record, so the artifact travels in
    # cleartext DNS where this module already looks.
    #
    # THE TWO PAIRS HAVE DIFFERENT EVIDENCE CEILINGS, and the
    # severities say so. For the expansion bugs (150, 151) the record
    # supplies the macro SYNTAX but the mail transaction supplies the
    # expanded VALUE -- sender, HELO, client IP -- which a DNS tap
    # never sees. So those report a record that can REACH the
    # vulnerable path. For the compile bugs (152, 153) the record IS
    # the whole attack: a 500-byte literal and 127 macros in one term
    # are not things a legitimate record contains.
    "DNSD-150": {
        "name": "SPF_MACRO_URLENCODE_SPRINTF", "severity": "warning", "confidence": "high",
        "cve": "CVE-2021-33912", "klass": "spf-parser", "stateful": True,
        "desc": "An SPF record uses an UPPERCASE macro letter, which RFC 7208 s7.1 URL-escapes -- the libspf2 block whose sprintf printed eight hex digits for any byte above 0x7f because *p_read was a signed char, writing ten bytes where four were budgeted. Reports a record that can reach the path; the high byte itself comes from the mail transaction, which a DNS tap does not see",
    },
    "DNSD-151": {
        "name": "SPF_MACRO_REVERSE_URLENCODE", "severity": "warning", "confidence": "high",
        "cve": "CVE-2021-33913", "klass": "spf-parser", "stateful": True,
        "desc": "An SPF record combines an UPPERCASE macro letter with the 'r' reverse transformer -- e.g. %{Dr}. libspf2's reversal block overwrote the length variable with a single LABEL's length, which then sized the URL-encode allocation for the entire reversed string. Strictly worse than DNSD-150: the allocation is undersized rather than overrun by four bytes",
    },
    "DNSD-152": {
        "name": "SPF_EXP_LITERAL_STACK_OVERFLOW", "severity": "critical", "confidence": "high",
        "cve": "CVE-2021-20314", "klass": "spf-parser", "stateful": True,
        "desc": "A TXT record named by an observed SPF exp= modifier carries a string literal long enough to fill libspf2's 511-byte compile budget, split across multiple TXT strings. SPF_INIT_STRING_LITERAL never subtracted the 4-byte SPF_data_t header it had just written, so the literal overflows the stack buffer by exactly four bytes. The split is not incidental -- one TXT string caps at 255 bytes, so reaching 511 requires several",
    },
    "DNSD-153": {
        "name": "SPF_MACRO_BUDGET_UNDERFLOW", "severity": "critical", "confidence": "high",
        "cve": "CVE-2023-42118", "klass": "spf-parser", "stateful": True,
        "desc": "An SPF term carries enough macro variables to leave libspf2's compile budget between 0 and 3 bytes when the next string literal is initialised. The 2021 fix subtracted sizeof(SPF_data_t) from an unsigned count with no floor, so that subtraction UNDERFLOWS to roughly SIZE_MAX and every later bounds check passes. A regression of the CVE-2021-20314 fix, in the same macro in the same function",
    },

    # ---------------- 170-179: structural, continued ----------------
    # The 001-009 structural block is full. This is structural work
    # that arrived later, not a new class.
    "DNSD-170": {
        "name": "OUT_OF_BAILIWICK_ACCOUNTED", "severity": "notice",
        "confidence": "high", "cve": None, "klass": "structural",
        "stateful": False,
        "desc": "A record outside the queried zone's bailiwick that THIS response's own structure explains: either A/AAAA glue in the additional section whose owner is the target of an anchored NS record, or a record owned by a CNAME/DNAME chain target (or an NS/SOA for an ancestor of one). Reverse DNS at an ISP produces these constantly -- referral glue for out-of-zone NS targets, and RFC 2317 / CNAME chains into customer domains -- and they are normal operation rather than injection. Reported rather than silently dropped so the record stays visible and the count stays auditable; the classification decision is made from the single packet, with no cross-packet state",
    },

    # ---------------- 160-169: TCP stream reassembly ----------------
    # Reassembly is plumbing, not a detector, so it gets exactly one
    # code: the case where the plumbing is being attacked.
    "DNSD-160": {
        "name": "TCP_SEGMENT_OVERLAP_MISMATCH", "severity": "warning",
        "confidence": "high", "cve": None, "klass": "tcp-reassembly",
        "stateful": True,
        "desc": "Two TCP segments on the same DNS stream covered the same sequence range with DIFFERENT bytes. Reassembly keeps the first copy, so this reports the attempt rather than being fooled by it. The technique is Ptacek and Newsham's: a resolver that resolves overlap last-wins and a sensor that resolves it first-wins end up parsing different DNS messages from one stream, which is how an attacker makes a passive tap see something other than what the resolver acted on. Healthy stacks never retransmit different payload bytes for a sequence range, so the benign explanations are a rewriting middlebox or a broken stack -- both worth knowing about",
    },
}

# Codes whose detector needs a LEARNED per-zone baseline before it can
# say anything. Gated at runtime (see state.py / detect.py) because
# Ragnar's grab-and-go deployment model cannot assume warmup time.
BASELINE_DEPENDENT = {"DNSD-020", "DNSD-021", "DNSD-022"}

# Census codes report the EXISTENCE of something, so they are emitted
# once per (service, instance) and then suppressed. mDNS hosts
# re-announce constantly -- without this the census would emit on
# every announcement packet and drown the feed it is meant to inform.
CENSUS_CODES = {"DNSD-070", "DNSD-071", "DNSD-072", "DNSD-073", "DNSD-078",
                "DNSD-079",
                "DNSD-130", "DNSD-131", "DNSD-142"}

# Codes suppressed per instance like the census, but which are NOT
# census codes -- so they may carry a severity above notice. The
# distinction matters: CENSUS_CODES is the set the README promises is
# "never an alarm", and DNSD-077 is an alarm. Its key includes the CM
# value, so a window opening and closing re-reports once per state
# change rather than once per announcement packet.
INSTANCE_SUPPRESSED = {"DNSD-077", "DNSD-110", "DNSD-112", "DNSD-120",
                       "DNSD-121", "DNSD-122", "DNSD-100", "DNSD-132", "DNSD-133",
                       "DNSD-150", "DNSD-151", "DNSD-152", "DNSD-153"}

# The two scope codes that cannot run without operator-supplied local
# prefixes. Named here so the engine can report them as disabled
# rather than silently never firing.
PREFIX_DEPENDENT = {"DNSD-061", "DNSD-075", "DNSD-076", "DNSD-082", "DNSD-090"}

# Which config key each prefix-dependent code waits on. They are NOT
# the same key: an mDNS local prefix is "this link", a DDNS updater
# prefix is "hosts allowed to write my zones", and an rDNS internal
# prefix is "my organisation's resolvers". Collapsing them into one
# list would make each check wrong in the other two's terms.
PREFIX_CONFIG_KEY = {
    "DNSD-061": "xfr_allowed_secondary_prefixes",
    "DNSD-075": "mdns_local_prefixes",
    "DNSD-076": "mdns_local_prefixes",
    "DNSD-082": "ddns_allowed_updater_prefixes",
    "DNSD-090": "rdns_internal_prefixes",
}


def _validate():
    """Import-time structural guard. A registry that contradicts its
    own confidence/severity contract is a bug that should never reach
    a test tier, let alone the wire."""
    seen_names = set()
    for code, m in FINDINGS.items():
        assert m["severity"] in _SEVERITY_ORDER, f"{code}: bad severity"
        assert m["confidence"] in CONFIDENCE_SEVERITY_CAP, f"{code}: bad confidence"
        cap = CONFIDENCE_SEVERITY_CAP[m["confidence"]]
        assert _SEVERITY_ORDER[m["severity"]] <= _SEVERITY_ORDER[cap], (
            f"{code}: confidence '{m['confidence']}' caps severity at '{cap}' "
            f"but the registry says '{m['severity']}' (LESSON T)"
        )
        assert m["name"] not in seen_names, f"{code}: duplicate name {m['name']}"
        seen_names.add(m["name"])
        assert m["klass"] in ("structural", "posture", "behavioural", "integrity",
                              "dnssec-integrity", "protocol-abuse", "transfer", "mdns",
                              "ddns", "rdns", "dns-sd", "llmnr", "nbns",
                              "encrypted-transport", "tsig-posture",
                              "spf-parser", "tcp-reassembly")
    assert BASELINE_DEPENDENT <= set(FINDINGS), "BASELINE_DEPENDENT names an unknown code"
    assert PREFIX_DEPENDENT <= set(FINDINGS), "PREFIX_DEPENDENT names an unknown code"
    assert CENSUS_CODES <= set(FINDINGS), "CENSUS_CODES names an unknown code"
    assert INSTANCE_SUPPRESSED <= set(FINDINGS), "INSTANCE_SUPPRESSED names an unknown code"
    assert not (CENSUS_CODES & INSTANCE_SUPPRESSED), (
        "a code cannot be both a census code and an instance-suppressed alarm: "
        "CENSUS_CODES is the set documented as never being an alarm")
    for _c in CENSUS_CODES:
        assert FINDINGS[_c]["severity"] == "notice", (
            f"{_c} is a census code, so it must carry notice severity -- the README "
            f"promises the census is never an alarm")
    assert set(PREFIX_CONFIG_KEY) == PREFIX_DEPENDENT, (
        "every prefix-dependent code must name the config key it waits on, "
        "or the engine cannot report it as disabled rather than silently dead")


_validate()


def finding(code, zone, detail, evidence=None):
    """Build a standard finding. `evidence` carries the raw numbers an
    operator needs to judge it (DNSKEY count, iteration value, baseline
    ratio) -- the FP-mitigation strategy is that every MEDIUM/HIGH
    finding is reviewable without going back to the pcap."""
    if code not in FINDINGS:
        raise KeyError(f"unknown finding code: {code}")
    m = FINDINGS[code]
    return {
        "code": code,
        "name": m["name"],
        "severity": m["severity"],
        "confidence": m["confidence"],
        "klass": m["klass"],
        "cve": m["cve"],
        "zone": zone,
        "detail": detail,
        "evidence": evidence or {},
    }
