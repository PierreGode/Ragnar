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
  060-069  zone transfer integrity (TSIG coverage across multi-message XFR)

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
        "cve": "CVE-2021-25220, CVE-2025-40778", "klass": "structural", "stateful": False,
        "desc": "Response carries an authority or additional record outside the queried zone's bailiwick, or an unsolicited RR the query never asked for -- cache-poisoning record injection",
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
        "cve": "CVE-2026-76163", "klass": "protocol-abuse", "stateful": False,
        "desc": "A query of QTYPE TKEY was observed. TKEY is legitimate for GSS-TSIG, so this reports an attack ATTEMPT against the BIND assertion failure, not a vulnerable resolver -- correlate with your own BIND version before acting",
    },

    # --- zone transfer integrity (060-069) ------------------------
    "DNSD-060": {
        "name": "XFR_TSIG_ABSENT_MULTIMESSAGE", "severity": "critical", "confidence": "high",
        "cve": "CVE-2026-19033", "klass": "transfer", "stateful": True,
        "desc": "A multi-message TCP zone transfer completed with unsigned intermediate messages and no final TSIG -- a secondary applying this has already served unrolled-back data (RFC 8945). Detects the COMPLETED attack, not an attempt",
    },
}

# Codes whose detector needs a LEARNED per-zone baseline before it can
# say anything. Gated at runtime (see state.py / detect.py) because
# Ragnar's grab-and-go deployment model cannot assume warmup time.
BASELINE_DEPENDENT = {"DNSD-020", "DNSD-021", "DNSD-022"}


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
                              "dnssec-integrity", "protocol-abuse", "transfer")
    assert BASELINE_DEPENDENT <= set(FINDINGS), "BASELINE_DEPENDENT names an unknown code"


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
