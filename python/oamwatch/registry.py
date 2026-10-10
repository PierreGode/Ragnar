"""oamwatch finding registry.

Three classes, no version-screening class.

  POSTURE    (OAM-02x) - capability advertisements that are preconditions for
                         the abuse primitives. NOTE discipline: never a
                         vuln/not verdict. There is deliberately NO
                         "OAM is enabled" finding - that visibility is by
                         design and is not a finding (lldpwatch directive).
  STRUCTURAL (OAM-04x/05x) - spec-grammar and bounds violations. The spine.
                         Pathognomonic, no baseline, day-1.
  ABUSE      (OAM-06x/07x) - attack-in-flight on a cleartext unauthenticated
                         plane. Session-state dependent but NOT operator
                         baseline dependent: the state machine is learned from
                         the link itself within one discovery exchange.

802.3ah Link OAM has NO CVE backbone at the CVSS 6.5 bar. Every code here is
protocol-abuse-on-the-wire (the IGMP/SNTP/ICMP lineage), not CVE attribution.
Do not add a per-CVE attribution layer; there is nothing to attribute to.
"""

INFO = "INFO"
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"

SEVERITY_ORDER = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}

POSTURE = "posture"
STRUCTURAL = "structural"
ABUSE = "abuse"

# code -> (short name, class, severity, one-line summary)
REGISTRY = {
    # ---- POSTURE (OAM-02x) -------------------------------------------------
    "OAM-020": ("OAM_LOOPBACK_SUPPORTED", POSTURE, LOW,
                "Peer advertises remote-loopback support; precondition for the "
                "Loopback Control link-blackhole primitive."),
    "OAM-021": ("OAM_VARIABLE_RETRIEVAL_SUPPORTED", POSTURE, LOW,
                "Peer advertises Variable Retrieval; unauthenticated cleartext "
                "Clause 30 MIB read surface on the link."),
    "OAM-022": ("OAM_ACTIVE_MODE_PEER", POSTURE, INFO,
                "Peer is in OAM active mode; active peers may initiate loopback "
                "and variable requests. Passive peers may not."),
    "OAM-023": ("OAM_UNIDIRECTIONAL_SUPPORTED", POSTURE, INFO,
                "Peer advertises unidirectional operation; OAMPDUs may be sent "
                "on a link with one direction failed."),
    "OAM-024": ("OAM_PDU_SIZE_NONSTANDARD", POSTURE, LOW,
                "Advertised maximum OAMPDU size is outside the 64..1518 octet "
                "range the standard permits."),

    # ---- STRUCTURAL (OAM-04x / OAM-05x) ------------------------------------
    "OAM-040": ("TLV_LENGTH_OVERRUN", STRUCTURAL, HIGH,
                "Declared TLV length exceeds the octets remaining in the OAMPDU."),
    "OAM-041": ("TLV_LENGTH_UNDERFLOW", STRUCTURAL, HIGH,
                "TLV declares a length below the minimum its type can occupy."),
    "OAM-042": ("INFO_TLV_BAD_LENGTH", STRUCTURAL, HIGH,
                "Local/Remote Information TLV length is not the fixed 0x10 "
                "octets the standard defines."),
    "OAM-043": ("TRUNCATED_OAMPDU", STRUCTURAL, HIGH,
                "OAMPDU is shorter than the minimum its Code requires."),
    "OAM-044": ("RESERVED_CODE", STRUCTURAL, MEDIUM,
                "OAMPDU Code is in a reserved range (0x05-0xFD or 0xFF)."),
    "OAM-045": ("RESERVED_FLAG_BITS_SET", STRUCTURAL, MEDIUM,
                "Reserved Flags bits (7..15) are set; standard requires "
                "transmit-as-zero."),
    "OAM-046": ("EVENT_TLV_BAD_LENGTH", STRUCTURAL, HIGH,
                "Event TLV length does not match the fixed length the standard "
                "defines for that event type."),
    "OAM-047": ("RESERVED_TLV_TYPE", STRUCTURAL, MEDIUM,
                "TLV type is not defined for this OAMPDU Code."),
    "OAM-048": ("TRAILING_DATA_AFTER_END_TLV", STRUCTURAL, MEDIUM,
                "Non-zero octets follow the End-of-TLV marker; data smuggling "
                "in the pad region."),
    "OAM-049": ("INFO_REMOTE_WITHOUT_LOCAL_TLV", STRUCTURAL, MEDIUM,
                "Information OAMPDU carries a Remote Information TLV with no "
                "Local Information TLV; ill-formed grammar."),
    "OAM-050": ("ILLEGAL_PARSER_MUX_STATE", STRUCTURAL, MEDIUM,
                "Information TLV State field uses a reserved Parser or "
                "Multiplexer action encoding."),
    "OAM-051": ("LOOPBACK_CMD_ILLEGAL", STRUCTURAL, HIGH,
                "Loopback Control command octet is not exactly enable (0x01) or "
                "disable (0x02)."),
    "OAM-052": ("VAR_DESCRIPTOR_MALFORMED", STRUCTURAL, MEDIUM,
                "Variable Request descriptor is truncated or uses an undefined "
                "Clause 30 branch."),
    "OAM-053": ("VAR_CONTAINER_MALFORMED", STRUCTURAL, HIGH,
                "Variable Response container width overruns the OAMPDU or uses "
                "an undefined width encoding."),
    "OAM-054": ("OAM_VERSION_ILLEGAL", STRUCTURAL, LOW,
                "Information TLV OAM Version is not 0x01."),
    "OAM-055": ("OVERSIZED_OAMPDU", STRUCTURAL, MEDIUM,
                "Frame exceeds the 1518-octet maximum an OAMPDU may occupy."),
    "OAM-056": ("ORG_SPECIFIC_TLV_MALFORMED", STRUCTURAL, MEDIUM,
                "Organization-Specific TLV (0xFE) is too short to carry its "
                "3-octet OUI, or overruns the OAMPDU."),
    "OAM-057": ("DUPLICATE_INFO_TLV", STRUCTURAL, MEDIUM,
                "More than one Local or more than one Remote Information TLV in "
                "a single Information OAMPDU."),

    # ---- ABUSE (OAM-06x / OAM-07x) -----------------------------------------
    "OAM-060": ("LOOPBACK_CONTROL_ENABLE", ABUSE, CRITICAL,
                "Loopback Control enable observed. A diagnostic PDU that should "
                "not exist in steady state; puts the peer into remote loopback "
                "and sends its higher-layer egress to DISCARD - an instant link "
                "blackhole."),
    "OAM-061": ("LOOPBACK_CONTROL_DISABLE", ABUSE, MEDIUM,
                "Loopback Control disable observed; completes or conceals a "
                "loopback cycle."),
    "OAM-062": ("REMOTE_LOOPBACK_STATE_ENTERED", ABUSE, CRITICAL,
                "Peer's Information TLV State reports parser=loopback or "
                "multiplexer=discard: confirmation the blackhole took effect."),
    "OAM-063": ("DYING_GASP_ASSERTED", ABUSE, HIGH,
                "Dying Gasp flag asserted; declares imminent unrecoverable "
                "failure and can drive an upstream protection switch."),
    "OAM-064": ("CRITICAL_EVENT_ASSERTED", ABUSE, HIGH,
                "Critical Event flag asserted; unspecified critical condition "
                "that can drive a protection switch."),
    "OAM-065": ("LINK_FAULT_ASSERTED", ABUSE, MEDIUM,
                "Link Fault flag asserted; receive path declared failed."),
    "OAM-066": ("FAILURE_FLAG_FLAPPING", ABUSE, CRITICAL,
                "A failure flag was asserted and cleared repeatedly while the "
                "OAM session stayed up. A genuine Dying Gasp means the peer lost "
                "power; a peer that keeps chattering did not die."),
    "OAM-067": ("DISCOVERY_RESTART", ABUSE, HIGH,
                "Established OAM session dropped back to discovery (stable bits "
                "cleared) without the link going down; unauthenticated "
                "re-peering."),
    "OAM-068": ("PEER_IDENTITY_CHANGE", ABUSE, CRITICAL,
                "The OAM peer's source MAC, OUI or vendor-specific identity "
                "changed on a point-to-point link; peer substitution."),
    "OAM-069": ("CAPABILITY_CHANGE", ABUSE, HIGH,
                "Peer's OAM Configuration byte changed mid-session; false or "
                "escalating capability advertisement."),
    "OAM-070": ("OAMPDU_RATE_EXCEEDED", ABUSE, HIGH,
                "OAMPDU rate exceeded the 10 frames/second the standard caps "
                "the slow-protocol plane at. The cap is itself the signature."),
    "OAM-071": ("VARIABLE_REQUEST_OBSERVED", ABUSE, MEDIUM,
                "Unauthenticated Clause 30 MIB read in flight on the link."),
    "OAM-072": ("VARIABLE_RESPONSE_LEAK", ABUSE, HIGH,
                "Clause 30 MIB contents returned in cleartext on the wire."),
    "OAM-073": ("EVENT_SEQUENCE_ANOMALY", ABUSE, MEDIUM,
                "Event Notification sequence number regressed or repeated; "
                "replayed or forged link-event telemetry."),
    "OAM-074": ("MULTIPLE_PEERS_ON_LINK", ABUSE, CRITICAL,
                "More than one OAM source MAC seen on the segment. Link OAM is "
                "strictly point-to-point; a second speaker is an injector."),
}

CODES = tuple(sorted(REGISTRY))


def name_of(code):
    return REGISTRY[code][0]


def class_of(code):
    return REGISTRY[code][1]


def severity_of(code):
    return REGISTRY[code][2]


def summary_of(code):
    return REGISTRY[code][3]


def codes_in_class(klass):
    return tuple(c for c in CODES if REGISTRY[c][1] == klass)
