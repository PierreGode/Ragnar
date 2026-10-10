"""Hand-rolled IEEE 802.3 Clause 57 (802.3ah Link OAM) frame parser.

Pure receive-side. Dependency-free: no scapy, no sockets, no transmit.

Wire shape
----------
    Ethernet dst 01:80:C2:00:00:02 (slow protocols multicast)
    EtherType  0x8809 (Slow Protocols)
    Subtype    0x03   (OAM; 0x01 is LACP, 0x02 Marker - lacpwatch owns those)
    Flags      2 octets
    Code       1 octet
    Data/PAD   remainder, interpretation keyed on Code

PADDING TRAP (inherited from the cdpwatch false-positive and the lldpwatch
fix): an OAMPDU carries no length field, the kernel pads short frames to 60
octets, and some capture paths append a 4-octet FCS. The TLV walk is therefore
bounded by real content, trailing all-zero octets are padding and silent, and a
trailing run of exactly 4 non-zero octets at a frame length consistent with a
padded minimum frame is reported as a probable FCS rather than smuggled data
unless strict_tail is set.
"""

import struct

SLOW_PROTOCOLS_ETHERTYPE = 0x8809
OAM_SUBTYPE = 0x03
OAM_DEST_MAC = b"\x01\x80\xc2\x00\x00\x02"

ETH_HDR_LEN = 14
MIN_OAMPDU_BODY = 4           # subtype(1) + flags(2) + code(1)
MAX_OAM_FRAME = 1518          # standard ceiling, excluding FCS
MIN_ETH_FRAME = 60

# --- OAMPDU codes ---------------------------------------------------------
CODE_INFORMATION = 0x00
CODE_EVENT_NOTIFICATION = 0x01
CODE_VARIABLE_REQUEST = 0x02
CODE_VARIABLE_RESPONSE = 0x03
CODE_LOOPBACK_CONTROL = 0x04
CODE_ORG_SPECIFIC = 0xFE

CODE_NAMES = {
    CODE_INFORMATION: "Information",
    CODE_EVENT_NOTIFICATION: "EventNotification",
    CODE_VARIABLE_REQUEST: "VariableRequest",
    CODE_VARIABLE_RESPONSE: "VariableResponse",
    CODE_LOOPBACK_CONTROL: "LoopbackControl",
    CODE_ORG_SPECIFIC: "OrganizationSpecific",
}
DEFINED_CODES = frozenset(CODE_NAMES)

# --- Flags bits (Clause 57.4.2.1) -----------------------------------------
FLAG_LINK_FAULT = 0x0001
FLAG_DYING_GASP = 0x0002
FLAG_CRITICAL_EVENT = 0x0004
FLAG_LOCAL_EVALUATING = 0x0008
FLAG_LOCAL_STABLE = 0x0010
FLAG_REMOTE_EVALUATING = 0x0020
FLAG_REMOTE_STABLE = 0x0040
FLAGS_RESERVED_MASK = 0xFF80

# --- Information OAMPDU TLV types -----------------------------------------
TLV_END = 0x00
TLV_LOCAL_INFO = 0x01
TLV_REMOTE_INFO = 0x02
TLV_ORG_SPECIFIC = 0xFE
INFO_TLV_TYPES = frozenset((TLV_END, TLV_LOCAL_INFO, TLV_REMOTE_INFO, TLV_ORG_SPECIFIC))
INFO_TLV_FIXED_LEN = 0x10     # Local and Remote Information TLVs are 16 octets

# --- Event Notification TLV types and their fixed lengths -----------------
EV_ERRORED_SYMBOL_PERIOD = 0x01
EV_ERRORED_FRAME = 0x02
EV_ERRORED_FRAME_PERIOD = 0x03
EV_ERRORED_FRAME_SECONDS = 0x04
EVENT_TLV_FIXED_LEN = {
    EV_ERRORED_SYMBOL_PERIOD: 40,
    EV_ERRORED_FRAME: 26,
    EV_ERRORED_FRAME_PERIOD: 28,
    EV_ERRORED_FRAME_SECONDS: 18,
}
EVENT_TLV_TYPES = frozenset(
    (TLV_END, TLV_ORG_SPECIFIC) + tuple(EVENT_TLV_FIXED_LEN)
)
EVENT_TLV_NAMES = {
    EV_ERRORED_SYMBOL_PERIOD: "ErroredSymbolPeriod",
    EV_ERRORED_FRAME: "ErroredFrame",
    EV_ERRORED_FRAME_PERIOD: "ErroredFramePeriod",
    EV_ERRORED_FRAME_SECONDS: "ErroredFrameSecondsSummary",
}

# --- State field (Information TLV octet 3) --------------------------------
PARSER_FORWARD, PARSER_LOOPBACK, PARSER_DISCARD, PARSER_RESERVED = 0, 1, 2, 3
MUX_FORWARD, MUX_DISCARD = 0, 1
PARSER_NAMES = {0: "forward", 1: "loopback", 2: "discard", 3: "reserved"}
MUX_NAMES = {0: "forward", 1: "discard", 2: "reserved", 3: "reserved"}

# --- OAM Configuration byte (Information TLV octet 4) ---------------------
CFG_MODE_ACTIVE = 0x01
CFG_UNIDIRECTIONAL = 0x02
CFG_LOOPBACK_SUPPORT = 0x04
CFG_LINK_EVENTS = 0x08
CFG_VARIABLE_RETRIEVAL = 0x10
CFG_RESERVED_MASK = 0xE0

# --- Loopback Control command --------------------------------------------
LOOPBACK_ENABLE = 0x01
LOOPBACK_DISABLE = 0x02

# --- Clause 30 variable branches ------------------------------------------
BRANCH_END = 0x00
BRANCH_OBJECT = 0x03
BRANCH_PACKAGE = 0x04
BRANCH_ATTRIBUTE = 0x07
DEFINED_BRANCHES = frozenset((BRANCH_END, BRANCH_OBJECT, BRANCH_PACKAGE, BRANCH_ATTRIBUTE))
# Variable Response width values with bit 7 set are error indications, not lengths.
VAR_ERROR_WIDTHS = {
    0x80: "VariableLengthTooLong",
    0x81: "VariableUnsupported",
    0x82: "VariableUnavailable",
}


class Defect:
    """One structural defect found while parsing. Carries no judgement about
    intent - the engine decides what, if anything, to report."""

    __slots__ = ("code", "detail", "offset")

    def __init__(self, code, detail, offset=None):
        self.code = code
        self.detail = detail
        self.offset = offset

    def __repr__(self):
        return "Defect(%s, %r, off=%r)" % (self.code, self.detail, self.offset)

    def as_dict(self):
        return {"code": self.code, "detail": self.detail, "offset": self.offset}


class InfoTLV:
    __slots__ = ("kind", "oam_version", "revision", "state", "config",
                 "max_pdu_size", "oui", "vendor_info")

    def __init__(self, kind):
        self.kind = kind          # "local" or "remote"
        self.oam_version = None
        self.revision = None
        self.state = None
        self.config = None
        self.max_pdu_size = None
        self.oui = None
        self.vendor_info = None

    @property
    def parser_action(self):
        return None if self.state is None else (self.state & 0x03)

    @property
    def mux_action(self):
        return None if self.state is None else ((self.state >> 2) & 0x03)

    @property
    def mode_active(self):
        return None if self.config is None else bool(self.config & CFG_MODE_ACTIVE)

    @property
    def loopback_supported(self):
        return None if self.config is None else bool(self.config & CFG_LOOPBACK_SUPPORT)

    @property
    def unidirectional(self):
        return None if self.config is None else bool(self.config & CFG_UNIDIRECTIONAL)

    @property
    def variable_retrieval(self):
        return None if self.config is None else bool(self.config & CFG_VARIABLE_RETRIEVAL)

    @property
    def link_events(self):
        return None if self.config is None else bool(self.config & CFG_LINK_EVENTS)

    def identity(self):
        """Stable identity tuple for peer-substitution detection."""
        return (self.oui, self.vendor_info)


class Oampdu:
    """Parsed view of one OAM frame. Fields are None when not applicable or
    not parseable; `defects` carries every structural violation found."""

    __slots__ = ("src", "dst", "ethertype", "subtype", "flags", "code",
                 "body", "frame_len", "content_len", "local_info",
                 "remote_info", "org_tlvs", "event_seq", "events",
                 "var_descriptors", "var_containers", "loopback_cmd",
                 "defects", "tail_kind", "ts")

    def __init__(self):
        self.src = None
        self.dst = None
        self.ethertype = None
        self.subtype = None
        self.flags = None
        self.code = None
        self.body = b""
        self.frame_len = 0
        self.content_len = 0
        self.local_info = None
        self.remote_info = None
        self.org_tlvs = []
        self.event_seq = None
        self.events = []
        self.var_descriptors = []
        self.var_containers = []
        self.loopback_cmd = None
        self.defects = []
        self.tail_kind = None      # None | "padding" | "fcs" | "data"
        self.ts = None

    # -- flag helpers -----------------------------------------------------
    def _f(self, bit):
        return None if self.flags is None else bool(self.flags & bit)

    @property
    def link_fault(self):
        return self._f(FLAG_LINK_FAULT)

    @property
    def dying_gasp(self):
        return self._f(FLAG_DYING_GASP)

    @property
    def critical_event(self):
        return self._f(FLAG_CRITICAL_EVENT)

    @property
    def local_stable(self):
        return self._f(FLAG_LOCAL_STABLE)

    @property
    def local_evaluating(self):
        return self._f(FLAG_LOCAL_EVALUATING)

    @property
    def remote_stable(self):
        return self._f(FLAG_REMOTE_STABLE)

    @property
    def remote_evaluating(self):
        return self._f(FLAG_REMOTE_EVALUATING)

    @property
    def code_name(self):
        return CODE_NAMES.get(self.code, "Reserved(0x%02x)" % (self.code or 0))

    def defect_codes(self):
        return [d.code for d in self.defects]

    def add(self, code, detail, offset=None):
        self.defects.append(Defect(code, detail, offset))


def _mac(b):
    return ":".join("%02x" % x for x in b)


def is_oam_frame(raw):
    """Cheap pre-filter. True when the frame is slow-protocols OAM subtype."""
    if len(raw) < ETH_HDR_LEN + 1:
        return False
    if struct.unpack_from("!H", raw, 12)[0] != SLOW_PROTOCOLS_ETHERTYPE:
        return False
    return raw[ETH_HDR_LEN] == OAM_SUBTYPE


def _classify_tail(raw, tail_start, strict_tail):
    """Decide what the octets after the parsed content are.

    Returns ("padding"|"fcs"|"data", tail_bytes).
    """
    tail = raw[tail_start:]
    if not tail:
        return None, b""
    if not any(tail):
        return "padding", tail
    # A capture path that keeps the FCS leaves exactly 4 trailing octets after
    # the padded content. Only treat it as FCS when the frame length is
    # consistent with that and the operator has not demanded strict tails.
    nz = len(tail)
    trailing_nonzero = tail.rstrip(b"\x00")
    leading_zeros = nz - len(trailing_nonzero)
    if (not strict_tail and len(trailing_nonzero) == 4
            and leading_zeros + 4 == nz
            and len(raw) in (MIN_ETH_FRAME + 4, len(raw))
            and len(raw) >= MIN_ETH_FRAME + 4):
        return "fcs", tail
    return "data", tail


def _parse_info_tlvs(pdu, body, base_off, strict_tail, raw):
    """Walk the Information OAMPDU TLV list. Bounded by real content."""
    i = 0
    n = len(body)
    seen_local = 0
    seen_remote = 0
    end_at = None
    while i < n:
        t = body[i]
        if t == TLV_END:
            end_at = i + 1
            break
        if i + 2 > n:
            pdu.add("OAM-043", "TLV header truncated at end of OAMPDU",
                    base_off + i)
            return n
        ln = body[i + 1]
        if ln < 2:
            pdu.add("OAM-041",
                    "TLV type 0x%02x declares length %d, below the 2-octet "
                    "header it must include" % (t, ln), base_off + i)
            return n
        if i + ln > n:
            pdu.add("OAM-040",
                    "TLV type 0x%02x declares length %d but only %d octets "
                    "remain" % (t, ln, n - i), base_off + i)
            return n
        val = body[i + 2:i + ln]

        if t in (TLV_LOCAL_INFO, TLV_REMOTE_INFO):
            kind = "local" if t == TLV_LOCAL_INFO else "remote"
            if ln != INFO_TLV_FIXED_LEN:
                pdu.add("OAM-042",
                        "%s Information TLV length %d, standard fixes it at %d"
                        % (kind.capitalize(), ln, INFO_TLV_FIXED_LEN),
                        base_off + i)
            else:
                tlv = InfoTLV(kind)
                tlv.oam_version = val[0]
                tlv.revision = struct.unpack_from("!H", val, 1)[0]
                tlv.state = val[3]
                tlv.config = val[4]
                tlv.max_pdu_size = struct.unpack_from("!H", val, 5)[0]
                tlv.oui = val[7:10]
                tlv.vendor_info = val[10:14]
                if tlv.oam_version != 0x01:
                    pdu.add("OAM-054",
                            "%s Information TLV OAM Version 0x%02x, standard "
                            "defines 0x01" % (kind, tlv.oam_version),
                            base_off + i + 2)
                if tlv.parser_action == PARSER_RESERVED:
                    pdu.add("OAM-050",
                            "%s State parser action 0b11 is reserved" % kind,
                            base_off + i + 5)
                if tlv.mux_action >= 2:
                    pdu.add("OAM-050",
                            "%s State multiplexer action 0b%s is reserved"
                            % (kind, format(tlv.mux_action, "02b")),
                            base_off + i + 5)
                if kind == "local":
                    seen_local += 1
                    if pdu.local_info is None:
                        pdu.local_info = tlv
                else:
                    seen_remote += 1
                    if pdu.remote_info is None:
                        pdu.remote_info = tlv
        elif t == TLV_ORG_SPECIFIC:
            if ln < 5:
                pdu.add("OAM-056",
                        "Organization-Specific TLV length %d cannot hold a "
                        "3-octet OUI" % ln, base_off + i)
            else:
                pdu.org_tlvs.append((bytes(val[:3]), bytes(val[3:])))
        else:
            pdu.add("OAM-047",
                    "TLV type 0x%02x is not defined for an Information OAMPDU"
                    % t, base_off + i)
        i += ln

    if seen_local > 1:
        pdu.add("OAM-057", "%d Local Information TLVs in one OAMPDU" % seen_local)
    if seen_remote > 1:
        pdu.add("OAM-057", "%d Remote Information TLVs in one OAMPDU" % seen_remote)
    if seen_remote and not seen_local:
        pdu.add("OAM-049",
                "Remote Information TLV present with no Local Information TLV")
    return end_at if end_at is not None else n


def _parse_event_tlvs(pdu, body, base_off):
    i = 0
    n = len(body)
    end_at = None
    while i < n:
        t = body[i]
        if t == TLV_END:
            end_at = i + 1
            break
        if i + 2 > n:
            pdu.add("OAM-043", "Event TLV header truncated", base_off + i)
            return n
        ln = body[i + 1]
        if ln < 2:
            pdu.add("OAM-041",
                    "Event TLV type 0x%02x declares length %d" % (t, ln),
                    base_off + i)
            return n
        if i + ln > n:
            pdu.add("OAM-040",
                    "Event TLV type 0x%02x declares length %d but only %d "
                    "octets remain" % (t, ln, n - i), base_off + i)
            return n
        if t in EVENT_TLV_FIXED_LEN:
            want = EVENT_TLV_FIXED_LEN[t]
            if ln != want:
                pdu.add("OAM-046",
                        "%s event TLV length %d, standard fixes it at %d"
                        % (EVENT_TLV_NAMES[t], ln, want), base_off + i)
            else:
                ts = struct.unpack_from("!H", body, i + 2)[0]
                pdu.events.append((t, EVENT_TLV_NAMES[t], ts))
        elif t == TLV_ORG_SPECIFIC:
            if ln < 5:
                pdu.add("OAM-056",
                        "Organization-Specific event TLV length %d cannot hold "
                        "a 3-octet OUI" % ln, base_off + i)
        else:
            pdu.add("OAM-047",
                    "TLV type 0x%02x is not defined for an Event Notification "
                    "OAMPDU" % t, base_off + i)
        i += ln
    return end_at if end_at is not None else n


def _parse_var_request(pdu, body, base_off):
    i = 0
    n = len(body)
    while i < n:
        br = body[i]
        if br == BRANCH_END:
            return i + 1
        if br not in DEFINED_BRANCHES:
            pdu.add("OAM-052",
                    "Variable descriptor branch 0x%02x is not a defined "
                    "Clause 30 branch" % br, base_off + i)
            return n
        if i + 3 > n:
            pdu.add("OAM-052",
                    "Variable descriptor truncated: branch 0x%02x with no "
                    "2-octet leaf" % br, base_off + i)
            return n
        leaf = struct.unpack_from("!H", body, i + 1)[0]
        pdu.var_descriptors.append((br, leaf))
        i += 3
    return n


def _parse_var_response(pdu, body, base_off):
    i = 0
    n = len(body)
    while i < n:
        br = body[i]
        if br == BRANCH_END:
            return i + 1
        if br not in DEFINED_BRANCHES:
            pdu.add("OAM-052",
                    "Variable container branch 0x%02x is not a defined "
                    "Clause 30 branch" % br, base_off + i)
            return n
        if i + 4 > n:
            pdu.add("OAM-053",
                    "Variable container truncated: no leaf/width after branch "
                    "0x%02x" % br, base_off + i)
            return n
        leaf = struct.unpack_from("!H", body, i + 1)[0]
        width = body[i + 3]
        if width & 0x80:
            if width not in VAR_ERROR_WIDTHS:
                pdu.add("OAM-053",
                        "Variable container width 0x%02x sets the error bit "
                        "but is not one of the defined error indications "
                        "(0x80/0x81/0x82)" % width, base_off + i + 3)
            pdu.var_containers.append(
                (br, leaf, VAR_ERROR_WIDTHS.get(width, "Error(0x%02x)" % width), b""))
            i += 4
            continue
        if width == 0:
            pdu.add("OAM-053",
                    "Variable container width 0 is neither a length nor a "
                    "defined error indication", base_off + i + 3)
            return n
        if i + 4 + width > n:
            pdu.add("OAM-053",
                    "Variable container declares width %d but only %d octets "
                    "remain" % (width, n - i - 4), base_off + i + 3)
            return n
        pdu.var_containers.append((br, leaf, width, bytes(body[i + 4:i + 4 + width])))
        i += 4 + width
    return n


def parse_frame(raw, strict_tail=False, ts=None):
    """Parse one Ethernet frame. Returns an Oampdu, or None if not OAM.

    `strict_tail` disables the probable-FCS allowance and reports every
    non-zero trailing octet as smuggled data.
    """
    pdu = Oampdu()
    pdu.ts = ts
    pdu.frame_len = len(raw)
    if len(raw) < ETH_HDR_LEN + 1:
        return None
    pdu.dst = bytes(raw[0:6])
    pdu.src = bytes(raw[6:12])
    pdu.ethertype = struct.unpack_from("!H", raw, 12)[0]
    if pdu.ethertype != SLOW_PROTOCOLS_ETHERTYPE:
        return None
    pdu.subtype = raw[ETH_HDR_LEN]
    if pdu.subtype != OAM_SUBTYPE:
        return None

    if len(raw) > MAX_OAM_FRAME:
        pdu.add("OAM-055",
                "frame is %d octets; an OAMPDU may not exceed %d"
                % (len(raw), MAX_OAM_FRAME))

    if len(raw) < ETH_HDR_LEN + MIN_OAMPDU_BODY:
        pdu.add("OAM-043",
                "frame holds %d octets after the Ethernet header; an OAMPDU "
                "needs at least %d for subtype, flags and code"
                % (len(raw) - ETH_HDR_LEN, MIN_OAMPDU_BODY))
        pdu.content_len = len(raw)
        return pdu

    pdu.flags = struct.unpack_from("!H", raw, ETH_HDR_LEN + 1)[0]
    pdu.code = raw[ETH_HDR_LEN + 3]
    body_off = ETH_HDR_LEN + 4
    pdu.body = bytes(raw[body_off:])

    if pdu.flags & FLAGS_RESERVED_MASK:
        pdu.add("OAM-045",
                "Flags reserved bits set: 0x%04x" % (pdu.flags & FLAGS_RESERVED_MASK),
                ETH_HDR_LEN + 1)

    if pdu.code not in DEFINED_CODES:
        pdu.add("OAM-044",
                "OAMPDU Code 0x%02x is reserved" % pdu.code, ETH_HDR_LEN + 3)
        consumed = 0
    elif pdu.code == CODE_INFORMATION:
        consumed = _parse_info_tlvs(pdu, pdu.body, body_off, strict_tail, raw)
    elif pdu.code == CODE_EVENT_NOTIFICATION:
        if len(pdu.body) < 2:
            pdu.add("OAM-043",
                    "Event Notification OAMPDU has no 2-octet sequence number",
                    body_off)
            consumed = len(pdu.body)
        else:
            pdu.event_seq = struct.unpack_from("!H", pdu.body, 0)[0]
            consumed = 2 + _parse_event_tlvs(pdu, pdu.body[2:], body_off + 2)
    elif pdu.code == CODE_VARIABLE_REQUEST:
        consumed = _parse_var_request(pdu, pdu.body, body_off)
    elif pdu.code == CODE_VARIABLE_RESPONSE:
        consumed = _parse_var_response(pdu, pdu.body, body_off)
    elif pdu.code == CODE_LOOPBACK_CONTROL:
        if len(pdu.body) < 1:
            pdu.add("OAM-043",
                    "Loopback Control OAMPDU carries no command octet", body_off)
            consumed = 0
        else:
            pdu.loopback_cmd = pdu.body[0]
            if pdu.loopback_cmd not in (LOOPBACK_ENABLE, LOOPBACK_DISABLE):
                pdu.add("OAM-051",
                        "Loopback Control command 0x%02x is neither enable "
                        "(0x01) nor disable (0x02)" % pdu.loopback_cmd,
                        body_off)
            consumed = 1
    else:  # CODE_ORG_SPECIFIC
        if len(pdu.body) < 3:
            pdu.add("OAM-056",
                    "Organization-Specific OAMPDU cannot hold a 3-octet OUI",
                    body_off)
            consumed = len(pdu.body)
        else:
            pdu.org_tlvs.append((bytes(pdu.body[:3]), bytes(pdu.body[3:])))
            consumed = len(pdu.body)

    pdu.content_len = body_off + consumed
    kind, tail = _classify_tail(raw, pdu.content_len, strict_tail)
    pdu.tail_kind = kind
    if kind == "data":
        pdu.add("OAM-048",
                "%d non-zero octets follow the parsed OAMPDU content"
                % len(tail.rstrip(b"\x00").lstrip(b"\x00") or tail),
                pdu.content_len)
    return pdu
