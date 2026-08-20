#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Passive LDAP / Active Directory watch for the Ragnar suite.

PASSIVE ONLY. This module never transmits. It sniffs LDAP (TCP/389, GC/3268,
LDAPS/636, GC-S/3269) and connectionless LDAP (UDP/389) off the wire, reassembles
TCP byte streams per flow, decodes the BER/ASN.1 LDAPMessage envelope with a
hand-rolled definite-length decoder, and raises findings for insecure transport,
weak/absent authentication, STARTTLS stripping, directory enumeration, filter
injection, brute force, and CLDAP reflection/amplification.

Design conventions (shared across the Ragnar suite):
  * Passive-only Scapy capture. No sockets are opened for transmit; no packet is
    ever built or sent. The self-test greps this source for transmit primitives.
  * Custom raw-byte parser. No library dissectors - BER is decoded here directly.
  * systemd least-privilege unit: CAP_NET_RAW only, drops all other capabilities.
  * Self-test harness (test_ldapwatch.py) fabricates BER LDAP messages and runs
    them through THIS module's production parse+detect path.
  * JSON-lines output (one finding object per line) for the web UI + Pushover.
  * Hardware floor: Raspberry Pi Zero 2 W. Scapy import is lazy so --selftest and
    offline parsing work with zero third-party deps.

RFCs: 4511 (LDAPv3 protocol), 4513 (authentication methods & security),
2830/4513 (StartTLS), 4532 (Who Am I), 3062 (Password Modify), 4514 (DN string).
"""

# Cleartext LDAP / Global Catalog (parsed) vs. TLS-wrapped LDAPS / GC-S (only
# counted as "encrypted flow present" - the LDAP inside is TLS Watch's job).
LDAP_CLEARTEXT_PORTS = (389, 3268)
LDAPS_PORTS = (636, 3269)
CLDAP_PORT = 389                     # connectionless LDAP rides UDP/389

# --- BER/ASN.1 tags used by LDAPMessage (RFC 4511) ---------------------------
# protocolOp is an APPLICATION-class CHOICE; each op has a fixed tag byte.
_T_SEQUENCE = 0x30
_T_INTEGER = 0x02
_T_ENUMERATED = 0x0a
_T_OCTETSTRING = 0x04
_T_BOOLEAN = 0x01
OP_BIND_REQ = 0x60      # [APPLICATION 0]  constructed
OP_BIND_RESP = 0x61     # [APPLICATION 1]
OP_UNBIND_REQ = 0x42    # [APPLICATION 2]  primitive NULL
OP_SEARCH_REQ = 0x63    # [APPLICATION 3]
OP_SEARCH_ENTRY = 0x64  # [APPLICATION 4]
OP_SEARCH_DONE = 0x65   # [APPLICATION 5]
OP_MODIFY_REQ = 0x66    # [APPLICATION 6]
OP_ADD_REQ = 0x68       # [APPLICATION 8]
OP_DEL_REQ = 0x4a       # [APPLICATION 10] primitive
OP_MODDN_REQ = 0x6c     # [APPLICATION 12]
OP_COMPARE_REQ = 0x6e   # [APPLICATION 14]
OP_ABANDON_REQ = 0x50   # [APPLICATION 16] primitive
OP_EXT_REQ = 0x77       # [APPLICATION 23]
OP_EXT_RESP = 0x78      # [APPLICATION 24]
OP_SEARCH_REF = 0x73    # [APPLICATION 19]
# AuthenticationChoice context tags inside a BindRequest.
_AUTH_SIMPLE = 0x80     # [0] simple password (primitive)
_AUTH_SASL = 0xa3       # [3] SaslCredentials  (constructed)
# ExtendedRequest / ExtendedResponse context tags.
_EXT_REQ_NAME = 0x80    # [0] requestName  (LDAPOID)
_EXT_REQ_VALUE = 0x81   # [1] requestValue
# Search Filter context tags.
_F_AND, _F_OR, _F_NOT = 0xa0, 0xa1, 0xa2
_F_EQ, _F_SUBSTR, _F_GE, _F_LE = 0xa3, 0xa4, 0xa5, 0xa6
_F_PRESENT, _F_APPROX, _F_EXT = 0x87, 0xa8, 0xa9

# LDAP result codes we key on (RFC 4511 section 4.1.9).
RC_SUCCESS = 0
RC_INVALID_CREDENTIALS = 49
RC_STRONGER_AUTH_REQUIRED = 8
RC_SASL_BIND_IN_PROGRESS = 14
RC_CONFIDENTIALITY_REQUIRED = 13

# Extended-operation OIDs.
OID_STARTTLS = '1.3.6.1.4.1.1466.20037'
OID_WHOAMI = '1.3.6.1.4.1.4203.1.11.3'
OID_PASSWORD_MODIFY = '1.3.6.1.4.1.4203.1.11.1'

# Referral component of an LDAPResult (RFC 4511 4.1.10) is [3] context-tagged; a
# SearchResultReference (OP_SEARCH_REF) carries its LDAPURLs directly. A referral
# that steers a client to an EXTERNAL LDAP/CLDAP host is the LDAPNightmare vector
# (CVE-2024-49113 Windows LDAP DoS / CVE-2024-49112 LDAP client RCE): the exploit
# feeds a victim's LDAP client a crafted referral pointing at an attacker server.
_REFERRAL_CTX = 0xa3            # [3] referral  SEQUENCE OF LDAPURL, in an LDAPResult

# Attributes whose disclosure is sensitive: password material, LAPS, gMSA,
# delegation, ACLs, and SPNs (Kerberoast recon). Lower-cased for matching.
SENSITIVE_ATTRS = {
    'userpassword', 'unicodepwd', 'dbcspwd', 'lmpwdhistory', 'ntpwdhistory',
    'supplementalcredentials', 'ms-mcs-admpwd', 'mslaps-password',
    'mslaps-encryptedpassword', 'msds-managedpassword', 'ntsecuritydescriptor',
    'msds-allowedtodelegateto', 'msds-allowedtoactonbehalfofotheridentity',
    'serviceprincipalname', 'sidhistory',
}

# Detection thresholds (per capture window / per source).
BRUTE_BIND_ATTEMPTS = 10        # binds from one client == likely spraying/brute
BRUTE_BIND_FAILURES = 5         # invalidCredentials results toward one client
ENUM_SEARCH_COUNT = 20          # searches from one client == directory sweep
CLDAP_AMPLIFICATION = 4.0       # response/request byte ratio flagged as reflector


# =============================================================================
# BER / ASN.1 - hand-rolled definite-length decoder (no library dissectors)
# =============================================================================
class BERError(ValueError):
    """Raised on malformed/indefinite/truncated BER so one bad message is dropped
    per-flow instead of crashing the passive watcher."""


def ber_tlv(buf, i):
    """Decode one TLV at offset i in buf. Returns (tag, value_start, value_end,
    next_i). Definite-length only (LDAP forbids the indefinite form)."""
    n = len(buf)
    if i >= n:
        raise BERError('eof at tag')
    tag = buf[i]
    j = i + 1
    if (tag & 0x1f) == 0x1f:                 # high-tag-number form (not used by LDAP)
        while j < n and (buf[j] & 0x80):
            j += 1
        j += 1
    if j >= n:
        raise BERError('eof at length')
    first = buf[j]
    j += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise BERError('indefinite length')
    else:
        k = first & 0x7f
        if k > 4 or j + k > n:
            raise BERError('bad long length')
        length = int.from_bytes(buf[j:j + k], 'big')
        j += k
    end = j + length
    if end > n:
        raise BERError('truncated value')
    return tag, j, end, end


def ber_children(buf, start, end):
    """Yield (tag, value_start, value_end) for each TLV in a constructed value."""
    i = start
    while i < end:
        tag, vs, ve, i = ber_tlv(buf, i)
        yield tag, vs, ve


def ber_children_off(buf, start, end):
    """Like ber_children but also hands back each TLV's tag offset, so a child that
    is itself a TLV (a Filter, a nested SEQUENCE) can be re-decoded from its tag."""
    i = start
    while i < end:
        tag, vs, ve, nxt = ber_tlv(buf, i)
        yield tag, i, vs, ve
        i = nxt


def ber_int(buf, start, end):
    """Signed INTEGER/ENUMERATED value."""
    b = buf[start:end]
    if not b:
        return 0
    v = int.from_bytes(b, 'big')
    return v - (1 << (8 * len(b))) if (b[0] & 0x80) else v


def ber_str(buf, start, end):
    """OCTET STRING value as text (LDAP strings are UTF-8; be lenient)."""
    return buf[start:end].decode('utf-8', 'replace')


def ber_oid(buf, start, end):
    """Decode an OID's content bytes to dotted-decimal. LDAP carries OIDs as
    OCTET STRING ASCII in ExtendedRequest, so pass those through as text."""
    raw = buf[start:end]
    if raw and all(c == 0x2e or 0x30 <= c <= 0x39 for c in raw):
        return raw.decode('ascii', 'replace')       # already "1.3.6.1..."
    if not raw:
        return ''
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for c in raw[1:]:
        val = (val << 7) | (c & 0x7f)
        if not (c & 0x80):
            parts.append(str(val))
            val = 0
    return '.'.join(parts)


# =============================================================================
# LDAPMessage decode
# =============================================================================
def _decode_filter(buf, tag_off, hard_end, raw_values, depth=0):
    """Render the Filter TLV whose tag byte is at tag_off to its RFC 4515 string
    form, collecting raw assertion values into `raw_values` for injection checks."""
    if depth > 24:
        return '(...)'
    try:
        tag, vs, ve, _ = ber_tlv(buf, tag_off)
    except BERError:
        return '(?)'
    if ve > hard_end:
        return '(?)'
    if tag in (_F_AND, _F_OR, _F_NOT):
        op = {_F_AND: '&', _F_OR: '|', _F_NOT: '!'}[tag]
        inner = ''
        i = vs
        while i < ve:
            try:
                _t, _cvs, _cve, nxt = ber_tlv(buf, i)
            except BERError:
                break
            inner += _decode_filter(buf, i, ve, raw_values, depth + 1)
            i = nxt
        return '(' + op + inner + ')'
    if tag == _F_PRESENT:                        # [7] primitive: attribute present
        return '(' + ber_str(buf, vs, ve) + '=*)'
    if tag in (_F_EQ, _F_GE, _F_LE, _F_APPROX):
        sym = {_F_EQ: '=', _F_GE: '>=', _F_LE: '<=', _F_APPROX: '~='}[tag]
        kids = list(ber_children(buf, vs, ve))
        if len(kids) >= 2:
            attr = ber_str(buf, kids[0][1], kids[0][2])
            val = ber_str(buf, kids[1][1], kids[1][2])
            raw_values.append(val)
            return '(' + attr + sym + val + ')'
        return '(=)'
    if tag == _F_SUBSTR:                          # [4] substrings
        kids = list(ber_children(buf, vs, ve))
        if not kids:
            return '(=*)'
        attr = ber_str(buf, kids[0][1], kids[0][2])
        pieces = []
        if len(kids) >= 2:
            for _st, ss, se in ber_children(buf, kids[1][1], kids[1][2]):
                frag = ber_str(buf, ss, se)
                raw_values.append(frag)
                pieces.append(frag)
        return '(' + attr + '=' + '*'.join([''] + pieces + ['']) + ')'
    if tag == _F_EXT:
        return '(extensibleMatch)'
    return '(?)'


def parse_ldap_message(buf, start, end):
    """Decode one LDAPMessage SEQUENCE spanning buf[start:end] into a dict, or None
    if it is not a well-formed LDAPMessage."""
    try:
        tag, vs, ve, _ = ber_tlv(buf, start)
    except BERError:
        return None
    if tag != _T_SEQUENCE or ve > end:
        return None
    try:
        kids = list(ber_children(buf, vs, ve))
    except BERError:
        return None
    if len(kids) < 2 or kids[0][0] != _T_INTEGER:
        return None
    msg = {'messageID': ber_int(buf, kids[0][1], kids[0][2])}
    op_tag, ops, ope = kids[1]
    try:
        if op_tag == OP_BIND_REQ:
            _decode_bind_request(buf, ops, ope, msg)
        elif op_tag == OP_BIND_RESP:
            msg['op'] = 'bind-resp'
            msg['result_code'] = _first_enum(buf, ops, ope)
            msg['referrals'] = _result_referrals(buf, ops, ope)
        elif op_tag == OP_SEARCH_REQ:
            _decode_search_request(buf, ops, ope, msg)
        elif op_tag == OP_SEARCH_ENTRY:
            msg['op'] = 'search-entry'
            ek = list(ber_children(buf, ops, ope))
            msg['dn'] = ber_str(buf, ek[0][1], ek[0][2]) if ek else ''
        elif op_tag == OP_SEARCH_DONE:
            msg['op'] = 'search-done'
            msg['result_code'] = _first_enum(buf, ops, ope)
            msg['referrals'] = _result_referrals(buf, ops, ope)
        elif op_tag == OP_SEARCH_REF:
            # SearchResultReference == SEQUENCE OF LDAPURL carried directly.
            msg['op'] = 'search-ref'
            msg['referrals'] = _referral_urls(buf, ops, ope)
        elif op_tag == OP_EXT_REQ:
            _decode_extended_request(buf, ops, ope, msg)
        elif op_tag == OP_EXT_RESP:
            msg['op'] = 'ext-resp'
            msg['result_code'] = _first_enum(buf, ops, ope)
        elif op_tag == OP_UNBIND_REQ:
            msg['op'] = 'unbind-req'
        elif op_tag == OP_ABANDON_REQ:
            msg['op'] = 'abandon-req'
        else:
            msg['op'] = _OP_NAMES.get(op_tag, 'op-0x%02x' % op_tag)
    except BERError:
        msg.setdefault('op', 'malformed')
    return msg


_OP_NAMES = {OP_MODIFY_REQ: 'modify-req', OP_ADD_REQ: 'add-req',
             OP_DEL_REQ: 'del-req', OP_MODDN_REQ: 'moddn-req',
             OP_COMPARE_REQ: 'compare-req', OP_SEARCH_REF: 'search-ref'}


def _first_enum(buf, start, end):
    """resultCode is the first ENUMERATED in an LDAPResult COMPONENTS sequence."""
    for tag, vs, ve in ber_children(buf, start, end):
        if tag == _T_ENUMERATED:
            return ber_int(buf, vs, ve)
    return None


def _referral_urls(buf, start, end):
    """Collect the LDAPURL octet-strings inside a SEQUENCE OF LDAPURL region
    (either a SearchResultReference body or a [3] referral component)."""
    urls = []
    for _tag, vs, ve in ber_children(buf, start, end):
        try:
            u = ber_str(buf, vs, ve)
        except BERError:
            continue
        if u:
            urls.append(u)
    return urls


def _result_referrals(buf, start, end):
    """An LDAPResult may carry an optional referral component tagged [3] (RFC 4511
    4.1.10) holding a SEQUENCE OF LDAPURL. Return the URLs, or [] if absent."""
    for tag, vs, ve in ber_children(buf, start, end):
        if tag == _REFERRAL_CTX:
            return _referral_urls(buf, vs, ve)
    return []


def _decode_bind_request(buf, start, end, msg):
    msg['op'] = 'bind-req'
    kids = list(ber_children(buf, start, end))
    if len(kids) < 3:
        msg['auth'] = 'malformed'
        return
    msg['version'] = ber_int(buf, kids[0][1], kids[0][2])
    msg['name'] = ber_str(buf, kids[1][1], kids[1][2])
    atag, avs, ave = kids[2]
    if atag == _AUTH_SIMPLE:
        msg['auth'] = 'simple'
        msg['password_len'] = ave - avs
        msg['password_empty'] = (ave == avs)
    elif atag == _AUTH_SASL:
        msg['auth'] = 'sasl'
        sk = list(ber_children(buf, avs, ave))
        msg['sasl_mech'] = ber_str(buf, sk[0][1], sk[0][2]) if sk else ''
        msg['password_len'] = (sk[1][2] - sk[1][1]) if len(sk) > 1 else 0
    else:
        msg['auth'] = 'unknown'


def _decode_search_request(buf, start, end, msg):
    msg['op'] = 'search-req'
    kids = list(ber_children_off(buf, start, end))   # (tag, tag_off, vs, ve)
    msg['base'] = ''
    msg['scope'] = None
    msg['filter'] = '(?)'
    msg['attributes'] = []
    msg['assertion_values'] = []
    if len(kids) < 7:
        return
    msg['base'] = ber_str(buf, kids[0][2], kids[0][3])
    msg['scope'] = ber_int(buf, kids[1][2], kids[1][3])
    raw_values = []
    msg['filter'] = _decode_filter(buf, kids[6][1], kids[6][3], raw_values)
    msg['assertion_values'] = raw_values
    attrs = []
    if len(kids) >= 8:
        for _tg, vs, ve in ber_children(buf, kids[7][2], kids[7][3]):
            attrs.append(ber_str(buf, vs, ve).lower())
    msg['attributes'] = attrs


def _decode_extended_request(buf, start, end, msg):
    msg['op'] = 'ext-req'
    oid, val_len = '', 0
    for tag, vs, ve in ber_children(buf, start, end):
        if tag == _EXT_REQ_NAME:
            oid = ber_oid(buf, vs, ve)
        elif tag == _EXT_REQ_VALUE:
            val_len = ve - vs
    msg['oid'] = oid
    msg['value_len'] = val_len
    msg['ext_name'] = {OID_STARTTLS: 'starttls', OID_WHOAMI: 'whoami',
                       OID_PASSWORD_MODIFY: 'password-modify'}.get(oid, oid or '?')


# =============================================================================
# Per-flow reassembly + top-level LDAPMessage extraction
# =============================================================================
def split_ldap_messages(buf):
    """Split a reassembled byte stream into (parsed_messages, bytes_consumed) by
    walking top-level SEQUENCE TLVs. A trailing partial message leaves its bytes
    unconsumed so a streaming caller can wait for more."""
    msgs, i, n = [], 0, len(buf)
    while i < n:
        if buf[i] != _T_SEQUENCE:
            break                                # not an LDAPMessage start; stop
        try:
            _tag, _vs, _ve, nxt = ber_tlv(buf, i)
        except BERError:
            break                                # incomplete tail: wait for more
        m = parse_ldap_message(buf, i, nxt)
        if m is None:
            break
        msgs.append(m)
        i = nxt
    return msgs, i


class FlowReassembler:
    """Accumulates one TCP direction's payload and yields complete LDAP messages as
    they arrive (arrival-order; a mirror/SPAN port delivers segments in order)."""
    __slots__ = ('buf',)

    def __init__(self):
        self.buf = bytearray()

    def feed(self, payload):
        self.buf += payload
        msgs, consumed = split_ldap_messages(bytes(self.buf))
        if consumed:
            del self.buf[:consumed]
        return msgs


# =============================================================================
# Findings engine
# =============================================================================
_SEV_RANK = {'info': 0, 'low': 1, 'warn': 2, 'high': 3}
_VERDICT_RANK = {'clean': 0, 'suspicious': 1, 'compromised': 2}
# Finding codes that mean confirmed exposure/attack, not just weak posture.
_COMPROMISED_CODES = {'cleartext-bind-credentials', 'sasl-plaintext-cleartext',
                      'cleartext-password-modify', 'starttls-stripped',
                      'filter-injection', 'brute-force', 'cldap-amplification',
                      'external-referral'}


class LdapDetector:
    """Consumes parsed LDAP messages + CLDAP datagrams and accumulates findings.
    Shared by the bounded do_ldap_watch() path and the streaming daemon."""

    def __init__(self):
        self.local_nets = None           # our own subnets, for referral/CLDAP scoping
        self.flow_findings = {}          # flowkey -> [finding, ...]
        self.flow_msgs = {}              # flowkey -> message count
        self.bind_attempts = {}          # client_ip -> count
        self.bind_failures = {}          # client_ip -> count
        self.searches = {}               # client_ip -> count
        self.starttls_pending = set()    # flowkeys awaiting a StartTLS response
        self.cldap_req_bytes = {}
        self.cldap_resp_bytes = {}
        self.stats = {'ldap_messages': 0, 'binds': 0, 'searches': 0,
                      'extended': 0, 'cldap': 0, 'flows': 0}

    # -- helpers --------------------------------------------------------------
    def _add(self, flowkey, sev, code, message):
        bucket = self.flow_findings.setdefault(flowkey, [])
        if not any(f['code'] == code for f in bucket):   # one per code per flow
            bucket.append({'severity': sev, 'code': code, 'message': message})

    @staticmethod
    def _cleartext(dport, sport):
        return (dport in LDAP_CLEARTEXT_PORTS) or (sport in LDAP_CLEARTEXT_PORTS)

    # -- TCP LDAP -------------------------------------------------------------
    def feed_message(self, flowkey, msg):
        """flowkey = (src, sport, dst, dport); src sent this direction's bytes."""
        src, sport, dst, dport = flowkey
        cleartext = self._cleartext(dport, sport)
        self.flow_msgs[flowkey] = self.flow_msgs.get(flowkey, 0) + 1
        self.stats['ldap_messages'] += 1
        op = msg.get('op')

        if op == 'bind-req':
            self.stats['binds'] += 1
            self.bind_attempts[src] = self.bind_attempts.get(src, 0) + 1
            self._check_bind(flowkey, msg, cleartext)
        elif op == 'bind-resp':
            if msg.get('result_code') == RC_INVALID_CREDENTIALS:
                self.bind_failures[dst] = self.bind_failures.get(dst, 0) + 1
            self._check_referrals(flowkey, msg.get('referrals'))
        elif op == 'search-done':
            self._check_referrals(flowkey, msg.get('referrals'))
        elif op == 'search-ref':
            self._check_referrals(flowkey, msg.get('referrals'))
        elif op == 'search-req':
            self.stats['searches'] += 1
            self.searches[src] = self.searches.get(src, 0) + 1
            self._check_search(flowkey, msg, cleartext)
        elif op == 'ext-req':
            self.stats['extended'] += 1
            if msg.get('ext_name') == 'starttls':
                self.starttls_pending.add(flowkey)
            elif msg.get('ext_name') == 'password-modify' and cleartext:
                self._add(flowkey, 'high', 'cleartext-password-modify',
                          'LDAP Password Modify (RFC 3062) over cleartext - the new '
                          'password crosses the wire unprotected; require LDAPS/StartTLS')
        elif op == 'ext-resp':
            self._check_starttls_response(flowkey, msg)

    def _check_bind(self, flowkey, msg, cleartext):
        auth = msg.get('auth')
        name = msg.get('name') or ''
        if auth == 'simple':
            if msg.get('password_empty'):
                if name:
                    self._add(flowkey, 'warn', 'unauthenticated-bind',
                              "Unauthenticated simple bind: DN '%s' with an EMPTY "
                              "password (RFC 4513 5.1.2). The server may accept it as "
                              "anonymous while the client believes it authenticated"
                              % _short_dn(name))
                else:
                    self._add(flowkey, 'warn', 'anonymous-bind',
                              'Anonymous simple bind (empty DN + empty password). '
                              'Disable anonymous binds on the directory')
            elif cleartext:
                self._add(flowkey, 'high', 'cleartext-bind-credentials',
                          "Cleartext simple bind for DN '%s' - the password (%d bytes) "
                          "is recoverable from this capture. Require LDAPS (636) or "
                          "StartTLS and reject simple binds on cleartext"
                          % (_short_dn(name), msg.get('password_len', 0)))
        elif auth == 'sasl':
            mech = (msg.get('sasl_mech') or '').upper()
            if cleartext and mech in ('PLAIN', 'LOGIN', 'EXTERNAL', ''):
                self._add(flowkey, 'high', 'sasl-plaintext-cleartext',
                          "SASL %s bind over cleartext - credentials are exposed. Use "
                          "a confidentiality layer (LDAPS/StartTLS) or GSSAPI/GSS-SPNEGO"
                          % (mech or 'anonymous'))

    def _check_search(self, flowkey, msg, cleartext):
        attrs = set(msg.get('attributes') or [])
        base = msg.get('base') or ''
        scope = msg.get('scope')
        filt = msg.get('filter') or ''

        # Filter injection: raw parentheses / metacharacters inside an assertion
        # value (which RFC 4515 requires be escaped) are a classic injection payload.
        for val in (msg.get('assertion_values') or []):
            if _looks_like_injection(val):
                self._add(flowkey, 'high', 'filter-injection',
                          "LDAP filter injection: assertion value contains unescaped "
                          "filter metacharacters (%s) - likely an auth-bypass / blind "
                          "injection probe" % _clip(val))
                break

        sens = attrs & SENSITIVE_ATTRS
        if sens and cleartext:
            self._add(flowkey, 'high', 'sensitive-attribute',
                      'Cleartext read of sensitive attribute(s) %s - password/LAPS/gMSA'
                      '/SPN/ACL material exposed on the wire' % ', '.join(sorted(sens)))
        elif sens:
            self._add(flowkey, 'warn', 'sensitive-attribute',
                      'Query for sensitive attribute(s) %s (LAPS/gMSA/SPN/ACL recon)'
                      % ', '.join(sorted(sens)))

        # Whole-subtree objectClass=* from a domain-ish base is the BloodHound /
        # ldapdomaindump enumeration signature.
        if scope == 2 and _is_broad_filter(filt) and _looks_like_domain_base(base):
            self._add(flowkey, 'warn', 'directory-enumeration',
                      "Whole-subtree enumeration of '%s' with filter %s - directory "
                      "dump (BloodHound / ldapdomaindump style)"
                      % (_short_dn(base) or '(root)', _clip(filt, 40)))

    def _check_referrals(self, flowkey, urls):
        """A referral / SearchResultReference that points a client to an LDAP host
        OUTSIDE our own subnets is the LDAPNightmare steering vector: a crafted
        response feeds the victim's LDAP client an attacker-controlled server. We
        only flag IP-literal targets outside the local nets - hostnames can't be
        classified passively (no DNS), and an unknown local-net list stays silent -
        so a legitimate in-forest referral never trips it."""
        for uri in (urls or []):
            host = _ldap_url_host(uri)
            if host and _referral_host_external(host, self.local_nets):
                self._add(flowkey, 'high', 'external-referral',
                          "LDAP referral steers a client to EXTERNAL host %s (%s) - "
                          "the LDAPNightmare vector (CVE-2024-49113 Windows LDAP DoS / "
                          "CVE-2024-49112 LDAP client RCE): a crafted referral points "
                          "the victim's LDAP client at an attacker server. Block "
                          "outbound LDAP/CLDAP from clients and apply the MS LDAP "
                          "client patch" % (host, _clip(uri, 60)))
                break

    def _check_starttls_response(self, flowkey, msg):
        rev = (flowkey[2], flowkey[3], flowkey[0], flowkey[1])
        if flowkey not in self.starttls_pending and rev not in self.starttls_pending:
            return
        self.starttls_pending.discard(flowkey)
        self.starttls_pending.discard(rev)
        if msg.get('result_code') not in (RC_SUCCESS, None):
            self._add(flowkey, 'high', 'starttls-stripped',
                      'StartTLS request was refused (resultCode %s) - the session '
                      'stays in cleartext (downgrade / TLS-strip). Enforce LDAP '
                      'signing + channel binding and require TLS'
                      % msg.get('result_code'))

    def finalize_starttls(self):
        """A StartTLS request with no successful upgrade whose flow kept carrying
        cleartext LDAP is a strip."""
        for flowkey in list(self.starttls_pending):
            if self.flow_msgs.get(flowkey, 0) > 1:
                self._add(flowkey, 'high', 'starttls-stripped',
                          'StartTLS was requested but the flow continued in cleartext '
                          '(no TLS records observed) - StartTLS stripped/failed')

    # -- CLDAP (UDP/389) ------------------------------------------------------
    def feed_cldap(self, src, sport, dst, dport, payload, is_response, local_nets):
        self.stats['cldap'] += 1
        flowkey = (src, sport, dst, dport)
        if is_response:
            self.cldap_resp_bytes[src] = self.cldap_resp_bytes.get(src, 0) + len(payload)
            return
        self.cldap_req_bytes[dst] = self.cldap_req_bytes.get(dst, 0) + len(payload)
        # A CLDAP query whose source is off-subnet can be a spoofed victim address -
        # i.e. this DC is being used as a reflection amplifier.
        if local_nets is not None and not _ip_in_nets(src, local_nets):
            self._add(flowkey, 'warn', 'cldap-reflection',
                      'CLDAP (UDP/389) query from off-subnet source %s - if spoofed, '
                      'this DC is an open reflector for UDP amplification DDoS. '
                      'Restrict UDP/389 at the edge' % src)

    def finalize_cldap(self):
        for host, rbytes in self.cldap_resp_bytes.items():
            qbytes = self.cldap_req_bytes.get(host, 0)
            if qbytes and rbytes / qbytes >= CLDAP_AMPLIFICATION:
                fk = (host, CLDAP_PORT, host, CLDAP_PORT)
                self._add(fk, 'high', 'cldap-amplification',
                          'CLDAP responder %s returned %.1fx the query bytes (%d->%d) - '
                          'a usable UDP reflection/amplification vector'
                          % (host, rbytes / qbytes, qbytes, rbytes))

    # -- brute force / enumeration (aggregate, per source) --------------------
    def finalize_rates(self):
        for src, n in self.bind_attempts.items():
            if n >= BRUTE_BIND_ATTEMPTS:
                self._add(_syn_flowkey(src), 'high', 'brute-force',
                          '%d LDAP bind attempts from %s in the window - password '
                          'spraying / brute force' % (n, src))
        for victim, n in self.bind_failures.items():
            if n >= BRUTE_BIND_FAILURES:
                self._add(_syn_flowkey(victim), 'high', 'brute-force',
                          '%d invalidCredentials bind responses toward %s - brute-force '
                          'in progress' % (n, victim))
        for src, n in self.searches.items():
            if n >= ENUM_SEARCH_COUNT:
                self._add(_syn_flowkey(src), 'warn', 'directory-enumeration',
                          '%d LDAP searches from %s in the window - directory sweep'
                          % (n, src))

    # -- result assembly ------------------------------------------------------
    def result(self):
        self.finalize_starttls()
        self.finalize_rates()
        self.finalize_cldap()
        self.stats['flows'] = len(set(list(self.flow_msgs) + list(self.flow_findings)))
        flows, all_findings, verdict = [], [], 'clean'
        for flowkey, findings in self.flow_findings.items():
            src, sport, dst, dport = flowkey
            findings = sorted(findings, key=lambda f: -_SEV_RANK.get(f['severity'], 0))
            proto = 'cldap' if (sport == CLDAP_PORT and dport == CLDAP_PORT
                                and self.flow_msgs.get(flowkey, 0) == 0) else 'ldap'
            flows.append({'proto': proto, 'src': '%s:%s' % (src, sport),
                          'dst': '%s:%s' % (dst, dport),
                          'messages': self.flow_msgs.get(flowkey, 0),
                          'findings': findings})
            for f in findings:
                all_findings.append(dict(f, src='%s:%s' % (src, sport),
                                         dst='%s:%s' % (dst, dport)))
                if f['code'] in _COMPROMISED_CODES:
                    v = 'compromised'
                elif f['severity'] in ('warn', 'high'):
                    v = 'suspicious'
                else:
                    v = 'clean'
                if _VERDICT_RANK[v] > _VERDICT_RANK[verdict]:
                    verdict = v
        all_findings.sort(key=lambda f: -_SEV_RANK.get(f['severity'], 0))
        # `reasons` mirrors the rest of the watcher suite so the Network Integrity
        # Monitor can surface LDAP findings in its Pushover regression alerts.
        reasons = ['%s: %s' % (f['code'], f['message']) for f in all_findings[:6]]
        return {'success': True, 'verdict': verdict, 'flows': flows,
                'findings': all_findings, 'reasons': reasons,
                'count': len(all_findings), 'stats': dict(self.stats)}


# --- finding helpers ---------------------------------------------------------
def _short_dn(dn, maxlen=64):
    dn = dn or ''
    return dn if len(dn) <= maxlen else dn[:maxlen - 1] + '...'


def _clip(s, maxlen=48):
    s = s or ''
    return s if len(s) <= maxlen else s[:maxlen - 1] + '...'


def _looks_like_injection(val):
    if not val:
        return False
    if ')(' in val or '*)(' in val or '(|' in val or '(&' in val:
        return True
    # A bare '(' or ')' inside a value must be escaped (\28/\29); raw ones == injection.
    return ('(' in val) or (')' in val)


def _is_broad_filter(filt):
    f = (filt or '').replace(' ', '').lower()
    return f.startswith('(objectclass=*') or f == '(cn=*)' \
        or f == '(&(objectclass=*))'


def _looks_like_domain_base(base):
    b = (base or '').lower()
    return b == '' or b.count('dc=') >= 2


def _ip_in_nets(ip, nets):
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in nets)
    except Exception:
        return True                              # unknown -> don't false-positive


def _ldap_url_host(uri):
    """Pull the host out of an ldap[s]://host[:port]/... referral URL (RFC 4516).
    Returns the bare host (IPv6 literals de-bracketed), or None if unparseable."""
    import re
    m = re.match(r'\s*ldaps?://(\[[^\]]+\]|[^:/\s]+)', uri or '', re.IGNORECASE)
    if not m:
        return None
    host = m.group(1)
    return host[1:-1] if host.startswith('[') else host


def _referral_host_external(host, nets):
    """True only when `host` is an IP literal that is NOT in our own subnets. A
    hostname (needs DNS to place) or an unknown local-net list returns False so we
    never false-positive on a legitimate in-forest referral."""
    if nets is None:
        return False
    try:
        import ipaddress
        addr = ipaddress.ip_address(host)          # raises for hostnames -> skip
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local:
        return False
    return not any(addr in net for net in nets)


def _syn_flowkey(ip):
    """A synthetic flowkey to hang aggregate (per-source) findings on."""
    return (ip, 0, ip, 0)


# =============================================================================
# Capture (passive Scapy sniff) -> records -> detector -> result
# =============================================================================
def _bpf():
    tcp = ' or '.join('tcp port %d' % p for p in LDAP_CLEARTEXT_PORTS + LDAPS_PORTS)
    return '(%s) or (udp port %d)' % (tcp, CLDAP_PORT)


def _record(pkt):
    """Extract (src, sport, dst, dport, payload, is_tcp) from a scapy packet using
    the exact captured bytes. Returns None for non-LDAP packets."""
    from scapy.layers.inet import IP, TCP, UDP
    try:
        from scapy.layers.inet6 import IPv6
    except Exception:
        IPv6 = None
    ipl = pkt.getlayer(IP) or (IPv6 and pkt.getlayer(IPv6))
    if not ipl:
        return None
    l4 = pkt.getlayer(TCP)
    is_tcp = l4 is not None
    if l4 is None:
        l4 = pkt.getlayer(UDP)
    if l4 is None:
        return None
    pl = l4.payload
    orig = getattr(pl, 'original', b'')
    payload = bytes(orig) if orig else bytes(pl)
    if not payload:
        return None
    return (ipl.src, int(l4.sport), ipl.dst, int(l4.dport), payload, is_tcp)


def _local_nets(interface):
    """Best-effort list of the interface's own IPv4/IPv6 networks, for CLDAP
    off-subnet detection. Passive: only reads local addressing, sends nothing."""
    nets = []
    try:
        import ipaddress
        import subprocess
        out = subprocess.run(['ip', '-o', 'addr', 'show', 'dev', interface],
                             capture_output=True, text=True, timeout=4).stdout
        for line in out.splitlines():
            parts = line.split()
            for i, tok in enumerate(parts):
                if tok in ('inet', 'inet6') and i + 1 < len(parts):
                    try:
                        nets.append(ipaddress.ip_network(parts[i + 1], strict=False))
                    except ValueError:
                        pass
    except Exception:
        return None
    return nets or None


def analyze_packets(packets, local_nets=None):
    """Reassemble TCP flows by sequence number (like the rest of the suite), decode
    CLDAP datagrams, and run the detector. Unit-testable; used by do_ldap_watch()."""
    from scapy.layers.inet import IP, TCP, UDP
    try:
        from scapy.layers.inet6 import IPv6
    except Exception:
        IPv6 = None
    det = LdapDetector()
    det.local_nets = local_nets
    tcp = {}
    for p in packets:
        ipl = p.getlayer(IP) or (IPv6 and p.getlayer(IPv6))
        if not ipl:
            continue
        if p.haslayer(TCP):
            t = p[TCP]
            pl = t.payload
            orig = getattr(pl, 'original', b'')
            pay = bytes(orig) if orig else bytes(pl)
            if pay:
                tcp.setdefault((ipl.src, int(t.sport), ipl.dst, int(t.dport)),
                               {})[int(t.seq)] = pay
        elif p.haslayer(UDP):
            u = p[UDP]
            pl = u.payload
            orig = getattr(pl, 'original', b'')
            pay = bytes(orig) if orig else bytes(pl)
            if pay:
                det.feed_cldap(ipl.src, int(u.sport), ipl.dst, int(u.dport), pay,
                               int(u.sport) == CLDAP_PORT, local_nets)
    for key, segs in tcp.items():
        stream = b''.join(segs[s] for s in sorted(segs))
        msgs, _ = split_ldap_messages(stream)
        for m in msgs:
            det.feed_message(key, m)
    return det.result()


def do_ldap_watch(interface=None, seconds=15, learn=True):
    """Passive LDAP/AD observation on `interface` for `seconds`. Sniffs cleartext
    LDAP + CLDAP, decodes it, and returns findings + an overall verdict. Requires
    root (raw capture). Scapy is imported lazily here, never at module import."""
    seconds = max(5, min(int(seconds or 15), 60))
    if not interface:
        return {'success': False, 'error': 'no interface specified'}
    try:
        from scapy.all import sniff
    except Exception:
        return {'success': False, 'missing_tool': 'scapy',
                'error': 'the Python "scapy" package is required for passive capture'}
    try:
        packets = sniff(iface=interface, filter=_bpf(), timeout=seconds, store=True)
    except PermissionError:
        return {'success': False, 'error': 'raw capture needs root / CAP_NET_RAW'}
    except Exception as e:
        return {'success': False, 'error': 'capture failed: %s' % e}
    res = analyze_packets(packets, local_nets=_local_nets(interface))
    res.update({'interface': interface, 'seconds': seconds})
    return res


# =============================================================================
# Streaming daemon (systemd) -> JSON-lines findings
# =============================================================================
def run_daemon(interface, out_path=None, local_nets=None):
    """Continuously sniff and emit one JSON object per finding to stdout (and, if
    given, append to out_path). Never returns under normal operation."""
    import json
    import sys
    import time
    from scapy.all import sniff
    if local_nets is None:
        local_nets = _local_nets(interface)
    reasm = {}                                   # flowkey -> FlowReassembler
    det = LdapDetector()
    det.local_nets = local_nets
    emitted = set()                              # de-dup of (code, src, dst)
    sink = open(out_path, 'a', buffering=1) if out_path else None

    def emit(finding):
        finding = dict(finding, ts=int(time.time()), iface=interface)
        line = json.dumps(finding, default=str)
        sys.stdout.write(line + '\n')
        sys.stdout.flush()
        if sink:
            sink.write(line + '\n')

    def flush_new():
        for flowkey, findings in det.flow_findings.items():
            for f in findings:
                dedup = (f['code'], flowkey[0], flowkey[2])
                if dedup in emitted:
                    continue
                emitted.add(dedup)
                emit(dict(f, src='%s:%s' % (flowkey[0], flowkey[1]),
                          dst='%s:%s' % (flowkey[2], flowkey[3])))

    def handle(pkt):
        rec = _record(pkt)
        if not rec:
            return
        src, sport, dst, dport, payload, is_tcp = rec
        key = (src, sport, dst, dport)
        if is_tcp:
            r = reasm.get(key)
            if r is None:
                r = reasm[key] = FlowReassembler()
            for m in r.feed(payload):
                det.feed_message(key, m)
        else:
            det.feed_cldap(src, sport, dst, dport, payload,
                           sport == CLDAP_PORT, local_nets)
        det.finalize_rates()                     # re-evaluate per-source rate findings
        flush_new()

    sniff(iface=interface, filter=_bpf(), prn=handle, store=False)


# =============================================================================
# Self-test - fabricate BER LDAP messages, run the production parse+detect path,
# and prove this source contains no transmit primitives.
# =============================================================================
def _b_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, content):
    return bytes([tag]) + _b_len(len(content)) + content


def _int(v):
    return _tlv(_T_INTEGER, v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big',
                                       signed=v < 0))


def _enum(v):
    return _tlv(_T_ENUMERATED, bytes([v]))


def _octet(s):
    return _tlv(_T_OCTETSTRING, s.encode() if isinstance(s, str) else s)


def _ldap_message(msgid, protocol_op):
    return _tlv(_T_SEQUENCE, _int(msgid) + protocol_op)


def _bind_req(version, name, simple=None, sasl_mech=None):
    if sasl_mech is not None:
        auth = _tlv(_AUTH_SASL, _octet(sasl_mech))
    else:
        auth = _tlv(_AUTH_SIMPLE, (simple or '').encode())
    return _ldap_message(1, _tlv(OP_BIND_REQ, _int(version) + _octet(name) + auth))


def _bind_resp(rc, referrals=None):
    body = _enum(rc) + _octet('') + _octet('')
    if referrals:
        body += _tlv(_REFERRAL_CTX, b''.join(_octet(u) for u in referrals))
    return _ldap_message(1, _tlv(OP_BIND_RESP, body))


def _search_ref(urls):
    return _ldap_message(4, _tlv(OP_SEARCH_REF, b''.join(_octet(u) for u in urls)))


def _search_req(base, scope, filt_bytes, attrs):
    body = (_octet(base) + _enum(scope) + _enum(0) + _int(0) + _int(0)
            + _tlv(_T_BOOLEAN, b'\x00') + filt_bytes
            + _tlv(_T_SEQUENCE, b''.join(_octet(a) for a in attrs)))
    return _ldap_message(2, _tlv(OP_SEARCH_REQ, body))


def _f_equal(attr, val):
    return _tlv(_F_EQ, _octet(attr) + _octet(val))


def _f_present(attr):
    return _tlv(_F_PRESENT, attr.encode())


def _ext_req(oid):
    return _ldap_message(3, _tlv(OP_EXT_REQ, _tlv(_EXT_REQ_NAME, oid.encode())))


def _ext_resp(rc):
    return _ldap_message(3, _tlv(OP_EXT_RESP, _enum(rc) + _octet('') + _octet('')))


def selftest():
    """Known-answer harness. Fabricates BER LDAP messages, feeds them through the
    real split/parse/detect path, and asserts findings + verdict."""
    checks = []

    def ck(name, got, want=True):
        checks.append({'name': name, 'pass': got == want, 'got': got, 'want': want})

    def detect(msgs, flowkey=('10.0.0.9', 55000, '10.0.0.1', 389), cldap=None,
               local_nets=None):
        det = LdapDetector()
        det.local_nets = local_nets
        for raw in msgs:
            parsed, _ = split_ldap_messages(raw)
            for m in parsed:
                det.feed_message(flowkey, m)
        for c in (cldap or []):
            det.feed_cldap(*c)
        return det.result()

    def codes(res):
        return {f['code'] for f in res['findings']}

    # 1. BER round-trip: parse a simple bind and read the fields back.
    raw = _bind_req(3, 'cn=admin,dc=corp,dc=local', simple='S3cret!')
    parsed, consumed = split_ldap_messages(raw)
    ck('ber_consumed_all', consumed, len(raw))
    m = parsed[0] if parsed else {}
    ck('bind_parse_op', m.get('op'), 'bind-req')
    ck('bind_parse_dn', m.get('name'), 'cn=admin,dc=corp,dc=local')
    ck('bind_parse_pwlen', m.get('password_len'), len('S3cret!'))

    # 2. Two concatenated messages in one stream both decode.
    two = _bind_req(3, 'cn=a,dc=c', simple='') + _ext_req(OID_WHOAMI)
    pm, _ = split_ldap_messages(two)
    ck('two_messages', len(pm), 2)

    # 3. Cleartext credentials -> compromised.
    r = detect([_bind_req(3, 'cn=admin,dc=corp,dc=local', simple='S3cret!')])
    ck('cleartext_creds_code', 'cleartext-bind-credentials' in codes(r))
    ck('cleartext_creds_verdict', r['verdict'], 'compromised')

    # 4. Anonymous vs unauthenticated bind.
    ck('anonymous_bind', 'anonymous-bind' in codes(detect([_bind_req(3, '', simple='')])))
    ck('unauth_bind', 'unauthenticated-bind' in codes(
        detect([_bind_req(3, 'cn=svc,dc=corp,dc=local', simple='')])))

    # 5. SASL PLAIN over cleartext.
    ck('sasl_plain_cleartext', 'sasl-plaintext-cleartext' in codes(
        detect([_bind_req(3, '', sasl_mech='PLAIN')])))

    # 6. Directory enumeration: whole-subtree objectClass=*.
    r = detect([_search_req('dc=corp,dc=local', 2, _f_present('objectClass'), ['cn'])])
    ck('enumeration', 'directory-enumeration' in codes(r))

    # 7. Sensitive attribute read (SPN / gMSA / LAPS).
    r = detect([_search_req('dc=corp,dc=local', 2, _f_equal('objectClass', 'user'),
                            ['samaccountname', 'serviceprincipalname'])])
    ck('sensitive_attr', 'sensitive-attribute' in codes(r))

    # 8. Filter injection: unescaped ')(' in an assertion value.
    r = detect([_search_req('dc=corp,dc=local', 1, _f_equal('uid', '*)(uid=*'), ['cn'])])
    ck('filter_injection', 'filter-injection' in codes(r))

    # 9. StartTLS stripped: request refused by the server.
    r = detect([_ext_req(OID_STARTTLS), _ext_resp(2)])
    ck('starttls_stripped', 'starttls-stripped' in codes(r))

    # 10. Brute force: many binds from one client.
    r = detect([_bind_req(3, 'cn=u,dc=c', simple='x')
                for _ in range(BRUTE_BIND_ATTEMPTS)])
    ck('brute_force', 'brute-force' in codes(r))

    # 11. CLDAP reflection from an off-subnet source.
    import ipaddress
    nets = [ipaddress.ip_network('10.0.0.0/24')]
    cl = [('203.0.113.7', 40000, '10.0.0.1', 389,
           _search_req('', 0, _f_present('objectClass'), []), False, nets)]
    r = detect([], cldap=cl)
    ck('cldap_reflection', 'cldap-reflection' in codes(r))

    # 12. Clean: a harmless unbind carries no finding.
    r = detect([_ldap_message(5, _tlv(OP_UNBIND_REQ, b''))])
    ck('clean_unbind', r['verdict'], 'clean')

    # 12b. LDAPNightmare: a SearchResultReference to an EXTERNAL IP is flagged and
    # compromises the verdict; an in-forest (local-subnet) referral does not.
    import ipaddress as _ipa
    nets = [_ipa.ip_network('10.0.0.0/24')]
    r = detect([_search_ref(['ldap://203.0.113.66:389/dc=evil,dc=com'])],
               local_nets=nets)
    ck('external_referral_ref', 'external-referral' in codes(r))
    ck('external_referral_verdict', r['verdict'], 'compromised')
    r = detect([_bind_resp(RC_SUCCESS, referrals=['ldap://198.51.100.5/'])],
               local_nets=nets)
    ck('external_referral_bindresp', 'external-referral' in codes(r))
    r = detect([_search_ref(['ldap://10.0.0.7/dc=corp'])], local_nets=nets)
    ck('local_referral_clean', 'external-referral' not in codes(r))

    # 13. Malformed BER must not raise (bogus long-form length).
    try:
        split_ldap_messages(b'\x30\x84\xff\xff\xff\xff\x02')
        ck('malformed_no_raise', True)
    except Exception:
        ck('malformed_no_raise', False)

    # 14. PASSIVE proof: this source contains no packet-transmit primitives.
    ck('no_transmit_primitives', _scan_for_transmit_primitives(), [])

    failed = sum(1 for c in checks if not c['pass'])
    return {'success': failed == 0, 'checks': checks, 'failed': failed}


def _scan_for_transmit_primitives():
    """Grep THIS source for network-transmit calls. Returns a list of offending
    matches (empty == passive-clean). The patterns are written so their own literal
    form here never matches (the regex escapes break the token), keeping it honest."""
    import re
    try:
        with open(__file__, 'r') as f:
            src = f.read()
    except OSError:
        return []
    banned = [r'\bsendp\s*\(', r'\bsendpfast\s*\(', r'\bsend\s*\(', r'\bsr\s*\(',
              r'\bsr1\s*\(', r'\bsrp\s*\(', r'\bsrp1\s*\(', r'\bsrloop\s*\(',
              r'\bsendto\s*\(', r'\bsendall\s*\(', r'\bconnect\s*\(',
              r'socket\s*\.\s*socket\s*\(', r'\bStreamSocket\b', r'\bL3RawSocket\b']
    hits = []
    for pat in banned:
        for mo in re.finditer(pat, src):
            hits.append(src[max(0, mo.start() - 8):mo.end()])
    return hits


def _main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(prog='ldap_watch',
                                 description='passive LDAP / Active Directory watch')
    ap.add_argument('--selftest', action='store_true',
                    help='run the known-answer harness and exit (no root, no deps)')
    ap.add_argument('--iface', '-i', default=None, help='capture interface')
    ap.add_argument('--seconds', '-s', type=int, default=15,
                    help='capture window in seconds (5-60)')
    ap.add_argument('--daemon', action='store_true',
                    help='run continuously, emitting JSON-lines findings')
    ap.add_argument('--out', default=None, help='append JSON-lines findings to this file')
    ap.add_argument('--json', action='store_true', help='emit JSON')
    args = ap.parse_args(argv)

    if args.selftest:
        r = selftest()
        if args.json:
            print(json.dumps(r, indent=2, default=str))
        else:
            print('ldap_watch self-test')
            print('-' * 52)
            for c in r['checks']:
                print('  [%s] %s' % ('PASS' if c['pass'] else 'FAIL', c['name']))
                if not c['pass']:
                    print('        got : %r' % (c['got'],))
                    print('        want: %r' % (c['want'],))
            print('\n%d checks, %d failed' % (len(r['checks']), r['failed']))
        return 0 if r['success'] else 1

    if args.daemon:
        if not args.iface:
            print('error: --daemon requires --iface')
            return 2
        try:
            run_daemon(args.iface, out_path=args.out)
        except KeyboardInterrupt:
            return 0
        return 0

    if args.iface:
        r = do_ldap_watch(interface=args.iface, seconds=args.seconds)
        if args.json:
            print(json.dumps(r, indent=2, default=str))
        elif not r.get('success'):
            print('error: %s' % r.get('error'))
        else:
            st = r.get('stats', {})
            print('LDAP Watch [%s] %ss: %s  (%d msgs, %d binds, %d searches, %d CLDAP)'
                  % (r['interface'], r['seconds'], r['verdict'].upper(),
                     st.get('ldap_messages', 0), st.get('binds', 0),
                     st.get('searches', 0), st.get('cldap', 0)))
            for f in r.get('findings', []):
                print('  - %-5s %s: %s' % (f['severity'], f['code'], f['message']))
        return 0 if r.get('success') else 1

    ap.print_help()
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(_main())
