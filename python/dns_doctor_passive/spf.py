"""
DNS Doctor passive tier -- SPF parser leg (libspf2, CVE-2021-33912,
CVE-2021-33913, CVE-2021-20314, CVE-2023-42118).

WHY THIS BELONGS IN A DNS MODULE. All four CVEs are reached by feeding
libspf2 a crafted record, and an SPF record IS a DNS TXT record. The
attacker's artifact therefore travels in cleartext DNS, which is
exactly where this module already looks -- the TXT rdata decoder built
for the Matter/Thread fingerprint reads it unchanged. smtpwatch
watches SMTP on the wire, and the SPF record never appears there: the
mail server fetches it out of band, over DNS, past this tap.

EVERY DETAIL BELOW WAS READ OUT OF THE libspf2 SOURCE AND ITS FIX
COMMITS, not inferred from advisory prose. The advisories are thin --
ZDI published CVE-2023-42118 as "an integer underflow before writing
to memory" with no function, no condition and no input -- and a
detector built on that sentence would have been a guess. The commits
say precisely what the bug is, and in one case say something the
advisories do not: CVE-2023-42118 is a REGRESSION OF THE CVE-2021-20314
FIX, one hunk in the same macro in the same function.

  CVE-2021-33912  spf_expand.c, SPF_record_expand_data, URL-encode
                  block. `sprintf(p_write, "%%%02x", *p_read)` where
                  *p_read is a SIGNED char: a byte >= 0x80 sign-extends
                  and %02x prints eight hex digits ("%ffffff80", ten
                  bytes with the NUL) where four were budgeted. Fixed
                  by casting to (unsigned char) and bounding with
                  snprintf(..., 4, ...).
                  REACHED BY: url_encode set, i.e. an UPPERCASE macro
                  letter. No transformer needed.

  CVE-2021-33913  Same function, `url_var = malloc(len * 3 + 1)`. The
                  reversal block above it had overwritten `len` with
                  the length of a single LABEL, so the allocation was
                  sized for one label while the whole reversed string
                  was URL-encoded into it. Fixed by giving the
                  reversal its own `label_len`.
                  REACHED BY: an uppercase macro letter AND the `r`
                  transformer -- expansion must both reverse and
                  URL-encode. e.g. %{Dr}.

  CVE-2021-20314  spf_compile.c, SPF_c_parse_var, the
                  SPF_INIT_STRING_LITERAL macro. `ds_avail = _avail`
                  never subtracted the 4-byte SPF_data_t header that
                  had just been written into buf[], so a string
                  literal filling the budget overflowed the stack
                  buffer by exactly 4 bytes. Fixed to
                  `_avail - sizeof(SPF_data_t)`.
                  REACHED BY: a long string literal that fills the
                  compile budget -- in ZDI's PoC, the explanation
                  record named by `exp=`.

  CVE-2023-42118  THE SAME MACRO, and the 2021 fix is what introduced
                  it. `ds_avail = _avail - sizeof(SPF_data_t)` on an
                  unsigned size_t with no lower bound: when _avail < 4
                  the subtraction UNDERFLOWS to ~SIZE_MAX, after which
                  SPF_ENSURE_STRING_AVAIL's `ds_len + _len > ds_avail`
                  can never be true and the copy is unbounded. Fixed
                  at HEAD (Simon Arlott, 30 Sep 2023) by rejecting
                  _avail < sizeof(SPF_data_t) outright.
                  REACHED BY: enough macros in one term to drive
                  `data_avail - *data_used` below 4 at the moment a
                  string literal is initialised.

THE TWO 2021 COMPILE BUGS HAVE MUTUALLY EXCLUSIVE VERSION RANGES, and
that shapes how these are reported. Below 1.2.11 the header is never
subtracted (CVE-2021-20314). From 1.2.11 until the HEAD fix it is
subtracted without a floor (CVE-2023-42118). A passive sensor cannot
see the victim's library version, so each finding reports the RECORD
SHAPE that exploits one of them and names which.
"""
import parse
from findings import finding

# --- RFC 7208 s7.1 macro grammar -----------------------------------
#   macro-expand = "%{" macro-letter transformers *delimiter "}"
#                  / "%%" / "%_" / "%-"
#   transformers = *DIGIT [ "r" ]
MACRO_LETTERS = frozenset("slodiphcrtv")
# UPPERCASE IS THE WHOLE STORY FOR THE TWO EXPANSION BUGS. RFC 7208
# s7.1: "Uppercase macros expand exactly as their lowercase
# equivalents, and are then URL escaped." That URL-escape step is the
# block both CVE-2021-33912 and CVE-2021-33913 live in, so the case of
# one letter decides whether a record can reach them at all.
# RFC 7208 s7.1's delimiter set, kept for reference and for the
# divergence test below.
RFC7208_DELIMITERS = frozenset(".-+,/_=")

# WHAT LIBSPF2 ACTUALLY ACCEPTS. Established by driving the compiled
# library (see lab/spf_oracle.py): it REJECTS "," and "/", which RFC
# 7208 permits, and ACCEPTS "|", which RFC 7208 does not list. This
# tier reports libspf2 parser bugs, so it has to model libspf2's
# grammar; a record using "," is rejected at compile time and is
# therefore not a path to any of these CVEs.
MACRO_DELIMITERS = frozenset(".-+_=|")

# c, r and t are accepted ONLY inside an exp= explanation. In a
# mechanism, in redirect= and in exists:, libspf2 fails them with
# "'c' macro is only valid in modifiers". Confirmed against the
# library for all three letters and for redirect= specifically.
EXP_ONLY_LETTERS = frozenset("crt")

# The subdomain-truncation depth libspf2 accepts: 1..128. 0 and 129+
# both fail with "Subdomain truncation depth too large". Bisected
# against the library.
MACRO_DIGITS_MIN = 1
MACRO_DIGITS_MAX = 128

# --- libspf2 compile budget, from src/include/spf_record.h ---------
# Read out of the headers rather than guessed: these are the numbers
# the underflow arithmetic is done against.
SPF_MAX_MECH_LEN = 511
SPF_MAX_MOD_LEN = 511
SPF_MAX_STR_LEN = 255
# sizeof(SPF_data_t). The union's largest member is four bytes on
# every ordinary platform, and ZDI's "4-byte stack buffer overflow"
# for CVE-2021-20314 is the same number from the other direction.
SPF_DATA_T_SIZE = 4

# libspf2's _ALIGN_SZ and _align_sz, from src/include/spf_internal.h:
#
#     #if 1
#     #define _ALIGN_SZ 4
#     static inline size_t _align_sz(size_t s)
#         { return (s + (_ALIGN_SZ - 1 - (((s - 1) & (_ALIGN_SZ - 1))))); }
#     #else
#     static inline size_t _align_sz(size_t s) { return s; }
#     #endif
#
# NOTE THE `#if 1`. This module previously modelled _align_sz as the
# IDENTITY and documented that as "what the header compiles to unless
# alignment is forced on, the conservative direction". That was simply
# wrong: the rounding version is compiled unconditionally and the
# identity branch is dead code. The compiled library found it --
# a 126-macro term with a one-byte literal tail is refused as
# "SPF domainspec too long (509 chars, 511 max)", which only adds up
# if the 5-byte element was rounded to 8.
_ALIGN_SZ = 4


def align_sz(n):
    """libspf2's _align_sz: round up to a multiple of _ALIGN_SZ."""
    if n == 0:
        return 0
    return n + (_ALIGN_SZ - 1 - ((n - 1) & (_ALIGN_SZ - 1)))

# A single DNS TXT string cannot exceed 255 bytes, because its length
# is one octet (RFC 1035 s3.3.14). THIS IS A NECESSARY CONDITION, not
# a detail: the compile budget is 511, so a literal large enough to
# reach it CANNOT fit in one TXT string and must be split across
# several, which RFC 7208 s3.3 then concatenates. That is why ZDI's
# proof of concept splits its run of "A"s, and it is the cheapest
# reliable discriminator this tier has.
TXT_STRING_MAX = 255


def spf_record_text(strings):
    """The concatenated SPF record, or None if these strings are not one.

    RFC 7208 s3.3: a TXT record's strings are joined with NO separator
    before the record is parsed. Joining them is therefore not a
    convenience -- a record split as "v=spf1 " + "-all" means
    "v=spf1 -all", and a parser that looked only at the first string
    would miss every term after the split.
    """
    if not strings:
        return None
    joined = b"".join(strings)
    # s4.5: the version check is case-insensitive, and the record must
    # start with it.
    low = joined[:6].lower()
    if low != b"v=spf1":
        return None
    if len(joined) > 6 and joined[6:7] not in (b" ", b"\t", b""):
        return None            # "v=spf1abc" is not an SPF record
    return joined


def spf_terms(text):
    """Split a record into its terms, dropping the version token."""
    parts = text.split()
    return [p for p in parts[1:] if p]


def term_domainspec(term):
    """The macro-bearing part of a term, and which budget it compiles
    against.

    Mechanisms are capped by SPF_MAX_MECH_LEN and modifiers by
    SPF_MAX_MOD_LEN. Both are 511, so the distinction does not change
    the arithmetic -- it is carried anyway because the two constants
    are separate in the header and a future divergence would
    otherwise be silently wrong.
    """
    body = term
    if body[:1] in (b"+", b"-", b"~", b"?"):
        body = body[1:]
    if b"=" in body and b":" not in body.split(b"=")[0]:
        name, _, value = body.partition(b"=")
        return value, "modifier", name.lower()
    if b":" in body:
        name, _, value = body.partition(b":")
        return value, "mechanism", name.lower()
    if b"/" in body:
        name, _, _ = body.partition(b"/")
        return b"", "mechanism", name.lower()
    return b"", "mechanism", body.lower()


def parse_macros(spec, in_exp=False):
    """
    Decompose every %{...} in a domain-spec.

    Returns a list of dicts, each with the macro letter, whether it was
    uppercase (URL-escape), the digit transformer, whether the `r`
    reverse transformer is present, the delimiters, and the raw text.
    Malformed sequences are reported rather than skipped: libspf2 has
    to parse them too, and "this record does not parse cleanly" is
    itself worth knowing when the question is what a parser will do
    with it.
    """
    out = []
    i, n = 0, len(spec)
    while i < n:
        if spec[i:i + 1] != b"%":
            i += 1
            continue
        nxt = spec[i + 1:i + 2]
        if nxt in (b"%", b"_", b"-"):
            i += 2
            continue
        if nxt != b"{":
            # A bare '%' not starting a valid escape. RFC 7208 s7.1
            # makes this a syntax error; recorded, not silently eaten.
            out.append({"raw": b"%", "malformed": "bare '%' escape",
                        "letter": None, "upper": False, "digits": None,
                        "rev": False, "delims": ""})
            i += 1
            continue
        close = spec.find(b"}", i + 2)
        if close < 0:
            out.append({"raw": spec[i:], "malformed": "unterminated %{",
                        "letter": None, "upper": False, "digits": None,
                        "rev": False, "delims": ""})
            break
        inner = spec[i + 2:close]
        out.append(_parse_one_macro(inner, spec[i:close + 1], in_exp))
        i = close + 1
    return out


def _parse_one_macro(inner, raw, in_exp=False):
    m = {"raw": raw, "malformed": None, "letter": None, "upper": False,
         "digits": None, "rev": False, "delims": ""}
    if not inner:
        m["malformed"] = "empty %{}"
        return m
    ch = inner[0:1].decode("ascii", "replace")
    m["upper"] = ch.isupper()
    m["letter"] = ch.lower()
    if m["letter"] not in MACRO_LETTERS:
        m["malformed"] = f"unknown macro letter {ch!r}"
        return m
    if m["letter"] in EXP_ONLY_LETTERS and not in_exp:
        # libspf2: "'c' macro is only valid in modifiers". Not a path
        # to any of these CVEs outside an exp= explanation, because
        # the record does not compile.
        m["malformed"] = f"macro letter {ch!r} is exp=-only in libspf2"
        return m
    rest = inner[1:].decode("ascii", "replace")
    j = 0
    while j < len(rest) and rest[j].isdigit():
        j += 1
    if j:
        m["digits"] = int(rest[:j])
        if not (MACRO_DIGITS_MIN <= m["digits"] <= MACRO_DIGITS_MAX):
            m["malformed"] = (f"subdomain truncation depth {m['digits']} outside "
                              f"libspf2's {MACRO_DIGITS_MIN}..{MACRO_DIGITS_MAX}")
            return m
    # THE REVERSE TRANSFORMER IS LOWERCASE-ONLY IN LIBSPF2.
    #
    # RFC 7208's ABNF writes it as the string literal "r", and ABNF
    # string literals are case-insensitive, so "R" should be the same
    # transformer. libspf2 disagrees: %{DR} and %{dR} both fail with
    # "Invalid delimiter 'R'". This module had it the RFC's way, and
    # so did the ABNF-derived cross-check oracle -- both derived from
    # the same sentence of the same spec, so both shared the mistake
    # and agreed with each other (LESSON A). Only the compiled library
    # caught it. Treating "R" as reverse would have reported %{DR} as
    # CVE-2021-33913 on a record libspf2 never compiles.
    if j < len(rest) and rest[j] == "r":
        m["rev"] = True
        j += 1
    m["delims"] = rest[j:]
    bad = [c for c in m["delims"] if c not in MACRO_DELIMITERS]
    if bad:
        m["malformed"] = f"invalid delimiter(s) {''.join(bad)!r}"
    return m


# ======================================================================
# The libspf2 compile-budget walk (CVE-2021-20314 / CVE-2023-42118)
# ======================================================================

def compile_budget(spec, budget=SPF_MAX_MECH_LEN, in_exp=False):
    """
    Model libspf2's SPF_c_parse_var over a domain-spec.

    This models the VULNERABLE control flow, because that is what the
    two compile CVEs are about. It was written from spf_compile.c,
    then checked against THREE builds of the library: HEAD, HEAD with
    the CVE-2023-42118 floor check removed, and HEAD with the
    CVE-2021-20314 subtraction removed. Testing only HEAD was actively
    misleading and produced two wrong models in a row -- see the
    comments on the stop conditions.

    The relevant code, at HEAD:

        SPF_INIT_STRING_LITERAL(data_avail - *data_used);   /* 542, 647 */
          if ((_avail) < sizeof(SPF_data_t))      <-- the 42118 fix
              return ... "Out of memory for string literal";
          ds_avail = (_avail) - sizeof(SPF_data_t);
                                                  <-- the 20314 fix
        SPF_ENSURE_STRING_AVAIL(_len)
          if (ds_len + _len > ds_avail) return ... "fragment too long";
        *dst++ = c; ds_len++;                     <-- the write

        len = SPF_data_len(data);
        SPF_ADD_LEN_TO(*data_used, len, data_avail);
          if ((_val) + _align_sz(_len) > (_max)) return ... "too long";

    The write is per byte and happens immediately after ENSURE; the
    element is only committed with SPF_ADD_LEN_TO afterwards. So a
    wrapped ds_avail is not a four-byte problem -- every subsequent
    literal byte is written past the buffer.

    Returns a dict:
      used, remaining, macro_count, literal_inits
      underflow            True if a literal init was reached with
                           remaining < 4, so pre-fix `ds_avail =
                           _avail - sizeof(SPF_data_t)` wrapped to
                           ~SIZE_MAX                  (CVE-2023-42118)
      bytes_past_buffer    literal bytes written after that wrap, i.e.
                           the actual overrun. 0 means the underflow
                           was armed but nothing followed it.
      overflow_literal     length of a literal that fits the
                           pre-1.2.11 ds_avail (= _avail) but not the
                           corrected one (= _avail - 4), else None
                                                      (CVE-2021-20314)
      stopped_at           "too-long" | "end"

    Empirically, on the three builds:

      macros  HEAD              42118-vulnerable
      126     accepts           accepts
      127     "Out of memory"   ACCEPTS -- ds_avail wrapped
      128     "Out of memory"   "SPF domainspec too long (512, 511 max)"
      1000    "Out of memory"   "SPF domainspec too long (512, 511 max)"

    HEAD returns the identical error for 127 and for 1000 because its
    floor check fires at the 127th variable and nothing after it runs.
    That identical error is the FIX WORKING, and reading it as the
    vulnerability is what produced the second wrong model. On the
    vulnerable build the 128th variable is refused by SPF_ADD_LEN_TO
    before any write -- so the underflow is armed at variable 127 and
    is only written through if LITERAL TEXT follows it.
    """
    used = 0
    macro_count = 0
    literal_inits = 0
    underflow = False
    bytes_past_buffer = 0
    overflow_literal = None
    # What the CURRENT library would do here. Tracked separately from
    # the vulnerability flags because the fixed and unfixed builds
    # diverge exactly at these points, and the oracle tier checks the
    # model against both.
    stopped_at = "end"
    # ds_avail as each version computes it at the current literal init.
    ds_avail_pre20314 = 0      # pre-1.2.11: ds_avail = _avail
    ds_avail_fixed = 0         # 1.2.11+:    ds_avail = _avail - 4

    def init_literal():
        nonlocal literal_inits, underflow, ds_avail_pre20314, ds_avail_fixed
        literal_inits += 1
        avail = budget - used
        ds_avail_pre20314 = avail
        if avail < SPF_DATA_T_SIZE:
            # The unsigned subtraction wraps. Every later
            # SPF_ENSURE_STRING_AVAIL becomes a no-op.
            underflow = True
            ds_avail_fixed = -1          # sentinel: "unbounded"
        else:
            ds_avail_fixed = avail - SPF_DATA_T_SIZE

    init_literal()                                      # line 542

    for element, is_macro in _spec_elements(spec, in_exp):
        if is_macro:
            if used + align_sz(SPF_DATA_T_SIZE) > budget:
                # SPF_ADD_LEN_TO refuses. This is the real upper
                # bound, and it is why 128 macro variables are NOT a
                # path to a write even though the underflow is armed.
                stopped_at = "too-long"
                break
            used += align_sz(SPF_DATA_T_SIZE)
            macro_count += 1
            init_literal()                              # line 647
        else:
            n = len(element)
            if underflow:
                # ENSURE cannot fail, so all of it is written past the
                # space actually accounted for.
                bytes_past_buffer += n
            elif ds_avail_fixed < n <= ds_avail_pre20314:
                # Fits the pre-1.2.11 ds_avail but not the corrected
                # one: written up to sizeof(SPF_data_t) bytes past the
                # buffer. Confirmed by the two builds' own error
                # messages -- HEAD says "507 max", pre-1.2.11 says
                # "511 max", and the difference is the 4-byte header.
                if overflow_literal is None:
                    overflow_literal = n
            elif n > ds_avail_pre20314:
                stopped_at = "too-long"                 # refused in both
                break
            cost = align_sz(SPF_DATA_T_SIZE + n)
            if used + cost > budget:
                stopped_at = "too-long"
                break
            used += cost

    # The current library refuses at the floor check as soon as the
    # underflow condition exists, and refuses a window literal at
    # SPF_ENSURE_STRING_AVAIL. Either outranks a later length refusal
    # because it happens first.
    if underflow:
        stopped_at = "underflow"
    elif overflow_literal is not None:
        stopped_at = "literal-overflow"

    return {"used": used, "remaining": budget - used, "macro_count": macro_count,
            "literal_inits": literal_inits, "underflow": underflow,
            "bytes_past_buffer": bytes_past_buffer,
            "overflow_literal": overflow_literal,
            "stopped_at": stopped_at}


def _spec_elements(spec, in_exp=False):
    """Split a domain-spec into (text, is_macro) elements the way the
    compiler consumes it: literal runs and %{...} variables."""
    out = []
    i, n = 0, len(spec)
    lit = bytearray()
    while i < n:
        if spec[i:i + 1] == b"%" and spec[i + 1:i + 2] == b"{":
            close = spec.find(b"}", i + 2)
            if close < 0:
                lit += spec[i:]
                break
            if lit:
                out.append((bytes(lit), False))
                lit = bytearray()
            out.append((spec[i:close + 1], True))
            i = close + 1
            continue
        if spec[i:i + 1] == b"%" and spec[i + 1:i + 2] in (b"%", b"_", b"-"):
            lit += spec[i:i + 2]
            i += 2
            continue
        lit += spec[i:i + 1]
        i += 1
    if lit:
        out.append((bytes(lit), False))
    return out


# ======================================================================
# DETECTORS
# ======================================================================

def _addr(raw):
    import ipaddress
    try:
        return str(ipaddress.ip_address(bytes(raw)))
    except ValueError:
        return bytes(raw).hex()


def _txt_records(msg):
    """Every TXT record in a response, with its strings.

    ANSWER and ADDITIONAL only. A QUERY for a TXT record is not the
    record -- it carries no rdata at all -- so there is nothing in the
    question section for any of this to read.
    """
    out = []
    for rr in msg.answers + msg.additional:
        if rr.rtype != parse.T_TXT:
            continue
        strings = (rr.parsed or {}).get("strings") or []
        out.append((rr, strings))
    return out


def detect_macro_expansion(rr, text, cfg, table, src_raw, now):
    """
    DNSD-150 (CVE-2021-33912) and DNSD-151 (CVE-2021-33913).

    Both live in the same URL-encode block of SPF_record_expand_data,
    and the gate for the whole block is `d->dv.url_encode` -- which is
    set by an UPPERCASE macro letter and nothing else. So a record
    with no uppercase macro letter cannot reach either bug, whatever
    else it contains.

    THE TWO ARE REPORTED SEPARATELY AND ARE MUTUALLY EXCLUSIVE. The
    `r` transformer is what makes the difference: without it the only
    bug reachable is the sprintf writing eight hex digits for a high
    byte (four bytes over); with it the reversal block has already
    clobbered the length used to size the allocation, so the buffer is
    undersized before a single byte is encoded. One record form, one
    code, no overlap -- rather than one code that fires twice or two
    codes where one subsumes the other.

    WHAT THESE DO NOT CLAIM. The record supplies the macro syntax; the
    expanded VALUE comes from the mail transaction -- the sender, the
    HELO name, the client IP -- which a DNS tap never sees. For
    CVE-2021-33912 the overflow additionally needs a byte above 0x7f
    in that value. So these report a record that can REACH the
    vulnerable path, which is why they are warnings rather than
    criticals despite the CVEs' own scores.
    """
    out = []
    for term in spf_terms(text):
        spec, kind, name = term_domainspec(term)
        if not spec:
            continue
        # c, r and t are exp=-only in libspf2, so whether a macro is
        # even a reachable path depends on which term it sits in.
        for m in parse_macros(spec, in_exp=(name == b"exp")):
            if not m["upper"] or m["letter"] is None or m["malformed"]:
                continue
            code = "DNSD-151" if m["rev"] else "DNSD-150"
            key = (code, rr.name.text().lower(), m["raw"])
            if not table.first_sighting(key, now):
                continue
            ev = {"owner": rr.name.text(), "term": term.decode("ascii", "replace"),
                  "term_kind": kind, "term_name": name.decode("ascii", "replace"),
                  "macro": m["raw"].decode("ascii", "replace"),
                  "macro_letter": m["letter"], "url_escaped": True,
                  "reverse_transformer": m["rev"], "digits": m["digits"],
                  "delimiters": m["delims"], "source": _addr(src_raw)}
            # ONE source for the code. It used to be derived here and
            # then written again as a literal in each emit branch, and
            # a mutation that collapsed the first derivation escaped
            # every tier: the findings still came out right because the
            # literals carried the real codes, and only the suppression
            # key was wrong. Nothing tested that, and nothing should
            # have had to -- the duplication was the defect. Only the
            # MESSAGE differs between the two now.
            msg = (f"SPF record for {rr.name.text()} uses "
                   f"{m['raw'].decode('ascii', 'replace')} -- an uppercase macro letter "
                   f"with the 'r' transformer, so libspf2 both reverses and URL-encodes "
                   f"the expansion and sizes the encode allocation from a single label"
                   if m["rev"] else
                   f"SPF record for {rr.name.text()} uses "
                   f"{m['raw'].decode('ascii', 'replace')} -- an uppercase macro letter, "
                   f"so the expansion is URL-escaped through the block whose sprintf "
                   f"wrote eight hex digits for any byte above 0x7f")
            out.append(finding(code, rr.name.text(), msg, ev))
    return out


def detect_budget_underflow(rr, text, cfg, table, src_raw, now, is_explanation=False):
    """
    DNSD-153 (CVE-2023-42118).

    The condition, transcribed from spf_compile.c and then confirmed
    against the compiled library: every macro variable in a term costs
    sizeof(SPF_data_t) bytes of the 511-byte budget and is followed by
    SPF_INIT_STRING_LITERAL(data_avail - *data_used). When that
    remaining value is below 4, `ds_avail = _avail - sizeof(SPF_data_t)`
    underflows an unsigned size_t to roughly SIZE_MAX and every bounds
    check after it passes. HEAD's fix is a floor check immediately
    before that subtraction.

    THE WINDOW IS NOT BOUNDED ABOVE. An earlier version of this
    detector assumed it was -- that past 127 variables
    SPF_ADD_LEN_TO would reject the term as "SPF domainspec too long"
    before any literal was initialised -- and so stayed silent at 128
    and above. The compiled library says otherwise: 127, 128, 200 and
    1000 variables all return the SAME error from the SAME place,
    because compilation stops AT the 127th variable and never reaches
    the rest. The assumption was a false negative an attacker reaches
    by typing more macros, and it is why this tier was checked against
    a real build rather than only against the source.
    """
    out = []
    budget = SPF_MAX_MOD_LEN if is_explanation else SPF_MAX_MECH_LEN
    items = ([(text, "explanation", b"exp", text)] if is_explanation
             else [term_domainspec(t) + (t,) for t in spf_terms(text)])
    for spec, kind, name, term in items:
        if not spec:
            continue
        in_exp = is_explanation or name == b"exp"
        r = compile_budget(spec, budget, in_exp=in_exp)
        if not r["underflow"]:
            continue
        key = ("DNSD-153", rr.name.text().lower(), r["macro_count"],
               r["bytes_past_buffer"])
        if not table.first_sighting(key, now):
            continue
        out.append(finding(
            "DNSD-153", rr.name.text(),
            f"SPF {kind} for {rr.name.text()} drives libspf2's compile budget below "
            f"sizeof(SPF_data_t) at the {r['macro_count']}th macro variable, where "
            f"`_avail - sizeof(SPF_data_t)` underflows an unsigned count to SIZE_MAX "
            f"and every later bounds check becomes a no-op"
            + (f" -- and {r['bytes_past_buffer']} literal bytes follow it, so that "
               f"many are written past the stack buffer"
               if r["bytes_past_buffer"]
               else " -- no literal text follows, so the underflow is armed but "
                    "nothing is written through it"),
            {"owner": rr.name.text(), "kind": kind,
             "term_name": name.decode("ascii", "replace"),
             "macro_count": r["macro_count"], "data_used": r["used"],
             "min_remaining": r["remaining"], "budget": budget,
             "literal_inits": r["literal_inits"],
             "bytes_past_buffer": r["bytes_past_buffer"],
             "writes_through": bool(r["bytes_past_buffer"]),
             "source": _addr(src_raw),
             "window": "the underflow arms at the 127th macro variable (4 bytes each "
                       "against a 511-byte budget, leaving 3). It is written through "
                       "only if LITERAL text follows: at 128 variables and above "
                       "SPF_ADD_LEN_TO refuses the next variable before any write, "
                       "which the vulnerable build confirms with 'SPF domainspec too "
                       "long (512 chars, 511 max)'",
             "affected": "libspf2 1.2.11 up to the fix at HEAD -- versions that carry "
                         "the CVE-2021-20314 fix but not the floor check. Mutually "
                         "exclusive with CVE-2021-20314's range (below 1.2.11)"},
        ))
    return out


def detect_exp_explanation(rr, strings, cfg, table, exp_targets, src_raw, now):
    """
    DNSD-152 (CVE-2021-20314).

    Fires on the EXPLANATION record, not on the SPF record. `exp=` is
    ordinary and common; what is not ordinary is the TXT record it
    points at carrying a literal sized to overrun the compile buffer.
    So the SPF record's exp= target is remembered and this fires when
    that name's TXT arrives.

    THE WINDOW IS FOUR BYTES WIDE, and it was wrong here until the
    library was built and asked. The condition is NOT "a big literal":

        before 1.2.11   ds_avail = _avail            (the bug)
        at HEAD         ds_avail = _avail - 4        (the fix)

    SPF_ENSURE_STRING_AVAIL guards the write with
    `ds_len + _len > ds_avail`. A literal that fits the BUGGY ds_avail
    but not the FIXED one is written past the space actually there --
    by at most sizeof(SPF_data_t) bytes, which is exactly the "4-byte
    stack buffer overflow" the advisory describes. For a literal at
    the start of a spec that window is 508..511 bytes.

    A literal of 480..507 bytes -- which the previous threshold of 480
    reported -- fits BOTH versions and overflows nothing. It is
    rejected a moment later by the 255-byte SPF_MAX_STR_LEN cap in
    SPF_FINI_STRING_LITERAL, in the fixed and unfixed library alike.
    Those were false positives, and the compiled library named them:
    at HEAD a 507-byte literal fails with "String literal too long
    (507 chars, 255 max)" while 508 fails with "fragment too long
    (0 chars, 507 max)" -- two different checks, and only the second
    is the one the fix moved.

    THE MULTI-STRING SPLIT REMAINS A NECESSARY CONDITION. A DNS TXT
    string is length-prefixed by one octet and so caps at 255 bytes;
    the window starts at 508. A literal that reaches it therefore
    cannot arrive in one string and must be split across at least
    three, which RFC 7208 s3.3 concatenates before parsing.
    """
    if not strings:
        return []
    zone = exp_targets.lookup(rr.name.text())
    if zone is None:
        return []
    joined = b"".join(strings)
    # The explanation is compiled as a macro-string against
    # SPF_MAX_MOD_LEN, so run the same budget walk the library does
    # rather than comparing a raw length to a threshold.
    r = compile_budget(joined, SPF_MAX_MOD_LEN, in_exp=True)
    if r["overflow_literal"] is None:
        return []
    n = r["overflow_literal"]
    if n < cfg.spf_exp_literal_min:
        # Floor kept as a config safety valve; the default sits below
        # the real window so it never masks a true positive.
        return []
    key = ("DNSD-152", rr.name.text().lower(), n)
    if not table.first_sighting(key, now):
        return []
    return [finding(
        "DNSD-152", rr.name.text(),
        f"explanation TXT for {rr.name.text()}, named by the exp= modifier of {zone}, "
        f"carries a {n}-byte string literal across {len(strings)} TXT strings. That "
        f"fits the pre-1.2.11 ds_avail of {r['remaining']} but not the corrected "
        f"{r['remaining'] - SPF_DATA_T_SIZE}, so libspf2 writes up to "
        f"{SPF_DATA_T_SIZE} bytes past the stack buffer it accounted for",
        {"owner": rr.name.text(), "exp_referrer": zone,
         "literal_bytes": n, "txt_strings": len(strings),
         "ds_avail_buggy": r["remaining"],
         "ds_avail_fixed": r["remaining"] - SPF_DATA_T_SIZE,
         "budget": SPF_MAX_MOD_LEN, "source": _addr(src_raw),
         "window": f"{r['remaining'] - SPF_DATA_T_SIZE + 1}..{r['remaining']} bytes; "
                   f"shorter literals fit both versions and overflow nothing, longer "
                   f"ones are refused by SPF_ENSURE_STRING_AVAIL in both",
         "note": f"a single TXT string caps at {TXT_STRING_MAX} bytes, so reaching "
                 f"this window requires the split seen here",
         "affected": "libspf2 before 1.2.11. Mutually exclusive with "
                     "CVE-2023-42118's range (1.2.11 up to the fix at HEAD)"},
    )]


def note_exp_targets(rr, text, exp_targets, now):
    """Remember every exp= target named by this SPF record.

    A target containing a macro is NOT remembered: its real name
    depends on the mail transaction, so there is no name to match a
    later TXT record against. Recording the unexpanded form would
    create a key nothing can ever hit, which is worse than not
    recording it -- it looks like coverage.
    """
    noted = []
    for term in spf_terms(text):
        spec, kind, name = term_domainspec(term)
        if kind != "modifier" or name != b"exp" or not spec:
            continue
        if b"%" in spec:
            continue
        target = spec.decode("ascii", "replace")
        exp_targets.note(target, rr.name.text(), now)
        noted.append(target)
    return noted


def handle_spf(msg, cfg, table, exp_targets, src_raw, now):
    """Whole tier for one DNS response carrying TXT records."""
    if not cfg.spf_enabled or not msg.qr:
        return []
    out = []
    for rr, strings in _txt_records(msg):
        text = spf_record_text(strings)
        if text is not None:
            note_exp_targets(rr, text, exp_targets, now)
            out += detect_macro_expansion(rr, text, cfg, table, src_raw, now)
            out += detect_budget_underflow(rr, text, cfg, table, src_raw, now)
            continue
        # Not an SPF record. It may still be an EXPLANATION record,
        # which is a bare macro-string with no v=spf1 prefix.
        out += detect_exp_explanation(rr, strings, cfg, table, exp_targets,
                                      src_raw, now)
        joined = b"".join(strings)
        if exp_targets.lookup(rr.name.text()) is not None and joined:
            out += detect_budget_underflow(rr, joined, cfg, table, src_raw, now,
                                           is_explanation=True)
    return out
